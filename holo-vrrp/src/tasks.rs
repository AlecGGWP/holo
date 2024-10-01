//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, BytesMut};
use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::task::{IntervalTask, Task, TimeoutTask};
use holo_utils::{Sender, UnboundedReceiver};
use messages::input::MasterDownTimerMsg;
use messages::output::NetTxPacketMsg;
use tracing::{debug_span, Instrument};

use crate::instance::{Instance, VrrpTimer};
use crate::interface::Interface;
use crate::network;

//
// VRRP tasks diagram:
//                                     +--------------+
//                                     |  northbound  |
//                                     +--------------+
//                                           | ^
//                                           | |
//                        northbound_rx (1x) V | (1x) northbound_tx
//                                     +--------------+
//           master_down_timer (Nx) -> |              |
//                    vrrp_net (Nx) -> |   instance   | -> (Nx) net_tx
//                    arp_net  (Nx) -> |              |
//                                     +--------------+
//                              ibus_tx (1x) | ^ (1x) ibus_rx
//                                           | |
//                                           V |
//                                     +--------------+
//                                     |     ibus     |
//                                     +--------------+
//

// VRRP inter-task message types.
pub mod messages {
    use serde::{Deserialize, Serialize};

    use crate::packet::{DecodeError, VrrpPacket};

    // Type aliases.
    pub type ProtocolInputMsg = input::ProtocolMsg;
    pub type ProtocolOutputMsg = output::ProtocolMsg;

    // Input messages (child task -> main task).
    pub mod input {
        use std::net::Ipv4Addr;

        use super::*;
        use crate::packet::ArpPacket;

        #[derive(Debug, Deserialize, Serialize)]
        pub enum ProtocolMsg {
            VrrpNetRxPacket(VrrpNetRxPacketMsg),
            MasterDownTimer(MasterDownTimerMsg),
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct VrrpNetRxPacketMsg {
            pub src: Ipv4Addr,
            pub packet: Result<VrrpPacket, DecodeError>,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct ArpNetRxPacketMsg {
            pub packet: Result<ArpPacket, DecodeError>,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct MasterDownTimerMsg {
            pub vrid: u8,
        }
    }

    // Output messages (main task -> child task).
    pub mod output {
        use super::*;
        use crate::packet::{ArpPacket, EthernetFrame};

        #[derive(Debug, Serialize)]
        pub enum ProtocolMsg {
            NetTxPacket(NetTxPacketMsg),
        }

        #[derive(Clone, Debug, Serialize)]
        pub enum NetTxPacketMsg {
            Vrrp {
                ifname: String,
                buf: Vec<u8>,
            },
            Arp {
                name: String,
                eth_frame: EthernetFrame,
                arp_packet: ArpPacket,
            },
        }
    }
}

// ===== VRRP tasks =====

// Network Rx task.
pub(crate) fn vrrp_net_rx(
    socket_vrrp: Arc<AsyncFd<Socket>>,
    net_packet_rxp: &Sender<messages::input::VrrpNetRxPacketMsg>,
) -> Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        let span1 = debug_span!("network");
        let _span1_guard = span1.enter();
        let span2 = debug_span!("input");
        let _span2_guard = span2.enter();

        let net_packet_rxp = net_packet_rxp.clone();

        let span = tracing::span::Span::current();
        Task::spawn(
            async move {
                let _span_enter = span.enter();
                let _ =
                    network::vrrp_read_loop(socket_vrrp, net_packet_rxp).await;
            }
            .in_current_span(),
        )
    }
    #[cfg(feature = "testing")]
    {
        Task::spawn(async move { std::future::pending().await })
    }
}

// Network Tx task.
#[allow(unused_mut)]
pub(crate) fn net_tx(
    socket_vrrp: Arc<AsyncFd<Socket>>,
    socket_arp: Arc<AsyncFd<Socket>>,
    mut net_packet_txc: UnboundedReceiver<messages::output::NetTxPacketMsg>,
    #[cfg(feature = "testing")] proto_output_tx: &Sender<
        messages::ProtocolOutputMsg,
    >,
) -> Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        let span1 = debug_span!("network");
        let _span1_guard = span1.enter();
        let span2 = debug_span!("output");
        let _span2_guard = span2.enter();

        let span = tracing::span::Span::current();
        Task::spawn(
            async move {
                let _span_enter = span.enter();
                network::write_loop(socket_vrrp, socket_arp, net_packet_txc)
                    .await;
            }
            .in_current_span(),
        )
    }
    #[cfg(feature = "testing")]
    {
        let proto_output_tx = proto_output_tx.clone();
        Task::spawn(async move {
            // Relay message to the test framework.
            while let Some(msg) = net_packet_txc.recv().await {
                let msg = messages::ProtocolOutputMsg::NetTxPacket(msg);
                let _ = proto_output_tx.send(msg).await;
            }
        })
    }
}

// handling the timers...
pub(crate) fn set_timer(
    interface: &mut Interface,
    vrid: u8,
    master_down_tx: Sender<MasterDownTimerMsg>,
) {
    // the net producer used for sending VRRP messages outside.
    let net_tx = interface.net.net_tx_packetp.clone();

    if let Some(instance) = interface.instances.get_mut(&vrid) {
        match instance.state.state {
            crate::instance::State::Initialize => {
                instance.timer = VrrpTimer::Null;
            }
            crate::instance::State::Backup => {
                let duration = Duration::from_secs(
                    instance.state.master_down_interval as u64,
                );
                set_master_down_timer(instance, duration, master_down_tx);
            }

            // in case we are Master, we will be sending VRRP advertisements
            // every ADVERT_INTERVAL seconds until otherwise.
            crate::instance::State::Master => {
                // -----------------
                let mut buf = BytesMut::new();

                // ethernet frame
                let eth_frame: &[u8] = &instance.advert_ether_frame().encode();
                buf.put(eth_frame);

                // ip packet
                let src_ip = interface.system.addresses.first().unwrap().ip();
                let ip_pkt: &[u8] = &instance.adver_ipv4_pkt(src_ip).encode();
                buf.put(ip_pkt);

                // vrrp packet
                let vrrp_pkt: &[u8] = &instance.adver_vrrp_pkt().encode();
                buf.put(vrrp_pkt);

                let ifname = instance.mac_vlan.name.clone();
                // -----------------

                let timer = IntervalTask::new(
                    Duration::from_secs(
                        instance.config.advertise_interval as u64,
                    ),
                    true,
                    move || {
                        let ifname = ifname.clone();
                        let buf = buf.to_vec();
                        let net_tx = net_tx.clone();
                        async move {
                            let msg = NetTxPacketMsg::Vrrp { ifname, buf };
                            let _ = net_tx.send(msg);
                        }
                    },
                );
                instance.timer = VrrpTimer::AdverTimer(timer);
            }
        }
    }
}
// ==== Set Master Down Timer ====
pub(crate) fn set_master_down_timer(
    instance: &mut Instance,
    duration: Duration,
    tx: Sender<MasterDownTimerMsg>,
) {
    let vrid = instance.vrid;
    let timer = TimeoutTask::new(duration, move || async move {
        let _ = tx.send(messages::input::MasterDownTimerMsg { vrid }).await;
    });
    instance.timer = VrrpTimer::MasterDownTimer(timer);
}

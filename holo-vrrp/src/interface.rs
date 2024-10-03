//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use holo_protocol::{
    InstanceChannelsTx, InstanceShared, MessageReceiver, ProtocolInstance,
};
use holo_utils::ibus::IbusMsg;
use holo_utils::ip::AddressFamily;
use holo_utils::protocol::Protocol;
use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::southbound::InterfaceFlags;
use holo_utils::task::Task;
use holo_utils::{Receiver, Sender, UnboundedSender};
use ipnetwork::{IpNetwork, Ipv4Network};
use tokio::sync::mpsc;
use tracing::{debug, debug_span};

use crate::error::{Error, IoError};
use crate::instance::{Instance, State};
use crate::tasks::messages::input::{MasterDownTimerMsg, VrrpNetRxPacketMsg};
use crate::tasks::messages::output::NetTxPacketMsg;
use crate::tasks::messages::{ProtocolInputMsg, ProtocolOutputMsg};
use crate::{events, network, southbound, tasks};

#[derive(Debug)]
pub struct Interface {
    // Interface name.
    pub name: String,
    // Interface system data.
    pub system: InterfaceSys,
    // Interface raw sockets and Tx/Rx tasks.
    pub net: InterfaceNet,
    // Interface VRRP instances.
    pub instances: BTreeMap<u8, Instance>,
    // Tx channels.
    pub tx: InstanceChannelsTx<Interface>,
    // Shared data.
    pub shared: InstanceShared,
}

// as far as vrrp is concerned, this will have
// nearly all the features of the normal interface
// but will not hold any VRRP instances etc.
// it is purely meant for being used together with
// a VRRP instance as the MacVlan interface when
// MacVlan is enabled on VRRP.
#[derive(Debug)]
pub struct MacVlanInterface {
    // Interface name.
    //
    // Macvlan interface naming for VRRP will be in the format:
    //   `mvlan-vrrp-{vrid}`
    pub name: String,
    // Interface system data.
    pub system: InterfaceSys,
    // Interface raw sockets and Tx/Rx tasks.
    pub net: Option<InterfaceNet>,
}

#[derive(Debug, Default)]
pub struct InterfaceSys {
    // Interface flags.
    pub flags: InterfaceFlags,
    // Interface index.
    pub ifindex: Option<u32>,
    // Interface IPv4 addresses.
    pub addresses: BTreeSet<Ipv4Network>,
    // interface Mac Address
    pub mac_address: [u8; 6],
}

#[derive(Debug)]
pub struct InterfaceNet {
    // Raw sockets.
    pub socket_vrrp: Arc<AsyncFd<Socket>>,
    pub socket_arp: Arc<AsyncFd<Socket>>,

    // Network Tx/Rx tasks.
    _net_tx_task: Task<()>,

    // network Tx/Rx tasks. But specifically for VRRP packets.
    _vrrp_net_rx_task: Task<()>,

    // Network Tx output channel.
    pub net_tx_packetp: UnboundedSender<NetTxPacketMsg>,
}

#[derive(Clone, Debug)]
pub struct ProtocolInputChannelsTx {
    // VRRP Packet Tx event.
    pub vrrp_net_packet_tx: Sender<VrrpNetRxPacketMsg>,
    // Master Down event
    pub master_down_timer_tx: Sender<MasterDownTimerMsg>,
}

#[derive(Debug)]
pub struct ProtocolInputChannelsRx {
    // VRRP Packet Rx event.
    pub vrrp_net_packet_rx: Receiver<VrrpNetRxPacketMsg>,
    // Master Down event
    pub master_down_timer_rx: Receiver<MasterDownTimerMsg>,
}

// ===== impl Interface =====

impl Interface {
    pub(crate) fn create_instance(&mut self, vrid: u8) {
        let instance = Instance::new(vrid);
        self.instances.insert(vrid, instance);

        //  `mvlan-vrrp{primary-interface-ifindex}{vrid}`
        let name = format!("mvlan-vrrp-{}", vrid);
        let mac_address: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x01, vrid];
        southbound::create_macvlan_iface(
            name.clone(),
            self.name.clone(),
            mac_address, // virtual mac address
            &self.tx.ibus,
        );
    }

    pub(crate) fn delete_instance(&mut self, vrid: u8) {
        let mvlan_ifindex: Option<u32>;
        if let Some(instance) = self.instances.get(&vrid) {
            mvlan_ifindex = instance.mac_vlan.system.ifindex;
        } else {
            return;
        }

        self.instances.remove(&vrid);
        if let Some(ifindex) = mvlan_ifindex {
            southbound::delete_iface(ifindex, &self.tx.ibus);
        }
    }

    pub(crate) fn change_state(&mut self, vrid: u8, state: State) {
        if let Some(instance) = self.instances.get_mut(&vrid) {
            debug_span!("change-state").in_scope(|| {
                if state == State::Backup {
                    debug!(%vrid, "state to BACKUP.");
                    // change admin state of MacVlan to down.
                } else if state == State::Master {
                    debug!(%vrid, "state to MASTER.");
                    // change admin state of MacVlan to up.
                }
            });

            instance.state.state = state;
            self.reset_timer(vrid);
        }
    }

    pub(crate) fn add_instance_virtual_address(
        &mut self,
        vrid: u8,
        addr: Ipv4Network,
    ) {
        if let Some(instance) = self.instances.get_mut(&vrid).take() {
            instance.config.virtual_addresses.insert(addr);

            if let Some(ifindex) = instance.mac_vlan.system.ifindex {
                southbound::addr_add(
                    ifindex,
                    IpNetwork::V4(addr),
                    &self.tx.ibus,
                );
            }
            self.reset_timer(vrid);
        }
    }

    // in order to update the details being sent in subsequent
    // requests, we will update the timer to have the updated timers with the relevant
    // information.
    pub(crate) fn reset_timer(&mut self, vrid: u8) {
        tasks::set_timer(
            self,
            vrid,
            self.tx.protocol_input.master_down_timer_tx.clone(),
        );
    }

    pub(crate) fn delete_instance_virtual_address(
        &self,
        vrid: u8,
        addr: Ipv4Network,
    ) {
        if let Some(instance) = self.instances.get(&vrid) {
            if let Some(ifindex) = instance.mac_vlan.system.ifindex {
                southbound::addr_del(
                    ifindex,
                    IpNetwork::V4(addr),
                    &self.tx.ibus,
                );
            }
        }
    }

    pub(crate) fn send_vrrp_advert(&self, vrid: u8) {
        if let Some(instance) = self.instances.get(&vrid) {
            let mut buf = BytesMut::new();

            // ethernet frame
            let eth_frame: &[u8] = &instance.advert_ether_frame().encode();
            buf.put(eth_frame);

            // ip packet
            let ip_pkt: &[u8] = &instance
                .adver_ipv4_pkt(self.system.addresses.first().unwrap().ip())
                .encode();
            buf.put(ip_pkt);

            // vrrp packet
            let vrrp_pkt: &[u8] = &instance.adver_vrrp_pkt().encode();
            buf.put(vrrp_pkt);

            let msg = NetTxPacketMsg::Vrrp {
                ifname: instance.mac_vlan.name.clone(),
                buf: buf.to_vec(),
            };
            let _ = self.net.net_tx_packetp.send(msg);
        }
    }
}

#[async_trait]
impl ProtocolInstance for Interface {
    const PROTOCOL: Protocol = Protocol::VRRP;

    type ProtocolInputMsg = ProtocolInputMsg;
    type ProtocolOutputMsg = ProtocolOutputMsg;
    type ProtocolInputChannelsTx = ProtocolInputChannelsTx;
    type ProtocolInputChannelsRx = ProtocolInputChannelsRx;

    async fn new(
        name: String,
        shared: InstanceShared,
        tx: InstanceChannelsTx<Interface>,
    ) -> Interface {
        // TODO: proper error handling
        let net = InterfaceNet::new(&name, &tx)
            .expect("Failed to initialize VRRP network tasks");
        Interface {
            name,
            system: Default::default(),
            net,
            instances: Default::default(),
            tx,
            shared,
        }
    }

    async fn init(&mut self) {
        // request for details of the master interface
        // to be sent so we can update our details.
        let _ = self.tx.ibus.send(IbusMsg::InterfaceQuery {
            ifname: self.name.clone(),
            af: Some(AddressFamily::Ipv4),
        });
    }

    async fn process_ibus_msg(&mut self, msg: IbusMsg) {
        if let Err(error) = process_ibus_msg(self, msg).await {
            error.log();
        }
    }

    fn process_protocol_msg(&mut self, msg: ProtocolInputMsg) {
        if let Err(error) = match msg {
            // Received network packet.
            ProtocolInputMsg::VrrpNetRxPacket(msg) => {
                events::process_vrrp_packet(self, msg.src, msg.packet)
            }
            ProtocolInputMsg::MasterDownTimer(msg) => {
                events::handle_master_down_timer(self, msg.vrid)
            }
        } {
            error.log();
        }
    }

    fn protocol_input_channels(
    ) -> (ProtocolInputChannelsTx, ProtocolInputChannelsRx) {
        let (vrrp_net_packet_rxp, vrrp_net_packet_rxc) = mpsc::channel(4);
        let (master_down_timerp, master_down_timerc) = mpsc::channel(4);

        let tx = ProtocolInputChannelsTx {
            vrrp_net_packet_tx: vrrp_net_packet_rxp,
            master_down_timer_tx: master_down_timerp,
        };
        let rx = ProtocolInputChannelsRx {
            vrrp_net_packet_rx: vrrp_net_packet_rxc,
            master_down_timer_rx: master_down_timerc,
        };

        (tx, rx)
    }

    #[cfg(feature = "testing")]
    fn test_dir() -> String {
        format!("{}/tests/conformance", env!("CARGO_MANIFEST_DIR"),)
    }
}

// ==== impl MacVlanInterface ====
impl MacVlanInterface {
    pub fn new(vrid: u8) -> Self {
        let name = format!("mvlan-vrrp-{}", vrid);
        Self {
            name,
            system: InterfaceSys::default(),
            net: None,
        }
    }

    pub fn create_net(&mut self, tx_channels: &InstanceChannelsTx<Interface>) {
        let net = InterfaceNet::new(&self.name, tx_channels)
            .expect("Failed to initialize VRRP tasks");
        self.net = Some(net);
    }
}

// ===== impl InterfaceNet =====

impl InterfaceNet {
    fn new(
        ifname: &str,
        instance_channels_tx: &InstanceChannelsTx<Interface>,
    ) -> Result<Self, IoError> {
        // create socket_vrrp_rx and socket_vrrp_tx
        // Currently being created separately so that we can customize
        // our vrrp sockets with some virtual fields in the headers
        // when sending out the VRRP advertisements
        let socket_vrrp_rx = network::socket_vrrp_rx(ifname)
            .map_err(IoError::SocketError)
            .and_then(|socket| {
                AsyncFd::new(socket).map_err(IoError::SocketError)
            })
            .map(Arc::new)?;

        // tx will change the creation to happen in it's own function.
        let socket_vrrp_tx = network::socket_vrrp_tx(ifname)
            .map_err(IoError::SocketError)
            .and_then(|socket| {
                AsyncFd::new(socket).map_err(IoError::SocketError)
            })
            .map(Arc::new)?;

        let socket_arp = network::socket_arp(ifname)
            .map_err(IoError::SocketError)
            .and_then(|socket| {
                AsyncFd::new(socket).map_err(IoError::SocketError)
            })
            .map(Arc::new)?;

        // Start network Tx/Rx tasks.
        let (net_tx_packetp, net_tx_packetc) = mpsc::unbounded_channel();
        let net_tx_task = tasks::net_tx(
            socket_vrrp_tx,
            socket_arp.clone(),
            net_tx_packetc,
            #[cfg(feature = "testing")]
            &instance_channels_tx.protocol_output,
        );
        let vrrp_net_rx_task = tasks::vrrp_net_rx(
            socket_vrrp_rx.clone(),
            &instance_channels_tx.protocol_input.vrrp_net_packet_tx,
        );

        Ok(InterfaceNet {
            socket_vrrp: socket_vrrp_rx,
            socket_arp,
            _net_tx_task: net_tx_task,
            _vrrp_net_rx_task: vrrp_net_rx_task,
            net_tx_packetp,
        })
    }
}

// ===== impl ProtocolInputChannelsRx =====

#[async_trait]
impl MessageReceiver<ProtocolInputMsg> for ProtocolInputChannelsRx {
    async fn recv(&mut self) -> Option<ProtocolInputMsg> {
        tokio::select! {
            biased;
            msg = self.vrrp_net_packet_rx.recv() => {
                msg.map(ProtocolInputMsg::VrrpNetRxPacket)
            }
            msg = self.master_down_timer_rx.recv() => {
                msg.map(ProtocolInputMsg::MasterDownTimer)
            }
        }
    }
}

// ===== helper functions =====

async fn process_ibus_msg(
    interface: &mut Interface,
    msg: IbusMsg,
) -> Result<(), Error> {
    match msg {
        // Interface update notification.
        IbusMsg::InterfaceUpd(msg) => {
            southbound::process_iface_update(interface, msg);
        }
        // Interface address addition notification.
        IbusMsg::InterfaceAddressAdd(msg) => {
            southbound::process_addr_add(interface, msg);
        }
        // Interface address delete notification.
        IbusMsg::InterfaceAddressDel(msg) => {
            southbound::process_addr_del(interface, msg);
        }
        // Ignore other events.
        _ => {}
    }

    Ok(())
}

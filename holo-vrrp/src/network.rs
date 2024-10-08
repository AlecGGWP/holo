//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::ffi::CString;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::{capabilities, Sender, UnboundedReceiver};
use libc::{if_nametoindex, AF_PACKET, ETH_P_ARP, ETH_P_IP};
use nix::sys::socket;
use socket2::{Domain, InterfaceIndexOrAddress, Protocol, Type};
use tokio::sync::mpsc::error::SendError;
use tracing::{debug, debug_span};

use crate::error::IoError;
use crate::interface::Interface;
use crate::packet::{ArpPacket, EthernetFrame, Ipv4Packet, VrrpPacket};
use crate::tasks::messages::input::VrrpNetRxPacketMsg;
use crate::tasks::messages::output::NetTxPacketMsg;

pub fn socket_vrrp_tx(
    interface: &Interface,
    vrid: u8,
) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        let instance = interface.instances.get(&vrid).unwrap();

        let sock = capabilities::raise(|| {
            Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(112)))
        })?;

        capabilities::raise(|| sock.set_nonblocking(true))?;

        // to be uncommented in due time.
        //if let Some(addr) = instance.mac_vlan.system.addresses.first() {
        //    capabilities::raise(|| {
        //        match sock.set_multicast_if_v4(&addr.ip()) {
        //            Ok(_res) => {
        //                debug_span!("socket-vrrp").in_scope(|| {
        //                    debug!("successfully joined multicast interface");
        //                });
        //            }
        //            Err(err) => {
        //                debug_span!("socket-vrrp").in_scope(|| {
        //                    debug!(%addr, %err, "unable to join multicast interface");
        //                });
        //            }
        //        }
        //    });
        //}

        // Confirm if we should bind to the primary interface's address...
        // bind it to the primary interface's name
        capabilities::raise(|| {
            sock.bind_device(Some(interface.name.as_str().as_bytes()))
        })?;
        capabilities::raise(|| {
            sock.set_reuse_address(true);
        });

        Ok(sock)
    }
    #[cfg(feature = "testing")]
    {
        Ok(Socket {})
    }
}

pub fn socket_vrrp_rx(ifname: &str) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        let sock = capabilities::raise(|| {
            Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(112)))
        })?;

        capabilities::raise(|| sock.bind_device(Some(ifname.as_bytes())))?;
        capabilities::raise(|| sock.set_broadcast(true))?;
        capabilities::raise(|| sock.set_nonblocking(true))?;
        capabilities::raise(|| join_multicast(&sock, ifname))?;

        Ok(sock)
    }
    #[cfg(feature = "testing")]
    {
        Ok(Socket {})
    }
}

pub fn socket_arp(ifname: &str) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        let sock = capabilities::raise(|| {
            Socket::new(
                Domain::PACKET,
                Type::RAW,
                Some(Protocol::from(ETH_P_ARP)),
            )
        })?;
        capabilities::raise(|| {
            let _ = sock.bind_device(Some(ifname.as_bytes()));
            let _ = sock.set_broadcast(true);
        });
        Ok(sock)
    }
    #[cfg(feature = "testing")]
    {
        Ok(Socket {})
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn send_packet_vrrp(
    sock: &AsyncFd<Socket>,
    ifname: &str,
    buf: &[u8],
) -> Result<usize, IoError> {
    let c_ifname = CString::new(ifname).unwrap();

    unsafe {
        let ifindex = libc::if_nametoindex(c_ifname.as_ptr());
        let mut sa = libc::sockaddr_ll {
            sll_family: libc::AF_INET as u16,
            sll_protocol: (ETH_P_IP as u16).to_be(),
            sll_ifindex: ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };

        let ptr_sockaddr = std::mem::transmute::<
            *mut libc::sockaddr_ll,
            *mut libc::sockaddr,
        >(&mut sa);

        match libc::sendto(
            sock.as_raw_fd(),
            buf.as_ptr().cast(),
            std::cmp::min(buf.len(), 130),
            0,
            ptr_sockaddr,
            std::mem::size_of_val(&sa) as u32,
        ) {
            -1 => Err(IoError::SendError(std::io::Error::last_os_error())),
            fd => Ok(fd as usize),
        }
    }
}

#[cfg(not(feature = "testing"))]
pub async fn send_packet_arp(
    sock: &AsyncFd<Socket>,
    ifname: &str,
    eth_frame: EthernetFrame,
    arp_packet: ArpPacket,
) -> Result<usize, IoError> {
    use std::ffi::CString;

    use libc::{c_void, sendto, sockaddr, sockaddr_ll};

    use crate::packet::ARPframe;
    let mut arpframe = ARPframe::new(eth_frame, arp_packet);

    let c_ifname = match CString::new(ifname) {
        Ok(c_ifname) => c_ifname,
        Err(err) => {
            return Err(IoError::SocketError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                err,
            )))
        }
    };
    let ifindex = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) };

    let mut sa = sockaddr_ll {
        sll_family: AF_PACKET as u16,
        sll_protocol: 0x806_u16.to_be(),
        sll_ifindex: ifindex as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    unsafe {
        let ptr_sockaddr =
            std::mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(&mut sa);

        match sendto(
            sock.as_raw_fd(),
            &mut arpframe as *mut _ as *const c_void,
            std::mem::size_of_val(&arpframe),
            0,
            ptr_sockaddr,
            std::mem::size_of_val(&sa) as u32,
        ) {
            -1 => Err(IoError::SendError(std::io::Error::last_os_error())),
            fd => Ok(fd as usize),
        }
    }
}

// for joining the VRRP multicast
pub fn join_multicast(
    sock: &Socket,
    ifname: &str,
) -> Result<(), std::io::Error> {
    let sock = socket2::SockRef::from(sock);
    let ifname = CString::new(ifname).unwrap();
    let ifindex = unsafe { if_nametoindex(ifname.as_ptr()) };

    sock.join_multicast_v4_n(
        &Ipv4Addr::new(224, 0, 0, 18),
        &InterfaceIndexOrAddress::Index(ifindex),
    )
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn write_loop(
    socket_vrrp: Arc<AsyncFd<Socket>>,
    socket_arp: Arc<AsyncFd<Socket>>,
    mut net_tx_packetc: UnboundedReceiver<NetTxPacketMsg>,
) {
    while let Some(msg) = net_tx_packetc.recv().await {
        match msg {
            NetTxPacketMsg::Vrrp { ifname, buf } => {
                if let Err(error) =
                    send_packet_vrrp(&socket_vrrp, &ifname, &buf[..]).await
                {
                    error.log();
                }
            }
            NetTxPacketMsg::Arp {
                name,
                eth_frame,
                arp_packet,
            } => {
                if let Err(error) =
                    send_packet_arp(&socket_arp, &name, eth_frame, arp_packet)
                        .await
                {
                    error.log();
                }
            }
        }
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn vrrp_read_loop(
    socket_vrrp: Arc<AsyncFd<Socket>>,
    vrrp_net_packet_rxp: Sender<VrrpNetRxPacketMsg>,
) -> Result<(), SendError<VrrpNetRxPacketMsg>> {
    let mut buf = [0; 128];
    loop {
        match socket_vrrp
            .async_io(tokio::io::Interest::READABLE, |sock| {
                match socket::recv(
                    sock.as_raw_fd(),
                    &mut buf,
                    socket::MsgFlags::empty(),
                ) {
                    Ok(msg) => {
                        let data = &buf[0..msg];

                        // since ip header length is given in number of words
                        // (4 bytes per word), we multiply by 4 to get the actual
                        // number of bytes
                        let ip_header_len = ((data[0] & 0x0f) * 4) as usize;

                        let ip_pkt =
                            Ipv4Packet::decode(&data[0..ip_header_len])
                                .unwrap();
                        let vrrp_pkt =
                            VrrpPacket::decode(&data[ip_header_len..]);
                        Ok((ip_pkt.src_address, vrrp_pkt))
                    }
                    Err(errno) => Err(errno.into()),
                }
            })
            .await
        {
            Ok((src, vrrp_pkt)) => {
                let msg = VrrpNetRxPacketMsg {
                    src,
                    packet: vrrp_pkt,
                };
                vrrp_net_packet_rxp.send(msg).await.unwrap();
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                // retry if the syscall was interrupted
                continue;
            }
            Err(error) => {
                IoError::RecvError(error).log();
            }
        }
    }
}

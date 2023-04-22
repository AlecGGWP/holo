//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::Ipv4Addr;
use std::os::unix::io::BorrowedFd;
use std::str::FromStr;
use std::sync::LazyLock as Lazy;

use bytes::{Buf, Bytes};
use holo_utils::capabilities;
use holo_utils::ip::AddressFamily;
use holo_utils::socket::{Socket, SocketExt};
use ipnetwork::Ipv4Network;
use nix::sys::socket::{self, SockaddrIn};
use socket2::InterfaceIndexOrAddress;

use crate::network::{MulticastAddr, NetworkVersion, OSPF_IP_PROTO};
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::Packet;
use crate::version::Ospfv2;

// OSPFv2 multicast addresses.
static ALL_SPF_RTRS: Lazy<Ipv4Addr> =
    Lazy::new(|| Ipv4Addr::from_str("224.0.0.5").unwrap());
static ALL_DR_RTRS: Lazy<Ipv4Addr> =
    Lazy::new(|| Ipv4Addr::from_str("224.0.0.6").unwrap());

// ===== impl Ospfv2 =====

impl NetworkVersion<Self> for Ospfv2 {
    type NetIpAddr = Ipv4Addr;
    type NetIpNetwork = Ipv4Network;
    type SocketAddr = SockaddrIn;
    type Pktinfo = libc::in_pktinfo;

    fn socket() -> Result<Socket, std::io::Error> {
        #[cfg(not(feature = "testing"))]
        {
            use socket2::{Domain, Protocol, Type};

            let socket = capabilities::raise(|| {
                Socket::new(
                    Domain::IPV4,
                    Type::RAW,
                    Some(Protocol::from(OSPF_IP_PROTO)),
                )
            })?;

            socket.set_multicast_loop_v4(false)?;
            socket.set_multicast_ttl_v4(1)?;
            socket.set_ipv4_pktinfo(true)?;
            socket.set_tos(libc::IPTOS_PREC_INTERNETCONTROL as u32)?;

            Ok(socket)
        }
        #[cfg(feature = "testing")]
        {
            Ok(Socket {})
        }
    }

    fn multicast_addr(addr: MulticastAddr) -> &'static Ipv4Addr {
        match addr {
            MulticastAddr::AllSpfRtrs => &ALL_SPF_RTRS,
            MulticastAddr::AllDrRtrs => &ALL_DR_RTRS,
        }
    }

    fn join_multicast(
        socket: BorrowedFd<'_>,
        addr: MulticastAddr,
        ifindex: u32,
    ) -> Result<(), std::io::Error> {
        let addr = Self::multicast_addr(addr);
        let socket = socket2::SockRef::from(&socket);
        socket
            .join_multicast_v4_n(addr, &InterfaceIndexOrAddress::Index(ifindex))
    }

    fn leave_multicast(
        socket: BorrowedFd<'_>,
        addr: MulticastAddr,
        ifindex: u32,
    ) -> Result<(), std::io::Error> {
        let addr = Self::multicast_addr(addr);
        let socket = socket2::SockRef::from(&socket);
        socket.leave_multicast_v4_n(
            addr,
            &InterfaceIndexOrAddress::Index(ifindex),
        )
    }

    fn new_pktinfo(src: Option<Ipv4Addr>, ifindex: u32) -> libc::in_pktinfo {
        libc::in_pktinfo {
            ipi_ifindex: ifindex as i32,
            ipi_spec_dst: libc::in_addr { s_addr: 0 },
            ipi_addr: libc::in_addr {
                s_addr: src.unwrap_or(Ipv4Addr::UNSPECIFIED).into(),
            },
        }
    }

    fn set_cmsg_data(pktinfo: &libc::in_pktinfo) -> socket::ControlMessage<'_> {
        socket::ControlMessage::Ipv4PacketInfo(pktinfo)
    }

    fn get_cmsg_data(
        mut cmsgs: socket::CmsgIterator<'_>,
    ) -> Option<(u32, Ipv4Addr)> {
        cmsgs.find_map(|cmsg| {
            if let socket::ControlMessageOwned::Ipv4PacketInfo(pktinfo) = cmsg {
                let ifindex = pktinfo.ipi_ifindex as u32;
                let dst = Ipv4Addr::from(pktinfo.ipi_spec_dst.s_addr.to_be());
                Some((ifindex, dst))
            } else {
                None
            }
        })
    }

    fn dst_to_sockaddr(_ifindex: u32, addr: Ipv4Addr) -> SockaddrIn {
        std::net::SocketAddrV4::new(addr, 0).into()
    }

    fn src_from_sockaddr(sockaddr: &SockaddrIn) -> Ipv4Addr {
        Ipv4Addr::from(sockaddr.ip())
    }

    fn decode_packet(
        af: AddressFamily,
        data: &[u8],
    ) -> DecodeResult<Packet<Self>> {
        let mut buf = Bytes::copy_from_slice(data);
        let buf_len = buf.len() as u16;

        // Parse IHL (header length).
        let hdr_len = buf.get_u8() & 0x0F;

        // Ignore TOS.
        let _ = buf.get_u8();

        // Parse and validate the IP header total length.
        let total_len = buf.get_u16();
        if buf_len != total_len {
            return Err(DecodeError::InvalidIpHdrLength(total_len));
        }

        // Move past the IP header.
        buf.advance(((hdr_len << 2) - 4) as usize);

        // Parse OSPFv2 packet.
        Packet::decode(af, buf.as_ref())
    }
}
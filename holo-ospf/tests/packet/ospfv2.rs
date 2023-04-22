//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::LazyLock as Lazy;

use bytes::Bytes;
use holo_ospf::ospfv2::packet::lsa::*;
use holo_ospf::ospfv2::packet::lsa_opaque::*;
use holo_ospf::ospfv2::packet::*;
use holo_ospf::packet::lsa::{Lsa, LsaKey};
use holo_ospf::packet::tlv::*;
use holo_ospf::packet::{DbDescFlags, Packet, PacketType};
use holo_ospf::version::Ospfv2;
use holo_utils::ip::AddressFamily;
use holo_utils::mpls::Label;
use holo_utils::sr::{IgpAlgoType, Sid};
use ipnetwork::Ipv4Network;
use maplit::{btreemap, btreeset};

//
// Helper functions.
//

fn test_encode_packet(bytes_expected: &[u8], packet: &Packet<Ospfv2>) {
    let bytes_actual = packet.encode();
    assert_eq!(bytes_expected, bytes_actual.as_ref());
}

fn test_decode_packet(bytes: &[u8], packet_expected: &Packet<Ospfv2>) {
    let packet_actual = Packet::decode(AddressFamily::Ipv4, &bytes).unwrap();
    assert_eq!(*packet_expected, packet_actual);
}

fn test_encode_lsa(bytes_expected: &[u8], lsa: &Lsa<Ospfv2>) {
    assert_eq!(bytes_expected, lsa.raw.as_ref());
}

fn test_decode_lsa(bytes: &[u8], lsa_expected: &Lsa<Ospfv2>) {
    let mut bytes = Bytes::copy_from_slice(bytes);
    let lsa_actual = Lsa::decode(AddressFamily::Ipv4, &mut bytes).unwrap();
    assert_eq!(*lsa_expected, lsa_actual);
}

//
// Test packets.
//

static HELLO1: Lazy<(Vec<u8>, Packet<Ospfv2>)> = Lazy::new(|| {
    (
        vec![
            0x02, 0x01, 0x00, 0x30, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x00,
            0x01, 0xf6, 0x9e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00,
            0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x01, 0x01, 0x01,
        ],
        Packet::Hello(Hello {
            hdr: PacketHdr {
                pkt_type: PacketType::Hello,
                router_id: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                area_id: Ipv4Addr::from_str("0.0.0.1").unwrap(),
            },
            network_mask: Ipv4Addr::from_str("255.255.255.0").unwrap(),
            hello_interval: 3,
            options: Options::E,
            priority: 1,
            dead_interval: 36,
            dr: None,
            bdr: None,
            neighbors: [Ipv4Addr::from_str("1.1.1.1").unwrap()].into(),
        }),
    )
});

static DBDESC1: Lazy<(Vec<u8>, Packet<Ospfv2>)> = Lazy::new(|| {
    (
        vec![
            0x02, 0x02, 0x00, 0x48, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
            0x01, 0xd8, 0x9e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x05, 0xdc, 0x42, 0x00, 0x4e, 0xb8, 0x8f, 0x2e, 0x00,
            0x03, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x80, 0x00, 0x00, 0x02, 0x48, 0xd6, 0x00, 0x30, 0x00, 0x03, 0x02,
            0x05, 0xac, 0x10, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00,
            0x00, 0x01, 0xfc, 0xff, 0x00, 0x24,
        ],
        Packet::DbDesc(DbDesc {
            hdr: PacketHdr {
                pkt_type: PacketType::DbDesc,
                router_id: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                area_id: Ipv4Addr::from_str("0.0.0.1").unwrap(),
            },
            mtu: 1500,
            options: Options::E | Options::O,
            dd_flags: DbDescFlags::empty(),
            dd_seq_no: 1320718126,
            lsa_hdrs: vec![
                LsaHdr {
                    age: 3,
                    options: Options::E,
                    lsa_type: LsaTypeCode::Router.into(),
                    lsa_id: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                    adv_rtr: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                    seq_no: 0x80000002,
                    cksum: 0x48d6,
                    length: 48,
                },
                LsaHdr {
                    age: 3,
                    options: Options::E,
                    lsa_type: LsaTypeCode::AsExternal.into(),
                    lsa_id: Ipv4Addr::from_str("172.16.1.0").unwrap(),
                    adv_rtr: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                    seq_no: 0x80000001,
                    cksum: 0xfcff,
                    length: 36,
                },
            ],
        }),
    )
});

static LSREQUEST1: Lazy<(Vec<u8>, Packet<Ospfv2>)> = Lazy::new(|| {
    (
        vec![
            0x02, 0x03, 0x00, 0x30, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x00,
            0x01, 0x46, 0xab, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x05, 0xac, 0x10, 0x01, 0x00,
            0x01, 0x01, 0x01, 0x01,
        ],
        Packet::LsRequest(LsRequest {
            hdr: PacketHdr {
                pkt_type: PacketType::LsRequest,
                router_id: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                area_id: Ipv4Addr::from_str("0.0.0.1").unwrap(),
            },
            entries: vec![
                LsaKey {
                    lsa_type: LsaTypeCode::Router.into(),
                    adv_rtr: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                    lsa_id: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                },
                LsaKey {
                    lsa_type: LsaTypeCode::AsExternal.into(),
                    adv_rtr: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                    lsa_id: Ipv4Addr::from_str("172.16.1.0").unwrap(),
                },
            ],
        }),
    )
});

static LSUPDATE1: Lazy<(Vec<u8>, Packet<Ospfv2>)> = Lazy::new(|| {
    (
        vec![
            0x02, 0x04, 0x00, 0x78, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x00,
            0x01, 0x40, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x31, 0x02, 0x01, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x80, 0x00, 0x00, 0x02,
            0x37, 0xf4, 0x00, 0x24, 0x01, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x01,
            0x00, 0xff, 0xff, 0xff, 0x00, 0x03, 0x00, 0x00, 0x0a, 0x00, 0x31,
            0x02, 0x03, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x80,
            0x00, 0x00, 0x01, 0xd2, 0x7a, 0x00, 0x1c, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x02, 0x03, 0x0a, 0x00, 0x02,
            0x00, 0x02, 0x02, 0x02, 0x02, 0x80, 0x00, 0x00, 0x01, 0xfa, 0x44,
            0x00, 0x1c, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x0a,
        ],
        Packet::LsUpdate(LsUpdate {
            hdr: PacketHdr {
                pkt_type: PacketType::LsUpdate,
                router_id: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                area_id: Ipv4Addr::from_str("0.0.0.1").unwrap(),
            },
            lsas: vec![
                Lsa::new(
                    49,
                    Some(Options::E),
                    Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    0x80000002,
                    LsaBody::Router(LsaRouter {
                        flags: LsaRouterFlags::B,
                        links: vec![LsaRouterLink {
                            link_type: LsaRouterLinkType::StubNetwork,
                            link_id: Ipv4Addr::from_str("10.0.1.0").unwrap(),
                            link_data: Ipv4Addr::from_str("255.255.255.0")
                                .unwrap(),
                            metric: 10,
                        }],
                    }),
                ),
                Lsa::new(
                    49,
                    Some(Options::E),
                    Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    0x80000001,
                    LsaBody::SummaryNetwork(LsaSummary {
                        mask: Ipv4Addr::from_str("255.255.255.255").unwrap(),
                        metric: 0,
                    }),
                ),
                Lsa::new(
                    49,
                    Some(Options::E),
                    Ipv4Addr::from_str("10.0.2.0").unwrap(),
                    Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    0x80000001,
                    LsaBody::SummaryNetwork(LsaSummary {
                        mask: Ipv4Addr::from_str("255.255.255.0").unwrap(),
                        metric: 10,
                    }),
                ),
            ],
        }),
    )
});

static LSACK1: Lazy<(Vec<u8>, Packet<Ospfv2>)> = Lazy::new(|| {
    (
        vec![
            0x02, 0x05, 0x00, 0x54, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
            0x01, 0xa0, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x03, 0x03, 0x03, 0x03, 0x02,
            0x02, 0x02, 0x02, 0x80, 0x00, 0x00, 0x01, 0x09, 0x36, 0x00, 0x1c,
            0x00, 0x01, 0x02, 0x03, 0x0a, 0x00, 0x03, 0x00, 0x02, 0x02, 0x02,
            0x02, 0x80, 0x00, 0x00, 0x01, 0x54, 0xdf, 0x00, 0x1c, 0x00, 0x01,
            0x02, 0x03, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x02, 0x02, 0x02, 0x80,
            0x00, 0x00, 0x01, 0x49, 0xe9, 0x00, 0x1c,
        ],
        Packet::LsAck(LsAck {
            hdr: PacketHdr {
                pkt_type: PacketType::LsAck,
                router_id: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                area_id: Ipv4Addr::from_str("0.0.0.1").unwrap(),
            },
            lsa_hdrs: vec![
                LsaHdr {
                    age: 1,
                    options: Options::E,
                    lsa_type: LsaTypeCode::SummaryNetwork.into(),
                    lsa_id: Ipv4Addr::from_str("3.3.3.3").unwrap(),
                    adv_rtr: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    seq_no: 0x80000001,
                    cksum: 0x0936,
                    length: 28,
                },
                LsaHdr {
                    age: 1,
                    options: Options::E,
                    lsa_type: LsaTypeCode::SummaryNetwork.into(),
                    lsa_id: Ipv4Addr::from_str("10.0.3.0").unwrap(),
                    adv_rtr: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    seq_no: 0x80000001,
                    cksum: 0x54df,
                    length: 28,
                },
                LsaHdr {
                    age: 1,
                    options: Options::E,
                    lsa_type: LsaTypeCode::SummaryNetwork.into(),
                    lsa_id: Ipv4Addr::from_str("10.0.4.0").unwrap(),
                    adv_rtr: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    seq_no: 0x80000001,
                    cksum: 0x49e9,
                    length: 28,
                },
            ],
        }),
    )
});

//
// Test LSAs.
//

static LSA1: Lazy<(Vec<u8>, Lsa<Ospfv2>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x31, 0x02, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x80, 0x00, 0x00, 0x02, 0x37, 0xf4, 0x00, 0x24, 0x01, 0x00,
            0x00, 0x01, 0x0a, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0x00, 0x03,
            0x00, 0x00, 0x0a,
        ],
        Lsa::new(
            49,
            Some(Options::E),
            Ipv4Addr::from_str("2.2.2.2").unwrap(),
            Ipv4Addr::from_str("2.2.2.2").unwrap(),
            0x80000002,
            LsaBody::Router(LsaRouter {
                flags: LsaRouterFlags::B,
                links: vec![LsaRouterLink {
                    link_type: LsaRouterLinkType::StubNetwork,
                    link_id: Ipv4Addr::from_str("10.0.1.0").unwrap(),
                    link_data: Ipv4Addr::from_str("255.255.255.0").unwrap(),
                    metric: 10,
                }],
            }),
        ),
    )
});

static LSA2: Lazy<(Vec<u8>, Lsa<Ospfv2>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x01, 0x42, 0x0a, 0x04, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
            0x01, 0x80, 0x00, 0x00, 0x01, 0x20, 0x95, 0x00, 0x44, 0x00, 0x01,
            0x00, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x0b, 0x00, 0x1f, 0x40, 0x00,
            0x00, 0x01, 0x00, 0x03, 0x00, 0x3e, 0x80, 0x00, 0x00, 0x0e, 0x00,
            0x0b, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x3a,
            0x98, 0x00,
        ],
        Lsa::new(
            1,
            Some(Options::O | Options::E),
            OpaqueLsaId::new(LsaOpaqueType::RouterInfo as u8, 0).into(),
            Ipv4Addr::from_str("1.1.1.1").unwrap(),
            0x80000001,
            LsaBody::OpaqueArea(LsaOpaque::RouterInfo(LsaRouterInfo {
                info_caps: Some(RouterInfoCaps::TE.into()),
                func_caps: None,
                sr_algo: Some(SrAlgoTlv::new(btreeset!(IgpAlgoType::Spf))),
                srgb: vec![SidLabelRangeTlv::new(
                    Sid::Label(Label::new(16000)),
                    8000,
                )],
                srlb: vec![SrLocalBlockTlv::new(
                    Sid::Label(Label::new(15000)),
                    1000,
                )],
                msds: None,
                srms_pref: None,
                unknown_tlvs: vec![],
            })),
        ),
    )
});

static LSA3: Lazy<(Vec<u8>, Lsa<Ospfv2>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x01, 0x42, 0x0a, 0x07, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
            0x01, 0x80, 0x00, 0x00, 0x01, 0xda, 0x91, 0x00, 0x2c, 0x00, 0x01,
            0x00, 0x14, 0x01, 0x20, 0x00, 0x40, 0x01, 0x01, 0x01, 0x01, 0x00,
            0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
        ],
        Lsa::new(
            1,
            Some(Options::O | Options::E),
            Ipv4Addr::from_str("7.0.0.0").unwrap(),
            Ipv4Addr::from_str("1.1.1.1").unwrap(),
            0x80000001,
            LsaBody::OpaqueArea(LsaOpaque::ExtPrefix(LsaExtPrefix {
                prefixes: btreemap! {
                    Ipv4Network::from_str("1.1.1.1/32").unwrap() => {
                        ExtPrefixTlv {
                            route_type: ExtPrefixRouteType::IntraArea,
                            af: 0,
                            flags: LsaExtPrefixFlags::N,
                            prefix: Ipv4Network::from_str("1.1.1.1/32").unwrap(),
                            prefix_sids: btreemap! {
                                IgpAlgoType::Spf => {
                                    PrefixSid {
                                        flags: PrefixSidFlags::empty(),
                                        algo: IgpAlgoType::Spf,
                                        sid: Sid::Index(10),
                                    }
                                }
                            },
                            unknown_tlvs: vec![],
                        }
                    },
                },
            })),
        ),
    )
});

static LSA4: Lazy<(Vec<u8>, Lsa<Ospfv2>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x01, 0x42, 0x0a, 0x08, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
            0x01, 0x80, 0x00, 0x00, 0x01, 0xe3, 0xca, 0x00, 0x30, 0x00, 0x01,
            0x00, 0x18, 0x01, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x0a,
            0x00, 0x01, 0x01, 0x00, 0x02, 0x00, 0x07, 0x60, 0x00, 0x00, 0x00,
            0x00, 0x0f, 0xa0, 0x00,
        ],
        Lsa::new(
            1,
            Some(Options::O | Options::E),
            Ipv4Addr::from_str("8.0.0.0").unwrap(),
            Ipv4Addr::from_str("1.1.1.1").unwrap(),
            0x80000001,
            LsaBody::OpaqueArea(LsaOpaque::ExtLink(LsaExtLink {
                link: Some(ExtLinkTlv {
                    link_type: LsaRouterLinkType::PointToPoint,
                    link_id: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    link_data: Ipv4Addr::from_str("10.0.1.1").unwrap(),
                    adj_sids: vec![AdjSid {
                        flags: AdjSidFlags::V | AdjSidFlags::L,
                        weight: 0,
                        nbr_router_id: None,
                        sid: Sid::Label(Label::new(4000)),
                    }],
                    msds: Default::default(),
                    unknown_tlvs: vec![],
                }),
            })),
        ),
    )
});

//
// Tests.
//

#[test]
fn test_encode_hello1() {
    let (ref bytes, ref hello) = *HELLO1;
    test_encode_packet(bytes, hello);
}

#[test]
fn test_decode_hello1() {
    let (ref bytes, ref hello) = *HELLO1;
    test_decode_packet(bytes, hello);
}

#[test]
fn test_encode_dbdesc1() {
    let (ref bytes, ref dbdescr) = *DBDESC1;
    test_encode_packet(bytes, dbdescr);
}

#[test]
fn test_decode_dbdesc1() {
    let (ref bytes, ref dbdescr) = *DBDESC1;
    test_decode_packet(bytes, dbdescr);
}

#[test]
fn test_encode_lsrequest1() {
    let (ref bytes, ref request) = *LSREQUEST1;
    test_encode_packet(bytes, request);
}

#[test]
fn test_decode_lsrequest1() {
    let (ref bytes, ref request) = *LSREQUEST1;
    test_decode_packet(bytes, request);
}

#[test]
fn test_encode_lsupdate1() {
    let (ref bytes, ref lsupdate) = *LSUPDATE1;
    test_encode_packet(bytes, lsupdate);
}

#[test]
fn test_decode_lsupdate1() {
    let (ref bytes, ref lsupdate) = *LSUPDATE1;
    test_decode_packet(bytes, lsupdate);
}

#[test]
fn test_encode_lsack1() {
    let (ref bytes, ref lsack) = *LSACK1;
    test_encode_packet(bytes, lsack);
}

#[test]
fn test_decode_lsack1() {
    let (ref bytes, ref lsack) = *LSACK1;
    test_decode_packet(bytes, lsack);
}

#[test]
fn test_encode_lsa1() {
    let (ref bytes, ref lsa) = *LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_lsa1() {
    let (ref bytes, ref lsa) = *LSA1;
    test_decode_lsa(bytes, lsa);
}

#[test]
fn test_encode_lsa2() {
    let (ref bytes, ref lsa) = *LSA2;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_lsa2() {
    let (ref bytes, ref lsa) = *LSA2;
    test_decode_lsa(bytes, lsa);
}

#[test]
fn test_encode_lsa3() {
    let (ref bytes, ref lsa) = *LSA3;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_lsa3() {
    let (ref bytes, ref lsa) = *LSA3;
    test_decode_lsa(bytes, lsa);
}

#[test]
fn test_encode_lsa4() {
    let (ref bytes, ref lsa) = *LSA4;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_lsa4() {
    let (ref bytes, ref lsa) = *LSA4;
    test_decode_lsa(bytes, lsa);
}
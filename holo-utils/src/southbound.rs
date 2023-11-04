//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::IpAddr;

use bitflags::bitflags;
use holo_yang::ToYang;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::mpls::Label;
use crate::protocol::Protocol;

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct InterfaceFlags: u8 {
        const LOOPBACK = 0x01;
        const OPERATIVE = 0x02;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct AddressFlags: u8 {
        const UNNUMBERED = 0x01;
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum Nexthop {
    Address {
        ifindex: u32,
        addr: IpAddr,
        labels: Vec<Label>,
    },
    Interface {
        ifindex: u32,
    },
    Special(NexthopSpecial),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum NexthopSpecial {
    Blackhole,
    Unreachable,
    Prohibit,
}

// ===== Ibus messages =====

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct InterfaceUpdateMsg {
    pub ifname: String,
    pub ifindex: u32,
    pub mtu: u32,
    pub flags: InterfaceFlags,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct AddressMsg {
    pub ifname: String,
    pub addr: IpNetwork,
    pub flags: AddressFlags,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct RouteMsg {
    pub protocol: Protocol,
    pub prefix: IpNetwork,
    pub distance: u32,
    pub metric: u32,
    pub tag: Option<u32>,
    pub nexthops: BTreeSet<Nexthop>,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct RouteKeyMsg {
    pub protocol: Protocol,
    pub prefix: IpNetwork,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct LabelInstallMsg {
    pub protocol: Protocol,
    pub label: Label,
    pub nexthops: BTreeSet<Nexthop>,
    pub route: Option<(Protocol, IpNetwork)>,
    pub replace: bool,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct LabelUninstallMsg {
    pub protocol: Protocol,
    pub label: Label,
    pub nexthops: BTreeSet<Nexthop>,
    pub route: Option<(Protocol, IpNetwork)>,
}

// ===== impl Nexthop =====

impl Nexthop {
    // Compares two `Nexthop` instances for equality.
    pub fn matches(&self, other: &Nexthop) -> bool {
        self == other
    }

    // Compares two `Nexthop` instances for equality, excluding the `labels`
    // field in the `Address` variant.
    pub fn matches_no_labels(&self, other: &Nexthop) -> bool {
        match (self, other) {
            (
                Nexthop::Address {
                    ifindex: ifindex1,
                    addr: addr1,
                    ..
                },
                Nexthop::Address {
                    ifindex: ifindex2,
                    addr: addr2,
                    ..
                },
            ) => ifindex1 == ifindex2 && addr1 == addr2,
            (
                Nexthop::Interface { ifindex: ifindex1 },
                Nexthop::Interface { ifindex: ifindex2 },
            ) => ifindex1 == ifindex2,
            (Nexthop::Special(nexthop1), Nexthop::Special(nexthop2)) => {
                nexthop1 == nexthop2
            }
            _ => false,
        }
    }

    // Removes all labels from a `Nexthop::Address` variant.
    pub fn remove_labels(&mut self) {
        if let Nexthop::Address { labels, .. } = self {
            *labels = Vec::new();
        }
    }

    // Copies the `labels` field from another `Nexthop` instance to this one.
    pub fn copy_labels(&mut self, other: &Nexthop) {
        if let (
            Nexthop::Address {
                labels: labels1, ..
            },
            Nexthop::Address {
                labels: labels2, ..
            },
        ) = (self, other)
        {
            *labels1 = labels2.clone()
        }
    }
}

// ===== impl NexthopSpecial =====

impl ToYang for NexthopSpecial {
    fn to_yang(&self) -> String {
        match self {
            NexthopSpecial::Blackhole => "blackhole".to_owned(),
            NexthopSpecial::Unreachable => "unreachable".to_owned(),
            NexthopSpecial::Prohibit => "prohibit".to_owned(),
        }
    }
}
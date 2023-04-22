//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::collections::HashMap;
use std::net::Ipv4Addr;

use ipnetwork::Ipv4Network;

use crate::area::{Area, AreaType, AreaVersion};
use crate::ospfv2::packet::lsa_opaque::ExtPrefixTlv;
use crate::ospfv2::packet::Options;
use crate::version::Ospfv2;

#[derive(Debug, Default)]
pub struct AreaState {
    pub ext_prefix_db: HashMap<(Ipv4Addr, Ipv4Network), ExtPrefixTlv>,
}

// ===== impl Ospfv2 =====

impl AreaVersion<Self> for Ospfv2 {
    type State = AreaState;

    fn area_options(area: &Area<Self>, db_desc: bool) -> Options {
        let mut options = Options::empty();

        if area.config.area_type == AreaType::Normal {
            options.insert(Options::E);
        }

        // The O-bit is not set in packets other than Database Description
        // packets.
        if db_desc {
            options.insert(Options::O);
        }

        options
    }
}
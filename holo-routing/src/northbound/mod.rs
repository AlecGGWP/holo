//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

pub mod configuration;
pub mod rpc;
pub mod state;

use std::sync::LazyLock as Lazy;

use holo_northbound::paths::control_plane_protocol;
use holo_northbound::ProviderBase;
use regex::Regex;
use tracing::{debug_span, Span};

use crate::Master;

// ===== impl Master =====

impl ProviderBase for Master {
    fn yang_modules() -> &'static [&'static str] {
        &[
            "ietf-routing",
            "ietf-segment-routing",
            "ietf-segment-routing-common",
            "ietf-segment-routing-mpls",
        ]
    }

    fn top_level_node(&self) -> String {
        "/ietf-routing:routing".to_owned()
    }

    fn debug_span(_name: &str) -> Span {
        debug_span!("routing")
    }
}

// ===== regular expressions =====

// Matches on the protocol type and instance name of a YANG path.
static REGEX_PROTOCOLS_STR: Lazy<String> = Lazy::new(|| {
    format!(
        r"{}\[type='(.+?)'\]\[name='(.+?)'\]*",
        control_plane_protocol::PATH
    )
});
pub static REGEX_PROTOCOLS: Lazy<Regex> =
    Lazy::new(|| Regex::new(&REGEX_PROTOCOLS_STR).unwrap());
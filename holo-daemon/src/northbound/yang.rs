//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::sync::Arc;

use holo_northbound::ProviderBase;
use holo_ospf::version::{Ospfv2, Ospfv3};
use holo_rip::version::{Ripng, Ripv2};
use holo_utils::protocol::Protocol;
use holo_yang as yang;
use holo_yang::YANG_CTX;

use crate::config::Config;

fn modules_add<P: ProviderBase>(modules: &mut Vec<&'static str>) {
    modules.extend(P::yang_modules().iter());
}

pub(crate) fn create_context(config: &Config) {
    let mut modules = Vec::new();

    // Add data type modules.
    for module_name in ["iana-if-type", "ietf-routing-types", "ietf-bfd-types"]
    {
        modules.push(module_name);
    }

    // Add core modules.
    modules_add::<holo_interface::Master>(&mut modules);
    modules_add::<holo_routing::Master>(&mut modules);
    modules_add::<holo_keychain::Master>(&mut modules);

    // Add protocol modules (as per the configuration).
    for protocol in &config.protocols {
        match protocol {
            Protocol::BFD => {
                use holo_bfd::master::Master;
                modules_add::<Master>(&mut modules)
            }
            Protocol::LDP => {
                use holo_ldp::instance::Instance;
                modules_add::<Instance>(&mut modules)
            }
            Protocol::OSPFV2 => {
                use holo_ospf::instance::Instance;
                modules_add::<Instance<Ospfv2>>(&mut modules)
            }
            Protocol::OSPFV3 => {
                use holo_ospf::instance::Instance;
                modules_add::<Instance<Ospfv3>>(&mut modules)
            }
            Protocol::RIPV2 => {
                use holo_rip::instance::Instance;
                modules_add::<Instance<Ripv2>>(&mut modules)
            }
            Protocol::RIPNG => {
                use holo_rip::instance::Instance;
                modules_add::<Instance<Ripng>>(&mut modules)
            }
        };
    }

    // Create YANG context and load all required modules and their deviations.
    let mut yang_ctx = yang::new_context();
    for module_name in modules.iter() {
        yang::load_module(&mut yang_ctx, module_name);
    }
    for module_name in modules.iter().rev() {
        yang::load_deviations(&mut yang_ctx, module_name);
    }
    YANG_CTX.set(Arc::new(yang_ctx)).unwrap();
}
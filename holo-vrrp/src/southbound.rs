//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::ibus::{IbusMsg, IbusSender};
use holo_utils::southbound::{
    AddressMsg, InterfaceUpdateMsg, MacvlanCreateMsg,
};
use ipnetwork::IpNetwork;

use crate::interface::Interface;

// ===== global functions =====
pub(crate) fn process_iface_update(
    iface: &mut Interface,
    msg: InterfaceUpdateMsg,
) {
    // when the iface being updated is the
    // main interface for this `holo-vrrp`
    if msg.ifname == iface.name {
        iface.system.flags = msg.flags;
        iface.system.ifindex = Some(msg.ifindex);
        iface.system.mac_address = msg.mac_address;

        // update names for all macvlans
        for (vrid, instance) in iface.instances.iter_mut() {
            let name = format!("mvlan-vrrp-{}", vrid);
            instance.config.mac_vlan.name = name;
        }
        return;
    }

    // check if it is one of the macvlans being updated.
    for (vrid, instance) in iface.instances.iter_mut() {
        let name = format!("mvlan-vrrp-{}", vrid);
        let mvlan_iface = &mut instance.config.mac_vlan;

        if mvlan_iface.name == name {
            mvlan_iface.system.flags = msg.flags;
            mvlan_iface.system.ifindex = Some(msg.ifindex);
            mvlan_iface.system.mac_address = msg.mac_address;
            mvlan_iface.create_net(&iface.tx);
            return;
        }
    }
}

pub(crate) fn process_addr_add(iface: &mut Interface, msg: AddressMsg) {
    if msg.ifname != iface.name {
        return;
    }

    if let IpNetwork::V4(addr) = msg.addr {
        iface.system.addresses.insert(addr);

        // TODO: trigger protocol event?
    }
}

pub(crate) fn process_addr_del(iface: &mut Interface, msg: AddressMsg) {
    if msg.ifname != iface.name {
        return;
    }

    if let IpNetwork::V4(addr) = msg.addr {
        iface.system.addresses.remove(&addr);

        // TODO: trigger protocol event?
    }
}

// tx messages
pub(crate) fn create_macvlan_address(
    name: String,
    parent_name: String,
    mac_address: [u8; 6],
    ibus_tx: &IbusSender,
) {
    let msg = MacvlanCreateMsg {
        parent_name,
        name,
        mac_address: Some(mac_address),
    };
    let _ = ibus_tx.send(IbusMsg::CreateMacVlan(msg));
}

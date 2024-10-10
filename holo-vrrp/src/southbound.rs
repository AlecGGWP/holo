//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;

use holo_utils::ibus::{IbusMsg, IbusSender};
use holo_utils::southbound::{
    AddressMsg, InterfaceIpAddRequestMsg, InterfaceIpDeleteRequestMsg,
    InterfaceUpdateMsg, MacvlanCreateMsg,
};
use ipnetwork::{IpNetwork, Ipv4Network};

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

        let mut ips: BTreeSet<Ipv4Network> = BTreeSet::default();
        msg.addresses.iter().for_each(|addr| {
            if let IpNetwork::V4(v4addr) = addr {
                ips.insert(*v4addr);
            }
        });
        iface.system.addresses = ips;

        // update names for all macvlans
        for (vrid, instance) in iface.instances.iter_mut() {
            instance.mac_vlan.name = format!("mvlan-vrrp-{}", vrid);
        }
        return;
    }

    let mut target_vrid: Option<u8> = None;

    //check if it is one of the macvlans being updated.
    'outer: for (vrid, instance) in iface.instances.iter_mut() {
        let name = format!("mvlan-vrrp-{}", vrid);
        let mvlan_iface = &mut instance.mac_vlan;

        if mvlan_iface.name == name {
            mvlan_iface.system.flags = msg.flags;
            mvlan_iface.system.ifindex = Some(msg.ifindex);
            mvlan_iface.system.mac_address = msg.mac_address;

            let mut ips: BTreeSet<Ipv4Network> = BTreeSet::default();
            msg.addresses.iter().for_each(|addr| {
                if let IpNetwork::V4(v4addr) = addr {
                    ips.insert(*v4addr);
                }
            });

            mvlan_iface.system.addresses = ips;
            target_vrid = Some(*vrid);

            break 'outer;
        }
    }

    if let Some(vrid) = target_vrid {
        iface.macvlan_create(vrid);
    }
}

pub(crate) fn process_addr_add(iface: &mut Interface, msg: AddressMsg) {
    if msg.ifname == iface.name {
        if let IpNetwork::V4(addr) = msg.addr {
            iface.system.addresses.insert(addr);
        }
    }

    // when this is some, it means that we need to rebind our
    // transmission socket multicast address to the newly added address
    let mut target_vrid: Option<u8> = None;

    // if the interface being updated is one of the macvlans
    for (vrid, instance) in iface.instances.iter_mut() {
        let name = format!("mvlan-vrrp-{}", vrid);
        let mvlan_iface = &mut instance.mac_vlan;
        if mvlan_iface.system.addresses.is_empty() {
            target_vrid = Some(*vrid);
        }
        if mvlan_iface.name == name {
            if let IpNetwork::V4(addr) = msg.addr {
                mvlan_iface.system.addresses.insert(addr);
            }
        }
    }

    if let Some(vrid) = target_vrid {
        iface.macvlan_create(vrid);
        iface.reset_timer(vrid);
    }
}

pub(crate) fn process_addr_del(iface: &mut Interface, msg: AddressMsg) {
    if msg.ifname != iface.name {
        return;
    }

    // remove the address from the addresses of parent interfaces
    if let IpNetwork::V4(addr) = msg.addr {
        iface.system.addresses.remove(&addr);
    }

    for (vrid, instance) in iface.instances.iter_mut() {
        let name = format!("mvlan-vrrp-{}", vrid);
        let mvlan_iface = &mut instance.mac_vlan;

        // if it is one of the macvlans being edited, we
        // remove the macvlan's
        if mvlan_iface.name == name {
            if let IpNetwork::V4(addr) = msg.addr {
                mvlan_iface.system.addresses.remove(&addr);
            }
        }
    }
}

pub(crate) fn create_macvlan_iface(
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

// deletes and interface e.g eth0 entirely
pub(crate) fn mvlan_delete(ifindex: u32, ibus_tx: &IbusSender) {
    let _ = ibus_tx.send(IbusMsg::InterfaceDeleteRequest(ifindex));
}

// adds an address to an interface
pub(crate) fn addr_add(ifindex: u32, addr: IpNetwork, ibus_tx: &IbusSender) {
    let msg = InterfaceIpAddRequestMsg { ifindex, addr };
    let _ = ibus_tx.send(IbusMsg::InterfaceIpAddRequest(msg));
}

// removes a specific address from an interface
pub(crate) fn addr_del(ifindex: u32, addr: IpNetwork, ibus_tx: &IbusSender) {
    let msg = InterfaceIpDeleteRequestMsg { ifindex, addr };
    let _ = ibus_tx.send(IbusMsg::InterfaceIpDeleteRequest(msg));
}

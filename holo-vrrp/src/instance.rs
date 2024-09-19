//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use holo_utils::ibus::IbusSender;
use holo_utils::task::{IntervalTask, TimeoutTask};
use ipnetwork::IpNetwork;

use crate::northbound::configuration::InstanceCfg;
use crate::southbound;

#[derive(Debug)]
pub struct Instance {
    // Instance configuration data.
    pub config: InstanceCfg,

    // Instance state data.
    pub state: InstanceState,

    // timers
    pub timer: VrrpTimer,
}

#[derive(Debug)]
pub enum VrrpTimer {
    Null,
    AdverTimer(IntervalTask),
    MasterDownTimer(TimeoutTask),
}

#[derive(Debug)]
pub struct InstanceState {
    pub state: State,
    pub last_adv_src: Option<Ipv4Addr>,
    pub up_time: Option<DateTime<Utc>>,
    pub last_event: Event,
    pub new_master_reason: MasterReason,
    pub skew_time: f32,
    pub master_down_interval: u32,

    // TODO: interval/timer tasks
    pub statistics: Statistics,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Initialize,
    Backup,
    Master,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    None,
    Startup,
    Shutdown,
    HigherPriorityBackup,
    MasterTimeout,
    InterfaceUp,
    InterfaceDown,
    NoPrimaryIpAddress,
    PrimaryIpAddress,
    NoVirtualIpAddresses,
    VirtualIpAddresses,
    PreemptHoldTimeout,
    LowerPriorityMaster,
    OwnerPreempt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MasterReason {
    NotMaster,
    Priority,
    Preempted,
    NoResponse,
}

#[derive(Debug)]
pub struct Statistics {
    pub discontinuity_time: DateTime<Utc>,
    pub master_transitions: u32,
    pub adv_rcvd: u64,
    pub adv_sent: u64,
    pub interval_errors: u64,
    pub priority_zero_pkts_rcvd: u64,
    pub priority_zero_pkts_sent: u64,
    pub invalid_type_pkts_rcvd: u64,
    pub pkt_length_errors: u64,
    pub checksum_errors: u64,
    pub version_errors: u64,
    pub vrid_errors: u64,
    pub ip_ttl_errors: u64,
}

// ===== impl Instance =====

impl Instance {
    pub(crate) fn new(vrid: u8) -> Self {
        let mut inst = Instance {
            config: InstanceCfg::new(vrid),
            state: InstanceState::new(),
            timer: VrrpTimer::Null,
        };
        inst.set_advert_interval(inst.config.advertise_interval);
        inst
    }

    pub(crate) fn reset_timer(&mut self) {
        match self.timer {
            VrrpTimer::AdverTimer(ref mut t) => {
                t.reset(Some(Duration::from_secs(
                    self.config.advertise_interval as u64,
                )));
            }
            VrrpTimer::MasterDownTimer(ref mut t) => {
                t.reset(Some(Duration::from_secs(
                    self.state.master_down_interval as u64,
                )));
            }
            _ => {}
        }
    }

    // advert interval directly affects other state parameters
    // thus separated in its own function during modification of it.
    pub(crate) fn set_advert_interval(&mut self, advertisement_interval: u8) {
        self.config.advertise_interval = advertisement_interval;
        let skew_time: f32 = (256_f32 - self.config.priority as f32) / 256_f32;
        let master_down: u32 =
            (3_u32 * self.config.advertise_interval as u32) + skew_time as u32;
        self.state.skew_time = skew_time;
        self.state.master_down_interval = master_down;
    }

    // adds a new ip address to the virtual IP addresses
    // while simultaneously adding it to the instance's macvlan address
    pub(crate) fn add_virtual_address(
        &self,
        ibus_tx: &IbusSender,
        addr: IpNetwork,
    ) {
        if let Some(ifindex) = self.config.mac_vlan.system.ifindex {
            southbound::add_addr(ifindex, addr, ibus_tx);
        }
    }
}

// ===== impl InstanceState =====

impl InstanceState {
    pub(crate) fn new() -> Self {
        InstanceState {
            state: State::Initialize,
            last_adv_src: None,
            up_time: None,
            last_event: Event::None,
            new_master_reason: MasterReason::NotMaster,
            statistics: Default::default(),
            skew_time: 0.0,
            master_down_interval: 0,
        }
    }
}

// ===== impl Statistics =====

impl Default for Statistics {
    fn default() -> Self {
        Statistics {
            discontinuity_time: Utc::now(),
            master_transitions: 0,
            adv_rcvd: 0,
            adv_sent: 0,
            interval_errors: 0,
            priority_zero_pkts_rcvd: 0,
            priority_zero_pkts_sent: 0,
            invalid_type_pkts_rcvd: 0,
            pkt_length_errors: 0,
            checksum_errors: 0,
            version_errors: 0,
            vrid_errors: 0,
            ip_ttl_errors: 0,
        }
    }
}

//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use holo_protocol::event_recorder;
use holo_utils::protocol::Protocol;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub protocols: Vec<Protocol>,
    pub user: String,
    pub group: String,
    pub logging: Logging,
    pub tokio_console: TokioConsole,
    pub event_recorder: event_recorder::Config,
    pub plugins: Plugins,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Logging {
    pub journald: LoggingJournald,
    pub file: LoggingFile,
    pub stdout: LoggingFmt,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingJournald {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingFile {
    pub dir: String,
    pub name: String,
    pub rotation: LoggingFileRotation,
    #[serde(flatten)]
    pub inner: LoggingFmt,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingFmt {
    pub enabled: bool,
    pub style: LoggingFmtStyle,
    pub colors: bool,
    pub show_thread_id: bool,
    pub show_source: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LoggingFileRotation {
    #[default]
    Never,
    Hourly,
    Daily,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LoggingFmtStyle {
    Compact,
    Full,
    Json,
    Pretty,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TokioConsole {
    pub enabled: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Plugins {
    pub grpc: Grpc,
    pub gnmi: Gnmi,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Grpc {
    pub enabled: bool,
    pub address: String,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Gnmi {
    pub enabled: bool,
    pub address: String,
    pub tls: Option<GnmiTls>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnmiTls {
    pub certificate: String,
    pub key: String,
}

// ===== impl Config =====

impl Config {
    const DFLT_FILEPATH: &'static str = "/etc/holod.toml";

    pub(crate) fn load(config_file: Option<&str>) -> Config {
        let config_file = config_file.unwrap_or(Config::DFLT_FILEPATH);

        match std::fs::read_to_string(config_file) {
            Ok(config_str) => toml::from_str(&config_str)
                .expect("Failed to parse configuration file"),
            Err(err) => {
                eprintln!("Failed to load configuration file: {}", err);
                eprintln!("Falling back to default configuration...");
                Config::default()
            }
        }
    }
}

// ===== impl Config =====

impl Default for Config {
    fn default() -> Config {
        Config {
            protocols: vec![
                Protocol::BFD,
                Protocol::LDP,
                Protocol::OSPFV2,
                Protocol::OSPFV3,
                Protocol::RIPV2,
                Protocol::RIPNG,
            ],
            user: "frr".to_owned(),
            group: "frr".to_owned(),
            logging: Default::default(),
            tokio_console: Default::default(),
            event_recorder: Default::default(),
            plugins: Default::default(),
        }
    }
}

// ===== impl LoggingJournald =====

impl Default for LoggingJournald {
    fn default() -> LoggingJournald {
        LoggingJournald { enabled: true }
    }
}

// ===== impl LoggingFile =====

impl Default for LoggingFile {
    fn default() -> LoggingFile {
        LoggingFile {
            dir: "/var/run".to_owned(),
            name: "holod.log".to_owned(),
            rotation: Default::default(),
            inner: Default::default(),
        }
    }
}

// ===== impl LoggingFmt =====

impl Default for LoggingFmt {
    fn default() -> LoggingFmt {
        LoggingFmt {
            enabled: true,
            style: LoggingFmtStyle::Full,
            colors: false,
            show_thread_id: true,
            show_source: true,
        }
    }
}

// ===== impl Grpc =====

impl Default for Grpc {
    fn default() -> Grpc {
        Grpc {
            enabled: true,
            address: "[::1]:50051".to_owned(),
        }
    }
}

// ===== impl Gnmi =====

impl Default for Gnmi {
    fn default() -> Gnmi {
        Gnmi {
            enabled: true,
            address: "[::1]:10161".to_owned(),
            tls: None,
        }
    }
}

// ===== impl GnmiTls =====

impl Default for GnmiTls {
    fn default() -> GnmiTls {
        GnmiTls {
            certificate: "/etc/tls/gnmi.pem".to_owned(),
            key: "/etc/tls/gnmi.key".to_owned(),
        }
    }
}
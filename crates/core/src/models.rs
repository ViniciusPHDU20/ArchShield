// language: Rust, file: crates/core/src/models.rs, runtime: pure-rust, target: Linux
use crate::covert::CovertAlert;
use crate::rootkit_hunter::KernelIntegrityReport;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSettings {
    pub enabled: bool,
    pub notify_rootkit: bool,
    pub notify_covert: bool,
    pub notify_honeypot: bool,
}

impl Default for NotificationSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            notify_rootkit: true,
            notify_covert: true,
            notify_honeypot: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntruderEvent {
    pub ip: String,
    pub target_port: u16,
    pub port_desc: String,
    pub proto: String,
    pub os_family: String,
    pub scanner_name: String,
    pub is_scanner: bool,
    pub confidence: String,
    pub timestamp: u64,
    pub formatted_time: String,
    pub signature: String,
    pub summary: String,
    pub is_blocked: bool,
    pub country: String,
    pub org: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub process: String,
    pub pid: Option<u32>,
    pub proto: String,
    pub local: String,
    pub remote: String,
    pub remote_ip: String,
    pub state: String,
    pub site: String,
    pub org: String,
    pub exe_path: String,
    pub sha256: String,
    pub is_suspicious: bool,
    pub risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub total_packets: u64,
    pub trapped_count: usize,
    pub blocked_count: usize,
    pub outbound_count: usize,
    pub ia_status: String,
    pub trapped_intruders: Vec<IntruderEvent>,
    pub outbound_conns: Vec<ConnectionInfo>,
    pub blocked_ips: Vec<String>,
    pub traffic_history: Vec<u64>,
    pub time_history: Vec<String>,
    pub kernel_integrity: KernelIntegrityReport,
    pub covert_alerts: Vec<CovertAlert>,
    pub notification_settings: NotificationSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", content = "payload")]
pub enum IpcCommand {
    GetStatus,
    BlockIp { ip: String },
    UnblockIp { ip: String },
    ClearTrap,
    RunKernelAudit,
    GetNotificationSettings,
    UpdateNotificationSettings { settings: NotificationSettings },
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "data")]
pub enum IpcResponse {
    Success(serde_json::Value),
    Status(SystemStatus),
    KernelAudit(KernelIntegrityReport),
    NotificationSettings(NotificationSettings),
    Ack,
    Pong,
    Error(String),
}

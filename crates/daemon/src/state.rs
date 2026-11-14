// language: Rust, file: crates/daemon/src/state.rs, runtime: tokio, target: Linux
use crate::notify::Notifier;
use archshield_core::{
    ConnectionInfo, CovertAlert, IntruderEvent, KernelIntegrityReport, NotificationSettings,
    RootkitHunter, SystemStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct PersistentData {
    pub total_packets: u64,
    pub trapped_intruders: Vec<IntruderEvent>,
    #[serde(default)]
    pub notification_settings: NotificationSettings,
}

pub struct SystemState {
    pub total_packets: AtomicU64,
    pub trapped_intruders: Vec<IntruderEvent>,
    pub ip_domain_cache: HashMap<String, String>,
    pub ip_org_cache: HashMap<String, String>,
    pub traffic_history: Vec<u64>,
    pub time_history: Vec<String>,
    pub current_second_packets: AtomicU64,
    pub covert_alerts: Vec<CovertAlert>,
    pub kernel_report: KernelIntegrityReport,
    pub notification_settings: NotificationSettings,
}

impl SystemState {
    pub fn get_persistence_path() -> PathBuf {
        let var_dir = Path::new("/var/lib/archshield");
        if var_dir.exists() || std::fs::create_dir_all(var_dir).is_ok() {
            return var_dir.join("state.json");
        }
        PathBuf::from("/tmp/archshield_state.json")
    }

    pub fn new() -> Self {
        let initial_kernel_report = RootkitHunter::audit();
        let state_path = Self::get_persistence_path();

        let mut initial_packets = 0;
        let mut initial_intruders = Vec::new();
        let mut initial_notify = NotificationSettings::default();

        if let Ok(content) = std::fs::read_to_string(&state_path) {
            if let Ok(data) = serde_json::from_str::<PersistentData>(&content) {
                initial_packets = data.total_packets;
                initial_intruders = data.trapped_intruders;
                initial_notify = data.notification_settings;
                tracing::info!(
                    "💾 [PERSISTÊNCIA] Estado recuperado de {:?}: {} pacotes acumulados, {} intrusos em histórico",
                    state_path,
                    initial_packets,
                    initial_intruders.len()
                );
            }
        }

        Notifier::sync_settings(&initial_notify);

        Self {
            total_packets: AtomicU64::new(initial_packets),
            trapped_intruders: initial_intruders,
            ip_domain_cache: HashMap::new(),
            ip_org_cache: HashMap::new(),
            traffic_history: vec![0; 20],
            time_history: vec!["--:--:--".to_string(); 20],
            current_second_packets: AtomicU64::new(0),
            covert_alerts: Vec::new(),
            kernel_report: initial_kernel_report,
            notification_settings: initial_notify,
        }
    }

    pub fn save_persistent(&self) {
        let path = Self::get_persistence_path();
        let data = PersistentData {
            total_packets: self.total_packets.load(Ordering::Relaxed),
            trapped_intruders: self.trapped_intruders.clone(),
            notification_settings: self.notification_settings.clone(),
        };

        if let Ok(json) = serde_json::to_string_pretty(&data) {
            let tmp_path = format!("{}.tmp", path.display());
            if std::fs::write(&tmp_path, json).is_ok() {
                let _ = std::fs::rename(&tmp_path, &path);
            }
        }
    }

    pub fn record_packet(&self) {
        self.total_packets.fetch_add(1, Ordering::Relaxed);
        self.current_second_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_intruder(&mut self, mut intruder: IntruderEvent) {
        if let Some(last) = self.trapped_intruders.first() {
            if last.ip == intruder.ip
                && last.target_port == intruder.target_port
                && intruder.timestamp.saturating_sub(last.timestamp) < 2
            {
                return;
            }
        }

        if intruder.org.is_empty() {
            intruder.org = self.get_org_for_ip(&intruder.ip);
        }

        self.trapped_intruders.insert(0, intruder);
        if self.trapped_intruders.len() > 500 {
            self.trapped_intruders.truncate(500);
        }
    }

    pub fn record_covert_alert(&mut self, alert: CovertAlert) {
        // Evita duplicatas consecutivas nos últimos 3 segundos
        if let Some(last) = self.covert_alerts.first() {
            if last.indicator == alert.indicator
                && alert.timestamp.saturating_sub(last.timestamp) < 3
            {
                return;
            }
        }

        self.covert_alerts.insert(0, alert);
        if self.covert_alerts.len() > 100 {
            self.covert_alerts.truncate(100);
        }
    }

    pub fn update_kernel_report(&mut self, report: KernelIntegrityReport) {
        self.kernel_report = report;
    }

    pub fn associate_ip_domain(&mut self, ip: String, domain: String) {
        if !ip.is_empty() && !domain.is_empty() {
            if self.ip_domain_cache.len() > 2000 {
                self.ip_domain_cache.clear();
            }
            self.ip_domain_cache.insert(ip, domain);
        }
    }

    pub fn associate_ip_org(&mut self, ip: String, org: String) {
        if !ip.is_empty() && !org.is_empty() {
            self.ip_org_cache.insert(ip, org);
        }
    }

    pub fn get_domain_for_ip(&self, ip: &str) -> String {
        self.ip_domain_cache.get(ip).cloned().unwrap_or_default()
    }

    pub fn get_org_for_ip(&self, ip: &str) -> String {
        if let Some(cached) = self.ip_org_cache.get(ip) {
            return cached.clone();
        }

        if ip.starts_with("2001:4860:")
            || ip.starts_with("142.250.")
            || ip.starts_with("172.217.")
            || ip.starts_with("8.8.8.")
            || ip.starts_with("8.8.4.")
            || ip.starts_with("216.58.")
            || ip.starts_with("108.177.")
        {
            return "Google LLC".to_string();
        }

        if ip.starts_with("2606:4700:")
            || ip.starts_with("104.16.")
            || ip.starts_with("104.17.")
            || ip.starts_with("104.18.")
            || ip.starts_with("104.19.")
            || ip.starts_with("104.20.")
            || ip.starts_with("104.21.")
            || ip.starts_with("1.1.1.")
            || ip.starts_with("1.0.0.")
            || ip.starts_with("172.67.")
        {
            return "Cloudflare, Inc.".to_string();
        }

        if ip.starts_with("155.133.")
            || ip.starts_with("162.254.")
            || ip.starts_with("208.78.")
            || ip.starts_with("208.64.")
        {
            return "Valve Corporation (Steam)".to_string();
        }

        if ip.starts_with("89.222.")
            || ip.starts_with("89.187.")
            || ip.starts_with("185.152.")
            || ip.starts_with("185.228.")
            || ip.starts_with("2a02:6ea0:")
        {
            return "CDN77 / DataCamp".to_string();
        }

        if ip.starts_with("2606:b740:") {
            return "Tailscale Inc.".to_string();
        }

        if ip.starts_with("151.101.") || ip.starts_with("2a04:4e42:") {
            return "Fastly CDN".to_string();
        }

        if ip.starts_with("20.")
            || ip.starts_with("40.")
            || ip.starts_with("52.")
            || ip.starts_with("13.")
            || ip.starts_with("2a01:111:")
        {
            return "Microsoft Corporation".to_string();
        }

        if ip.starts_with("3.")
            || ip.starts_with("18.")
            || ip.starts_with("34.")
            || ip.starts_with("35.")
            || ip.starts_with("44.")
            || ip.starts_with("54.")
            || ip.starts_with("2600:1f18:")
            || ip.starts_with("2600:9000:")
        {
            return "Amazon AWS".to_string();
        }

        if ip.starts_with("192.168.") || ip.starts_with("10.") || ip.starts_with("172.16.") {
            return "Gateway / Rede Local".to_string();
        }

        String::new()
    }

    pub fn clear_trapped(&mut self) {
        self.trapped_intruders.clear();
        self.covert_alerts.clear();
    }

    pub fn tick_second(&mut self) {
        let pkts = self.current_second_packets.swap(0, Ordering::Relaxed);
        let now_str = chrono_or_simple_time();

        self.traffic_history.push(pkts);
        if self.traffic_history.len() > 20 {
            self.traffic_history.remove(0);
        }

        self.time_history.push(now_str);
        if self.time_history.len() > 20 {
            self.time_history.remove(0);
        }
    }

    pub fn build_snapshot(
        &self,
        active_conns: Vec<ConnectionInfo>,
        blocked_ips: Vec<String>,
    ) -> SystemStatus {
        let total = self.total_packets.load(Ordering::Relaxed);
        let trapped_count = self.trapped_intruders.len();
        let blocked_count = blocked_ips.len();
        let outbound_count = active_conns.len();

        let ia_status = if self.kernel_report.is_clean {
            "ARMED // RING 0 VERIFIED // SOVEREIGN ENGINE ACTIVE (RUST)".to_string()
        } else {
            format!("⚠️ ALERTA DE KERNEL // {} ROOTKITS/PROCESSOS FANTASMAS DETECTADOS", self.kernel_report.hidden_lkm_modules.len() + self.kernel_report.hidden_pids.len())
        };

        SystemStatus {
            total_packets: total,
            trapped_count,
            blocked_count,
            outbound_count,
            ia_status,
            trapped_intruders: self.trapped_intruders.clone(),
            outbound_conns: active_conns,
            blocked_ips,
            traffic_history: self.traffic_history.clone(),
            time_history: self.time_history.clone(),
            kernel_integrity: self.kernel_report.clone(),
            covert_alerts: self.covert_alerts.clone(),
            notification_settings: self.notification_settings.clone(),
        }
    }

    pub fn update_notification_settings(&mut self, settings: NotificationSettings) {
        Notifier::sync_settings(&settings);
        self.notification_settings = settings;
        self.save_persistent();
    }
}

pub type SharedState = Arc<RwLock<SystemState>>;

pub fn new_shared_state() -> SharedState {
    Arc::new(RwLock::new(SystemState::new()))
}

fn chrono_or_simple_time() -> String {
    use std::time::SystemTime;
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let hours = (secs / 3600) % 24;
    let mins = (secs / 60) % 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, mins, s)
}

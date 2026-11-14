// language: Rust, file: crates/daemon/src/state.rs, runtime: tokio, target: Linux
use archshield_core::{ConnectionInfo, IntruderEvent, SystemStatus};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct SystemState {
    pub total_packets: AtomicU64,
    pub trapped_intruders: Vec<IntruderEvent>,
    pub ip_domain_cache: HashMap<String, String>,
    pub ip_org_cache: HashMap<String, String>,
    pub traffic_history: Vec<u64>,
    pub time_history: Vec<String>,
    pub current_second_packets: AtomicU64,
}

impl SystemState {
    pub fn new() -> Self {
        Self {
            total_packets: AtomicU64::new(0),
            trapped_intruders: Vec::new(),
            ip_domain_cache: HashMap::new(),
            ip_org_cache: HashMap::new(),
            traffic_history: vec![0; 20],
            time_history: vec!["--:--:--".to_string(); 20],
            current_second_packets: AtomicU64::new(0),
        }
    }

    pub fn record_packet(&self) {
        self.total_packets.fetch_add(1, Ordering::Relaxed);
        self.current_second_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_intruder(&mut self, mut intruder: IntruderEvent) {
        // Evita duplicatas consecutivas nos últimos 2 segundos do mesmo IP e porta
        if let Some(last) = self.trapped_intruders.first() {
            if last.ip == intruder.ip
                && last.target_port == intruder.target_port
                && intruder.timestamp.saturating_sub(last.timestamp) < 2
            {
                return;
            }
        }

        // Tenta enriquecer com ASN/Org do cache ou prefixo se disponível
        if intruder.org.is_empty() {
            intruder.org = self.get_org_for_ip(&intruder.ip);
        }

        self.trapped_intruders.insert(0, intruder);
        if self.trapped_intruders.len() > 500 {
            self.trapped_intruders.truncate(500);
        }
    }

    pub fn associate_ip_domain(&mut self, ip: String, domain: String) {
        if !ip.is_empty() && !domain.is_empty() {
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

        // Heurísticas instantâneas de prefixos de rede conhecidos
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

        SystemStatus {
            total_packets: total,
            trapped_count,
            blocked_count,
            outbound_count,
            ia_status: "ARMED // SOVEREIGN ENGINE ACTIVE (RUST)".to_string(),
            trapped_intruders: self.trapped_intruders.clone(),
            outbound_conns: active_conns,
            blocked_ips,
            traffic_history: self.traffic_history.clone(),
            time_history: self.time_history.clone(),
        }
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

// language: Rust, file: crates/daemon/src/notify.rs, runtime: tokio, target: Linux
use archshield_core::NotificationSettings;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::SystemTime;
use tracing::info;

static NOTIFY_ENABLED: AtomicBool = AtomicBool::new(true);
static NOTIFY_ROOTKIT: AtomicBool = AtomicBool::new(true);
static NOTIFY_COVERT: AtomicBool = AtomicBool::new(true);
static NOTIFY_HONEYPOT: AtomicBool = AtomicBool::new(true);

static LAST_INTRUSION_ALERT: AtomicU64 = AtomicU64::new(0);
static LAST_COVERT_ALERT: AtomicU64 = AtomicU64::new(0);
static LAST_ROOTKIT_ALERT: AtomicU64 = AtomicU64::new(0);

// Cooldown de 5 minutos (300s) para evitar poluição da tela e fadiga de alertas
const ALERT_COOLDOWN_SECS: u64 = 300;

pub struct Notifier;

impl Notifier {
    /// Sincroniza as preferências do usuário nos registradores atômicos em tempo real
    pub fn sync_settings(settings: &NotificationSettings) {
        NOTIFY_ENABLED.store(settings.enabled, Ordering::Relaxed);
        NOTIFY_ROOTKIT.store(settings.notify_rootkit, Ordering::Relaxed);
        NOTIFY_COVERT.store(settings.notify_covert, Ordering::Relaxed);
        NOTIFY_HONEYPOT.store(settings.notify_honeypot, Ordering::Relaxed);
        info!(
            "🔔 [NOTIFY-CONFIG] Preferências atualizadas: Geral={}, Rootkits={}, Covert={}, Honeypot={}",
            settings.enabled, settings.notify_rootkit, settings.notify_covert, settings.notify_honeypot
        );
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Alerta de Rootkit em Ring 0 (Severidade Máxima: LKMs ocultos ou processos DKOM)
    pub fn alert_rootkit(details: &str) {
        if !NOTIFY_ENABLED.load(Ordering::Relaxed) || !NOTIFY_ROOTKIT.load(Ordering::Relaxed) {
            return;
        }

        let now = Self::current_timestamp();
        let last = LAST_ROOTKIT_ALERT.load(Ordering::Relaxed);
        if now.saturating_sub(last) < ALERT_COOLDOWN_SECS {
            return;
        }
        LAST_ROOTKIT_ALERT.store(now, Ordering::Relaxed);

        let title = "💀 ArchShield PRO: Alerta Crítico de Kernel";
        Self::send_alert(title, details, "critical");
    }

    /// Alerta de Exfiltração de Dados / DNS Tunneling ou Canal Encoberto
    pub fn alert_covert(details: &str) {
        if !NOTIFY_ENABLED.load(Ordering::Relaxed) || !NOTIFY_COVERT.load(Ordering::Relaxed) {
            return;
        }

        let now = Self::current_timestamp();
        let last = LAST_COVERT_ALERT.load(Ordering::Relaxed);
        if now.saturating_sub(last) < ALERT_COOLDOWN_SECS {
            return;
        }
        LAST_COVERT_ALERT.store(now, Ordering::Relaxed);

        let title = "⚠️ ArchShield PRO: Exfiltração de Dados";
        Self::send_alert(title, details, "critical");
    }

    /// Alerta de Bloqueio Ativo (Apenas quando um atacante agressivo é ativamente isolado no Netfilter)
    pub fn alert_blocked_attacker(ip: &str, reason: &str) {
        if !NOTIFY_ENABLED.load(Ordering::Relaxed) || !NOTIFY_HONEYPOT.load(Ordering::Relaxed) {
            return;
        }

        let now = Self::current_timestamp();
        let last = LAST_INTRUSION_ALERT.load(Ordering::Relaxed);
        if now.saturating_sub(last) < ALERT_COOLDOWN_SECS {
            return;
        }
        LAST_INTRUSION_ALERT.store(now, Ordering::Relaxed);

        let title = "🛡️ ArchShield PRO: Atacante Isolado no Kernel";
        let body = format!("IP Hostil bloqueado: {}\nMotivo: {}", ip, reason);
        Self::send_alert(title, &body, "normal");
    }

    /// Despacho assíncrono para as sessões gráficas ativas
    fn send_alert(title: &str, body: &str, urgency: &str) {
        let title = title.to_string();
        let body = body.to_string();
        let urgency = urgency.to_string();

        tokio::spawn(async move {
            Self::dispatch(&title, &body, &urgency);
        });
    }

    fn dispatch(title: &str, body: &str, urgency: &str) {
        if let Ok(entries) = std::fs::read_dir("/run/user") {
            for entry in entries.flatten() {
                let path = entry.path();
                let bus_path = path.join("bus");
                if bus_path.exists() {
                    let uid_str = entry.file_name().to_string_lossy().to_string();
                    if let Ok(uid) = uid_str.parse::<u32>() {
                        if uid >= 1000 {
                            Self::dispatch_to_user(uid, &uid_str, title, body, urgency);
                        }
                    }
                }
            }
        }
    }

    fn dispatch_to_user(uid: u32, uid_str: &str, title: &str, body: &str, urgency: &str) {
        let bus_env = format!("unix:path=/run/user/{}/bus", uid_str);

        let username = unsafe {
            let pwd = libc::getpwuid(uid);
            if !pwd.is_null() && !(*pwd).pw_name.is_null() {
                std::ffi::CStr::from_ptr((*pwd).pw_name)
                    .to_string_lossy()
                    .to_string()
            } else {
                "viniciusphdu".to_string()
            }
        };

        let icon_path = "/home/viniciusphdu/.local/share/icons/archshield.svg";
        let urgency_arg = match urgency {
            "critical" => "critical",
            "low" => "low",
            _ => "normal",
        };

        let res = Command::new("sudo")
            .args(&[
                "-u", &username,
                "env", &format!("DBUS_SESSION_BUS_ADDRESS={}", bus_env),
                "notify-send",
                "-a", "ArchShield PRO",
                "-u", urgency_arg,
                "-i", icon_path,
                title,
                body,
            ])
            .output();

        if let Ok(out) = res {
            if out.status.success() {
                info!("📢 [NOTIFY-DESKTOP] Alerta visual enviado para {}: {}", username, title);
            }
        }
    }
}

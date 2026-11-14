// language: Rust, file: crates/daemon/src/notify.rs, runtime: tokio, target: Linux
use std::process::Command;
use tracing::info;

pub struct Notifier;

impl Notifier {
    /// Envia uma notificação visual nativa para todos os usuários com sessão gráfica ativa
    pub fn send_alert(title: &str, body: &str, urgency: &str) {
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

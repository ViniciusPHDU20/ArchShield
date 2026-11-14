// language: Rust, file: crates/daemon/src/config.rs, runtime: tokio, target: Linux
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub interface: String,
    pub socket_path: PathBuf,
    pub ghost_ports: Vec<u16>,
    pub allowed_ports: Vec<u16>,
    pub dry_run: bool,
}

impl DaemonConfig {
    pub fn load() -> Self {
        let interface = Self::detect_default_interface();
        
        let socket_path = match std::env::var("ARCHSHIELD_SOCKET_PATH") {
            Ok(p) => PathBuf::from(p),
            Err(_) => {
                // Tenta /run/archshield/ se existir ou tiver permissão, senão usa /tmp/archshield.sock
                let run_dir = PathBuf::from("/run/archshield");
                if run_dir.exists() || fs::create_dir_all(&run_dir).is_ok() {
                    run_dir.join("archshield.sock")
                } else {
                    PathBuf::from("/tmp/archshield.sock")
                }
            }
        };

        let dry_run = std::env::var("ARCHSHIELD_DRY_RUN")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        Self {
            interface,
            socket_path,
            ghost_ports: vec![21, 22, 23, 445, 3389, 8080],
            allowed_ports: vec![80, 443, 22, 53, 5555, 8080],
            dry_run,
        }
    }

    pub fn detect_default_interface() -> String {
        if let Ok(iface) = std::env::var("ARCHSHIELD_INTERFACE") {
            if !iface.trim().is_empty() {
                return iface.trim().to_string();
            }
        }

        if let Ok(content) = fs::read_to_string("/proc/net/route") {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && parts[1] == "00000000" {
                    return parts[0].to_string();
                }
            }
        }

        "enp6s0".to_string()
    }

    pub fn get_local_ip() -> String {
        use std::net::UdpSocket;
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
            if socket.connect("8.8.8.8:80").is_ok() {
                if let Ok(local_addr) = socket.local_addr() {
                    return local_addr.ip().to_string();
                }
            }
        }
        "127.0.0.1".to_string()
    }
}

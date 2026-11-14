use archshield_core::ConnectionInfo;
use std::process::Command;

pub struct ProcessTracker;

impl ProcessTracker {
    pub fn get_active_connections() -> Vec<ConnectionInfo> {
        let is_root = unsafe { libc::geteuid() == 0 };
        let cmd = if is_root { "ss" } else { "sudo" };
        let mut args = Vec::new();
        if !is_root {
            args.push("ss");
        }
        args.extend_from_slice(&["-tunp", "-H"]);

        let output = match Command::new(cmd).args(&args).output() {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };

        let text = match String::from_utf8(output.stdout) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };

        let mut conns = Vec::new();

        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let proto = parts[0].to_uppercase();
                let state = parts[1].to_string();
                let local = parts[4];
                let remote = if parts.len() > 5 { parts[5] } else { "*:*" };
                let proc_raw = if parts.len() > 6 { parts[6] } else { "" };

                let mut process = "Sistema / Kernel".to_string();
                let mut pid = None;

                if let Some(start) = proc_raw.find('"') {
                    if let Some(end) = proc_raw[start + 1..].find('"') {
                        process = proc_raw[start + 1..start + 1 + end].to_string();
                    }
                }

                if let Some(pid_idx) = proc_raw.find("pid=") {
                    let num_str: String = proc_raw[pid_idx + 4..]
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect();
                    if let Ok(n) = num_str.parse::<u32>() {
                        pid = Some(n);
                    }
                }

                let remote_ip = Self::extract_ip(remote);
                let is_loopback = remote_ip == "127.0.0.1" || remote_ip == "::1" || remote_ip == "*";

                if !is_loopback && !remote_ip.is_empty() {
                    conns.push(ConnectionInfo {
                        process,
                        pid,
                        proto,
                        local: local.to_string(),
                        remote: remote.to_string(),
                        remote_ip,
                        state,
                        site: String::new(),
                        org: String::new(),
                    });
                }
            }
        }

        conns
    }

    fn extract_ip(addr_str: &str) -> String {
        if addr_str.is_empty() || addr_str == "*" || addr_str == "*:*" {
            return String::new();
        }
        let clean = addr_str.split('%').next().unwrap_or(addr_str);

        // IPv6: [2001:...]:443
        if clean.starts_with('[') {
            if let Some(end_bracket) = clean.find(']') {
                return clean[1..end_bracket].to_string();
            }
        }

        // IPv4: 1.2.3.4:443
        if let Some(colon) = clean.rfind(':') {
            return clean[..colon].to_string();
        }

        clean.to_string()
    }
}

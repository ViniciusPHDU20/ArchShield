use std::process::Command;
use tracing::{info, warn, error};

pub struct FirewallManager;

impl FirewallManager {
    fn run_iptables(args: &[&str]) -> bool {
        let is_root = unsafe { libc::geteuid() == 0 };
        let cmd = if is_root { "iptables" } else { "sudo" };
        let mut actual_args = Vec::new();
        if !is_root {
            actual_args.push("iptables");
        }
        actual_args.extend_from_slice(args);

        match Command::new(cmd).args(&actual_args).output() {
            Ok(output) => output.status.success(),
            Err(e) => {
                error!("Falha ao invocar iptables: {}", e);
                false
            }
        }
    }

    pub fn block_ip(ip: &str, dry_run: bool) -> bool {
        if dry_run {
            info!("🛡️ [DRY-RUN] Simulação de bloqueio para: {}", ip);
            return true;
        }

        if Self::is_ip_blocked(ip) {
            return true;
        }

        let in_res = Self::run_iptables(&["-I", "INPUT", "-s", ip, "-j", "DROP"]);
        let out_res = Self::run_iptables(&["-I", "OUTPUT", "-d", ip, "-j", "DROP"]);

        if in_res && out_res {
            info!("💀 [SHIELD] IP bloqueado com sucesso no Netfilter: {}", ip);
            true
        } else {
            error!("❌ [FIREWALL] Falha ao bloquear IP: {}", ip);
            false
        }
    }

    pub fn unblock_ip(ip: &str) -> bool {
        let in_res = Self::run_iptables(&["-D", "INPUT", "-s", ip, "-j", "DROP"]);
        let out_res = Self::run_iptables(&["-D", "OUTPUT", "-d", ip, "-j", "DROP"]);

        if in_res || out_res {
            info!("🔓 [SHIELD] IP liberado do Netfilter: {}", ip);
            true
        } else {
            warn!("Aviso: IP não constava nas regras ativas para liberar: {}", ip);
            false
        }
    }

    pub fn is_ip_blocked(ip: &str) -> bool {
        Self::run_iptables(&["-C", "INPUT", "-s", ip, "-j", "DROP"])
    }

    pub fn get_active_blocks() -> Vec<String> {
        let is_root = unsafe { libc::geteuid() == 0 };
        let cmd = if is_root { "iptables" } else { "sudo" };
        let mut args = Vec::new();
        if !is_root {
            args.push("iptables");
        }
        args.extend_from_slice(&["-n", "-L", "INPUT"]);

        let mut blocked = Vec::new();
        if let Ok(output) = Command::new(cmd).args(&args).output() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                for line in text.lines() {
                    if line.contains("DROP") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 4 && parts[0] == "DROP" {
                            let src = parts[3];
                            if src != "0.0.0.0/0" && src != "anywhere" && !blocked.contains(&src.to_string()) {
                                blocked.push(src.to_string());
                            }
                        }
                    }
                }
            }
        }
        blocked
    }

    pub fn arm_ghost_ports(ports: &[u16]) -> bool {
        let ports_str = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
        
        let check = Self::run_iptables(&["-C", "INPUT", "-p", "tcp", "-m", "multiport", "--dports", &ports_str, "--syn", "-j", "DROP"]);
        if !check {
            let res = Self::run_iptables(&["-A", "INPUT", "-p", "tcp", "-m", "multiport", "--dports", &ports_str, "--syn", "-j", "DROP"]);
            if res {
                info!("🕸️ [TRAP] Portas fantasma armadas silenciosamente em: {}", ports_str);
                return true;
            }
        }
        true
    }
}

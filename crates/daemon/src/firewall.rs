// language: Rust, file: crates/daemon/src/firewall.rs, runtime: tokio, target: Linux
use crate::whitelist::Whitelist;
use std::process::Command;
use tracing::info;

pub struct FirewallManager;

impl FirewallManager {
    fn run_cmd(binary: &str, args: &[&str]) -> bool {
        let is_root = unsafe { libc::geteuid() == 0 };
        let cmd = if is_root { binary } else { "sudo" };
        let mut actual_args = Vec::new();
        if !is_root {
            actual_args.push(binary);
        }
        actual_args.extend_from_slice(args);

        match Command::new(cmd).args(&actual_args).output() {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    pub fn init_engine() {
        // Limpa tabela anterior para evitar duplicação de regras em reinícios
        Self::run_cmd("nft", &["delete", "table", "inet", "archshield"]);

        // Inicializa tabela atômica inet archshield no nftables com O(1) hash sets e suporte a CIDR
        Self::run_cmd("nft", &["add", "table", "inet", "archshield"]);
        Self::run_cmd("nft", &["add", "set", "inet", "archshield", "blacklist_v4", "{", "type", "ipv4_addr;", "flags", "interval;", "}"]);
        Self::run_cmd("nft", &["add", "set", "inet", "archshield", "blacklist_v6", "{", "type", "ipv6_addr;", "flags", "interval;", "}"]);
        Self::run_cmd("nft", &["add", "chain", "inet", "archshield", "input", "{", "type", "filter", "hook", "input", "priority", "-100;", "policy", "accept;", "}"]);
        Self::run_cmd("nft", &["add", "chain", "inet", "archshield", "output", "{", "type", "filter", "hook", "output", "priority", "-100;", "policy", "accept;", "}"]);

        // Regras de garantia: Tráfego legítimo, loopback e sessões ativas (conntrack established) NUNCA são bloqueados
        Self::run_cmd("nft", &["add", "rule", "inet", "archshield", "input", "iifname", "lo", "accept"]);
        Self::run_cmd("nft", &["add", "rule", "inet", "archshield", "input", "ct", "state", "established,related", "accept"]);
        Self::run_cmd("nft", &["add", "rule", "inet", "archshield", "output", "oifname", "lo", "accept"]);
        Self::run_cmd("nft", &["add", "rule", "inet", "archshield", "output", "ct", "state", "established,related", "accept"]);

        // Regras de drop para as blacklists (apenas novos fluxos de atacantes)
        Self::run_cmd("nft", &["add", "rule", "inet", "archshield", "input", "ip", "saddr", "@blacklist_v4", "drop"]);
        Self::run_cmd("nft", &["add", "rule", "inet", "archshield", "input", "ip6", "saddr", "@blacklist_v6", "drop"]);
        Self::run_cmd("nft", &["add", "rule", "inet", "archshield", "output", "ip", "daddr", "@blacklist_v4", "drop"]);
        Self::run_cmd("nft", &["add", "rule", "inet", "archshield", "output", "ip6", "daddr", "@blacklist_v6", "drop"]);

        info!("⚡ [KERNEL-NFTABLES] Tabela atômica O(1) e motor de whitelist ativados com sucesso");
    }

    pub fn block_ip(ip: &str, dry_run: bool) -> bool {
        if dry_run {
            info!("🛡️ [DRY-RUN] Simulação de bloqueio no Netfilter: {}", ip);
            return true;
        }

        if Whitelist::is_whitelisted(ip) {
            info!("🛡️ [WHITELIST] Bloqueio cancelado para IP/Subnet protegido: {}", ip);
            return false;
        }

        let is_v6 = ip.contains(':');
        let set_name = if is_v6 { "blacklist_v6" } else { "blacklist_v4" };

        // 1. Tenta inserção atômica no nftables O(1) hash set
        let nft_ok = Self::run_cmd("nft", &["add", "element", "inet", "archshield", set_name, "{", ip, "}"]);
        if nft_ok {
            info!("💀 [SHIELD-NFT] IP neutralizado via O(1) Kernel Hash Set: {}", ip);
            return true;
        }

        // 2. Fallback para iptables
        let in_res = Self::run_cmd("iptables", &["-I", "INPUT", "-s", ip, "-j", "DROP"]);
        let out_res = Self::run_cmd("iptables", &["-I", "OUTPUT", "-d", ip, "-j", "DROP"]);
        in_res && out_res
    }

    pub fn block_batch(entries: &[String], dry_run: bool) {
        if dry_run {
            info!("🛡️ [DRY-RUN] Simulação de inserção em lote de {} entradas", entries.len());
            return;
        }

        let mut v4_entries = Vec::new();
        let mut v6_entries = Vec::new();

        for e in entries {
            if Whitelist::is_whitelisted(e) {
                continue;
            }
            if e.contains(':') {
                v6_entries.push(e.as_str());
            } else {
                v4_entries.push(e.as_str());
            }
        }

        for chunk in v4_entries.chunks(100) {
            let joined = chunk.join(", ");
            let elements_arg = format!("{{ {} }}", joined);
            Self::run_cmd("nft", &["add", "element", "inet", "archshield", "blacklist_v4", &elements_arg]);
        }

        for chunk in v6_entries.chunks(100) {
            let joined = chunk.join(", ");
            let elements_arg = format!("{{ {} }}", joined);
            Self::run_cmd("nft", &["add", "element", "inet", "archshield", "blacklist_v6", &elements_arg]);
        }
    }

    pub fn unblock_ip(ip: &str) -> bool {
        let is_v6 = ip.contains(':');
        let set_name = if is_v6 { "blacklist_v6" } else { "blacklist_v4" };

        let nft_ok = Self::run_cmd("nft", &["delete", "element", "inet", "archshield", set_name, "{", ip, "}"]);
        if nft_ok {
            info!("🔓 [SHIELD-NFT] IP liberado do Kernel Hash Set: {}", ip);
            return true;
        }

        let in_res = Self::run_cmd("iptables", &["-D", "INPUT", "-s", ip, "-j", "DROP"]);
        let out_res = Self::run_cmd("iptables", &["-D", "OUTPUT", "-d", ip, "-j", "DROP"]);
        in_res || out_res
    }

    pub fn is_ip_blocked(ip: &str) -> bool {
        let is_v6 = ip.contains(':');
        let set_name = if is_v6 { "blacklist_v6" } else { "blacklist_v4" };

        let is_root = unsafe { libc::geteuid() == 0 };
        let cmd = if is_root { "nft" } else { "sudo" };
        let mut args = Vec::new();
        if !is_root {
            args.push("nft");
        }
        args.extend_from_slice(&["get", "element", "inet", "archshield", set_name, "{", ip, "}"]);

        if let Ok(output) = Command::new(cmd).args(&args).output() {
            if output.status.success() {
                return true;
            }
        }

        Self::run_cmd("iptables", &["-C", "INPUT", "-s", ip, "-j", "DROP"])
    }

    pub fn get_active_blocks() -> Vec<String> {
        let mut blocked = Vec::new();

        // 1. Coleta do nftables
        let is_root = unsafe { libc::geteuid() == 0 };
        let cmd = if is_root { "nft" } else { "sudo" };
        let mut args = Vec::new();
        if !is_root {
            args.push("nft");
        }
        args.extend_from_slice(&["list", "set", "inet", "archshield", "blacklist_v4"]);

        if let Ok(output) = Command::new(cmd).args(&args).output() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                if let Some(start) = text.find("elements = {") {
                    if let Some(end) = text[start..].find('}') {
                        let elements_str = &text[start + 12..start + end];
                        for item in elements_str.split(',') {
                            let clean = item.trim();
                            if !clean.is_empty() && !blocked.contains(&clean.to_string()) {
                                blocked.push(clean.to_string());
                            }
                        }
                    }
                }
            }
        }

        // 2. Coleta complementar do iptables se houver
        let mut ipt_args = Vec::new();
        if !is_root {
            ipt_args.push("iptables");
        }
        ipt_args.extend_from_slice(&["-n", "-L", "INPUT"]);

        let ipt_cmd = if is_root { "iptables" } else { "sudo" };
        if let Ok(output) = Command::new(ipt_cmd).args(&ipt_args).output() {
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
        let ports_str = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
        
        // 1. Registra no nftables com prioridade máxima
        let nft_res = Self::run_cmd("nft", &["add", "rule", "inet", "archshield", "input", "tcp", "dport", &format!("{{ {} }}", ports_str), "tcp", "flags", "syn", "drop"]);
        if nft_res {
            info!("🕸️ [TRAP-NFT] Portas fantasma armadas via Kernel bytecode: {}", ports_str);
            return true;
        }

        // 2. Fallback iptables
        let ports_ipt = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
        let check = Self::run_cmd("iptables", &["-C", "INPUT", "-p", "tcp", "-m", "multiport", "--dports", &ports_ipt, "--syn", "-j", "DROP"]);
        if !check {
            let res = Self::run_cmd("iptables", &["-A", "INPUT", "-p", "tcp", "-m", "multiport", "--dports", &ports_ipt, "--syn", "-j", "DROP"]);
            if res {
                info!("🕸️ [TRAP-IPT] Portas fantasma armadas silenciosamente em: {}", ports_ipt);
                return true;
            }
        }
        true
    }
}

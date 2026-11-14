use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintResult {
    pub os_family: String,
    pub scanner_name: String,
    pub is_scanner: bool,
    pub confidence: String,
    pub signature: String,
    pub summary: String,
}

pub fn describe_port(port: u16) -> &'static str {
    match port {
        21 => "FTP (Exploração de Arquivos)",
        22 => "SSH (Varredura de Força-Bruta)",
        23 => "Telnet (Scanner IoT / Legado)",
        25 => "SMTP (Relay de Spam)",
        53 => "DNS (Tentativa de Recursão/Amp)",
        80 => "HTTP (Varredura Web)",
        110 => "POP3 (Coleta de E-mails)",
        135 => "RPC / Endpoint Mapper",
        139 => "NetBIOS (Varredura de Rede)",
        443 => "HTTPS (Sonda SSL)",
        445 => "SMB / Active Directory (WannaCry Vector)",
        1433 => "MS-SQL (Injeção/Força-Bruta)",
        1521 => "Oracle DB (Sonda de Banco)",
        3306 => "MySQL (Sonda de Credenciais)",
        3389 => "RDP (Acesso Remoto Windows)",
        5432 => "PostgreSQL (Sonda de Banco)",
        5900 => "VNC (Acesso Gráfico Remoto)",
        6379 => "Redis (Tentativa de RCE não autenticado)",
        8080 => "HTTP Proxy / Web Admin",
        8443 => "HTTPS Alt / Console Admin",
        9200 => "Elasticsearch (Exfiltração de Dados)",
        27017 => "MongoDB (Varredura de Banco Sem Senha)",
        _ => "Porta Genérica / Não Catalogada",
    }
}

pub fn fingerprint_syn(ip_ttl: u8, tcp_win: u16, options: &[String], payload_len: usize) -> FingerprintResult {
    // 1. Scanners Automatizados
    if options.is_empty() && tcp_win == 1024 {
        return FingerprintResult {
            os_family: "Scanner Automatizado".into(),
            scanner_name: "Masscan".into(),
            is_scanner: true,
            confidence: "Alta (95%)".into(),
            signature: format!("WIN:{}|OPT:NONE|TTL:{}", tcp_win, ip_ttl),
            summary: "Varredura ultrarrápida Masscan detectada".into(),
        };
    }

    if matches!(tcp_win, 1024 | 2048 | 3072 | 4096) && (options.len() <= 2 || options == ["MSS"]) {
        return FingerprintResult {
            os_family: "Scanner Automatizado".into(),
            scanner_name: "Nmap Stealth Scanner".into(),
            is_scanner: true,
            confidence: "Alta (90%)".into(),
            signature: format!("WIN:{}|OPT:{}|TTL:{}", tcp_win, options.join(","), ip_ttl),
            summary: "Varredura ativa Nmap SYN Stealth detectada".into(),
        };
    }

    if (tcp_win == 65535 || tcp_win == 54272) && options.is_empty() {
        return FingerprintResult {
            os_family: "Scanner Automatizado".into(),
            scanner_name: "ZMap Network Scanner".into(),
            is_scanner: true,
            confidence: "Média (85%)".into(),
            signature: format!("WIN:{}|OPT:NONE|TTL:{}", tcp_win, ip_ttl),
            summary: "Varredura global ZMap detectada".into(),
        };
    }

    // 2. Heurística de Sistemas Operacionais
    // Windows (TTL base 128)
    if ip_ttl > 64 && ip_ttl <= 128 {
        let confidence = if matches!(tcp_win, 8192 | 64240 | 65535 | 17520) {
            "Muito Alta (95%)"
        } else {
            "Alta (85%)"
        };
        return FingerprintResult {
            os_family: "Windows (10 / 11 / Server)".into(),
            scanner_name: "Nenhum (Cliente Interativo)".into(),
            is_scanner: false,
            confidence: confidence.into(),
            signature: format!("WIN:{}|OPTS:{}|TTL:{}", tcp_win, options.join(","), ip_ttl),
            summary: format!("Windows via TCP Window {}", tcp_win),
        };
    }

    // Linux / Android (TTL base 64)
    if ip_ttl > 32 && ip_ttl <= 64 {
        let has_ts = options.iter().any(|o| o == "Timestamp");
        let has_sack = options.iter().any(|o| o == "SAckOK" || o == "SAck");
        let (os_name, confidence) = if has_ts && has_sack {
            ("Linux Kernel 4.x - 6.x (Ubuntu/Debian/Arch)", "Muito Alta (95%)")
        } else {
            ("Linux Kernel (Moderno) / Android", "Alta (85%)")
        };
        return FingerprintResult {
            os_family: os_name.into(),
            scanner_name: "Nenhum (Host Linux)".into(),
            is_scanner: false,
            confidence: confidence.into(),
            signature: format!("WIN:{}|OPTS:{}|TTL:{}", tcp_win, options.join(","), ip_ttl),
            summary: format!("{} via TCP Stack nativo", os_name),
        };
    }

    // Apple Darwin / BSD
    if ip_ttl <= 64 && tcp_win == 65535 && options.iter().any(|o| o == "WScale") {
        return FingerprintResult {
            os_family: "Apple (macOS / iOS) ou BSD".into(),
            scanner_name: "Nenhum (Cliente Apple/BSD)".into(),
            is_scanner: false,
            confidence: "Alta (85%)".into(),
            signature: format!("WIN:{}|OPTS:{}|TTL:{}", tcp_win, options.join(","), ip_ttl),
            summary: "Apple Darwin / BSD TCP Stack".into(),
        };
    }

    // Equipamentos de Rede (TTL base 255)
    if ip_ttl > 128 {
        return FingerprintResult {
            os_family: "Equipamento de Rede / Roteador / Solaris".into(),
            scanner_name: "Sonda / Dispositivo de Infra".into(),
            is_scanner: false,
            confidence: "Média (70%)".into(),
            signature: format!("WIN:{}|TTL:{}", tcp_win, ip_ttl),
            summary: format!("Dispositivo de Rede com TTL base 255 (TTL:{})", ip_ttl),
        };
    }

    // Desconhecido
    FingerprintResult {
        os_family: "Desconhecido / Sonda Sintética".into(),
        scanner_name: "Assinatura Customizada".into(),
        is_scanner: payload_len == 0,
        confidence: "Baixa (50%)".into(),
        signature: format!("WIN:{}|TTL:{}|OPTS:{}", tcp_win, ip_ttl, options.join(",")),
        summary: format!("Tráfego não padrão (TTL:{}, Win:{})", ip_ttl, tcp_win),
    }
}

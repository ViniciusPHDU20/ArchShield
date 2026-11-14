// language: Rust, file: crates/core/src/covert.rs, runtime: pure-rust, target: Linux
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CovertAlert {
    pub channel_type: String,
    pub indicator: String,
    pub entropy: f32,
    pub confidence: String,
    pub timestamp: u64,
    pub formatted_time: String,
    pub summary: String,
}

/// Calcula a Entropia de Shannon (H) de uma cadeia de texto
/// Entropia alta (> 3.85 em rótulos longos) indica dados criptografados ou codificados (Base64/Base32/Hex)
pub fn shannon_entropy(data: &str) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = HashMap::new();
    let mut total = 0.0;

    for ch in data.chars() {
        *freq.entry(ch).or_insert(0.0) += 1.0;
        total += 1.0;
    }

    let mut entropy = 0.0f32;
    for &count in freq.values() {
        let p = (count / total) as f32;
        entropy -= p * p.log2();
    }

    entropy
}

/// Analisador de consultas DNS para detecção de DNS Tunneling (Iodine, DNScat2, Cobalt Strike DNS)
pub fn analyze_dns_query(qname: &str) -> Option<CovertAlert> {
    let clean = qname.trim().trim_end_matches('.');
    let parts: Vec<&str> = clean.split('.').collect();

    if parts.len() < 2 {
        return None;
    }

    let subdomain = parts[0];
    let len = subdomain.len();

    // Heurística de DNS Tunneling: rótulo primário com mais de 24 caracteres e entropia alta
    if len >= 24 {
        let entropy = shannon_entropy(subdomain);
        if entropy >= 3.80 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let hours = (now / 3600) % 24;
            let mins = (now / 60) % 60;
            let secs = now % 60;
            let formatted_time = format!("{:02}:{:02}:{:02}", hours, mins, secs);

            return Some(CovertAlert {
                channel_type: "DNS Tunneling (Exfiltração Furtiva)".to_string(),
                indicator: clean.to_string(),
                entropy,
                confidence: if entropy > 4.1 { "Crítica (98%)".into() } else { "Alta (90%)".into() },
                timestamp: now,
                formatted_time,
                summary: format!("Subdomínio de alta entropia ({:.2}) e tamanho {} bytes detectado", entropy, len),
            });
        }
    }

    None
}

/// Analisador de payloads ICMP (Ping) para detecção de tunelamento e canais encobertos
pub fn analyze_icmp_payload(payload: &[u8], src: &str, dst: &str) -> Option<CovertAlert> {
    // Ping normal do Linux usa tipicamente 56 bytes de payload com timestamp e padrão ASCII
    if payload.len() > 64 {
        let entropy = {
            let mut freq = [0usize; 256];
            for &b in payload {
                freq[b as usize] += 1;
            }
            let total = payload.len() as f32;
            let mut ent = 0.0;
            for &count in &freq {
                if count > 0 {
                    let p = count as f32 / total;
                    ent -= p * p.log2();
                }
            }
            ent
        };

        if entropy > 4.0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let hours = (now / 3600) % 24;
            let mins = (now / 60) % 60;
            let secs = now % 60;
            let formatted_time = format!("{:02}:{:02}:{:02}", hours, mins, secs);

            return Some(CovertAlert {
                channel_type: "ICMP Tunneling / Exfiltração via Ping".to_string(),
                indicator: format!("{} -> {}", src, dst),
                entropy,
                confidence: "Alta (92%)".to_string(),
                timestamp: now,
                formatted_time,
                summary: format!("Payload ICMP anômalo de {} bytes com alta entropia ({:.2})", payload.len(), entropy),
            });
        }
    }

    None
}

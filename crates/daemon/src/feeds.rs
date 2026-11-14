// language: Rust, file: crates/daemon/src/feeds.rs, runtime: tokio, target: Linux
use crate::firewall::FirewallManager;
use crate::whitelist::Whitelist;
use std::process::Command;
use std::time::Duration;
use tracing::{info, warn};

pub struct ThreatFeeds;

impl ThreatFeeds {
    /// Inicia o atualizador periódico de feeds de inteligência de ameaças em background
    pub async fn start(dry_run: bool) {
        tokio::spawn(async move {
            // Aguarda 8 segundos após a subida do daemon para assegurar rota de internet estável
            tokio::time::sleep(Duration::from_secs(8)).await;

            let mut interval = tokio::time::interval(Duration::from_secs(43200)); // 12 horas
            loop {
                interval.tick().await;
                info!("🌐 [THREAT-INTEL] Verificando feeds globais de elite (Spamhaus DROP, Abuse.ch Feodo & Tor Exit Nodes)...");
                Self::sync_feeds(dry_run);
            }
        });
    }

    fn download_feed(url: &str) -> Option<String> {
        let output = Command::new("curl")
            .args(&[
                "-s",
                "--max-time", "10",
                "--connect-timeout", "5",
                url,
            ])
            .output()
            .ok()?;

        if output.status.success() {
            String::from_utf8(output.stdout).ok()
        } else {
            None
        }
    }

    pub fn sync_feeds(dry_run: bool) {
        let mut valid_entries = Vec::new();

        // 1. Abuse.ch Feodo Tracker (Botnet C2 IP Blocklist com garantia zero falso positivo)
        if let Some(content) = Self::download_feed("https://feodotracker.abuse.ch/downloads/ipblocklist.txt") {
            let mut count = 0;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if !Whitelist::is_whitelisted(trimmed) {
                    valid_entries.push(trimmed.to_string());
                    count += 1;
                }
            }
            info!("📥 [THREAT-INTEL] Feed Abuse.ch carregado: {} C2s maliciosos", count);
        } else {
            warn!("⚠️ [THREAT-INTEL] Falha temporária ao baixar Abuse.ch (mantendo regras atuais)");
        }

        // 2. Spamhaus DROP (Hijacked Cybercrime Subnets)
        if let Some(content) = Self::download_feed("https://www.spamhaus.org/drop/drop.txt") {
            let mut count = 0;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with(';') {
                    continue;
                }
                let cidr = trimmed.split(';').next().unwrap_or(trimmed).trim();
                if !cidr.is_empty() && !Whitelist::is_whitelisted(cidr) {
                    valid_entries.push(cidr.to_string());
                    count += 1;
                }
            }
            info!("📥 [THREAT-INTEL] Feed Spamhaus DROP carregado: {} sub-redes hostis", count);
        } else {
            warn!("⚠️ [THREAT-INTEL] Falha temporária ao baixar Spamhaus DROP");
        }

        // 3. Tor Bulk Exit List (Nós de Saída Anônimos Oficiais do Tor Project)
        if let Some(content) = Self::download_feed("https://check.torproject.org/torbulkexitlist") {
            let mut count = 0;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if !Whitelist::is_whitelisted(trimmed) {
                    valid_entries.push(trimmed.to_string());
                    count += 1;
                }
            }
            info!("📥 [THREAT-INTEL] Feed Tor Exit Nodes carregado: {} nós anônimos", count);
        } else {
            warn!("⚠️ [THREAT-INTEL] Falha temporária ao baixar Tor Exit Nodes");
        }

        if !valid_entries.is_empty() {
            info!(
                "🛡️ [THREAT-INTEL] Injetando {} ameaças no Netfilter (Proteção Atômica O(1))...",
                valid_entries.len()
            );
            FirewallManager::block_batch(&valid_entries, dry_run);
            info!("✅ [THREAT-INTEL] Atualização concluída. Conexões legítimas protegidas via Whitelist e Conntrack.");
        }
    }
}

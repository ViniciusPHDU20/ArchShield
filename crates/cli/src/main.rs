// language: Rust, file: crates/cli/src/main.rs, runtime: tokio, target: Linux
use archshield_core::{IpcCommand, IpcResponse, SystemStatus, DEFAULT_SOCKET_PATH};
use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

fn get_socket_path() -> PathBuf {
    if let Ok(p) = env::var("ARCHSHIELD_SOCKET_PATH") {
        return PathBuf::from(p);
    }
    let default_path = Path::new(DEFAULT_SOCKET_PATH);
    if default_path.exists() {
        return default_path.to_path_buf();
    }
    PathBuf::from("/tmp/archshield.sock")
}

async fn send_command(cmd: &IpcCommand) -> Result<IpcResponse, Box<dyn std::error::Error>> {
    let socket_path = get_socket_path();
    let stream = match UnixStream::connect(&socket_path).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("\x1b[1;31m❌ Erro ao conectar ao Daemon ArchShield em {:?}\x1b[0m", socket_path);
            eprintln!("   Verifique se o daemon está rodando: 'sudo archshield-daemon' ou 'sudo systemctl start archshield'");
            return Err(Box::new(e));
        }
    };

    let (reader, mut writer) = stream.into_split();
    let mut json_cmd = serde_json::to_string(cmd)?;
    json_cmd.push('\n');
    writer.write_all(json_cmd.as_bytes()).await?;

    let mut lines = BufReader::new(reader).lines();
    if let Some(line) = lines.next_line().await? {
        let res: IpcResponse = serde_json::from_str(&line)?;
        Ok(res)
    } else {
        Err("Resposta vazia do daemon".into())
    }
}

fn print_banner() {
    println!("\x1b[1;36m");
    println!(r#"
  █████╗ ██████╗  ██████╗██╗  ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
 ██╔══██╗██╔══██╗██╔════╝██║  ██║██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
 ███████║██████╔╝██║     ███████║███████╗███████║██║█████╗  ██║     ██║  ██║
 ██╔══██║██╔══██╗██║     ██╔══██║╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
 ██║  ██║██║  ██║╚██████╗██║  ██║███████║██║  ██║██║███████╗███████╗██████╔╝
 ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 
        -- SOVEREIGN INTELLIGENCE & RING-0 SENTRY (0-PORT UNIX IPC) --
    "#);
    println!("\x1b[0m");
}

fn render_status(status: &SystemStatus) {
    println!("\x1b[1;32m══════════════════════════════════════════════════════════════════════════════\x1b[0m");
    println!(" 🛡️  \x1b[1;37mESTADO DO SISTEMA:\x1b[0m \x1b[1;32m{}\x1b[0m", status.ia_status);
    println!(" 📦 \x1b[1;33mPacotes Analisados:\x1b[0m {}  |  🕸️  \x1b[1;31mArmadilha Capturados:\x1b[0m {}  |  💀 \x1b[1;31mBloqueados:\x1b[0m {}", 
        status.total_packets, status.trapped_count, status.blocked_count);
    println!(" 🌐 \x1b[1;36mConexões Ativas Outbound:\x1b[0m {}  |  🔬 \x1b[1;35mIntegridade Ring 0:\x1b[0m {}", 
        status.outbound_count, if status.kernel_integrity.is_clean { "\x1b[1;32m✓ LIMPO\x1b[0m" } else { "\x1b[1;31m⚠️ COMPROMISSO\x1b[0m" });
    println!("\x1b[1;32m══════════════════════════════════════════════════════════════════════════════\x1b[0m\n");

    // ALERTA DE KERNEL ROOTKIT SE HOUVER
    if !status.kernel_integrity.is_clean {
        println!("\x1b[1;41;37m ⚠️ ALERTA DE ANOMALIA EM RING 0 // KERNEL COMPROMISE DETECTED: \x1b[0m");
        for m in &status.kernel_integrity.hidden_lkm_modules {
            println!("   \x1b[1;31m[LKM ROOTKIT OCULTO]:\x1b[0m Módulo '{}' desvinculado de /proc/modules!", m);
        }
        for p in &status.kernel_integrity.hidden_pids {
            println!("   \x1b[1;31m[PROCESSO FANTASMA (DKOM)]:\x1b[0m PID {} oculto do VFS /proc!", p);
        }
        println!();
    }

    // CANAIS ENCOBERTOS (COVERT CHANNELS)
    if !status.covert_alerts.is_empty() {
        println!("\x1b[1;33m🕵️ CANAIS ENCOBERTOS & EXFILTRAÇÃO FURTIVA DETECTADOS:\x1b[0m");
        for c in status.covert_alerts.iter().take(4) {
            println!("   [{}] \x1b[1;33m{}\x1b[0m | Alvo: \x1b[1;37m{}\x1b[0m | Entropia: {:.2} ({})",
                c.formatted_time, c.channel_type, c.indicator, c.entropy, c.confidence);
        }
        println!();
    }

    println!("\x1b[1;31m🚨 ÚLTIMOS INTRUSOS CAPTURADOS NA ARMADILHA (SILENT BLACKHOLE):\x1b[0m");
    if status.trapped_intruders.is_empty() {
        println!("   \x1b[2mNenhum intruso detectado recentemente na armadilha.\x1b[0m");
    } else {
        for (i, intr) in status.trapped_intruders.iter().take(5).enumerate() {
            let block_tag = if intr.is_blocked { "\x1b[1;31m[BLOQUEADO]\x1b[0m" } else { "\x1b[1;33m[MONITORANDO]\x1b[0m" };
            println!("   \x1b[1;37m#{}\x1b[0m [{}] \x1b[1;31m{}\x1b[0m -> Porta {} [{}] | SO: {} | Scanner: {} {}",
                i + 1, intr.formatted_time, intr.ip, intr.target_port, intr.port_desc, intr.os_family, intr.scanner_name, block_tag);
        }
    }

    println!("\n\x1b[1;36m📡 TELEMETRIA DE CONEXÕES ATIVAS (PROCESSO / INTEGRIDADE SHA-256 / SITE / DESTINO):\x1b[0m");
    if status.outbound_conns.is_empty() {
        println!("   \x1b[2mNenhuma conexão externa ativa no momento.\x1b[0m");
    } else {
        println!("   {:<18} {:<7} {:<20} {:<24} {:<18} {:<12}", "PROCESSO", "PID", "INTEGRIDADE / HASH", "SITE / DOMÍNIO", "IP DESTINO", "STATUS");
        println!("   {:-<18} {:-<7} {:-<20} {:-<24} {:-<18} {:-<12}", "", "", "", "", "", "");
        for conn in status.outbound_conns.iter().take(20) {
            let pid_str = conn.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
            let site_display = if conn.site.is_empty() {
                if !conn.org.is_empty() {
                    format!("[{}]", conn.org)
                } else {
                    "-".to_string()
                }
            } else {
                format!("🔗 {}", conn.site)
            };

            let hash_trunc = if conn.sha256.len() > 14 {
                format!("{}...", &conn.sha256[..14])
            } else {
                conn.sha256.clone()
            };

            let status_tag = if conn.is_suspicious {
                format!("\x1b[1;31m⚠️ ALERTA ({})\x1b[0m", conn.risk_score)
            } else {
                "\x1b[1;32m✓ LIMPO\x1b[0m".to_string()
            };

            println!("   \x1b[1;37m{:<18}\x1b[0m {:<7} \x1b[2m{:<20}\x1b[0m \x1b[1;32m{:<24}\x1b[0m {:<18} {}",
                conn.process, pid_str, hash_trunc, site_display, conn.remote_ip, status_tag);
        }
    }
    println!();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let action = if args.len() > 1 { args[1].as_str() } else { "status" };

    match action {
        "status" => {
            print_banner();
            match send_command(&IpcCommand::GetStatus).await? {
                IpcResponse::Status(s) => render_status(&s),
                other => println!("{:?}", other),
            }
        }
        "audit" => {
            print_banner();
            println!("\x1b[1;35m🔬 EXECUTANDO AUDITORIA PROFUNDA DE RING 0 & ROOTKITS DE KERNEL...\x1b[0m\n");
            match send_command(&IpcCommand::RunKernelAudit).await? {
                IpcResponse::KernelAudit(report) => {
                    println!(" Timestamp da Auditoria: {}", report.formatted_time);
                    println!(" Diagnóstico: \x1b[1;32m{}\x1b[0m\n", report.summary);
                    if report.is_clean {
                        println!(" \x1b[1;32m[✓]\x1b[0m Nenhum Loadable Kernel Module (LKM) desvinculado ou oculto.");
                        println!(" \x1b[1;32m[✓]\x1b[0m Nenhum processo fantasma evadindo o VFS /proc (Zero DKOM).");
                        println!(" \x1b[1;32m[✓]\x1b[0m Tabela de processos e módulos sincronizados com o escalonador do kernel.");
                    } else {
                        for m in &report.hidden_lkm_modules {
                            println!(" \x1b[1;31m[!]\x1b[0m Módulo de Kernel Oculto Detectado: {}", m);
                        }
                        for p in &report.hidden_pids {
                            println!(" \x1b[1;31m[!]\x1b[0m PID Fantasma Oculto via DKOM: {}", p);
                        }
                    }
                }
                other => println!("{:?}", other),
            }
        }
        "watch" => {
            loop {
                print!("\x1b[2J\x1b[1;1H");
                print_banner();
                match send_command(&IpcCommand::GetStatus).await {
                    Ok(IpcResponse::Status(s)) => render_status(&s),
                    Ok(other) => println!("{:?}", other),
                    Err(_) => break,
                }
                tokio::time::sleep(Duration::from_millis(800)).await;
            }
        }
        "json" => {
            match send_command(&IpcCommand::GetStatus).await? {
                IpcResponse::Status(s) => {
                    println!("{}", serde_json::to_string_pretty(&s)?);
                }
                other => println!("{}", serde_json::to_string(&other)?),
            }
        }
        "block" => {
            if args.len() < 3 {
                eprintln!("Uso: archshield-ctl block <IP>");
                return Ok(());
            }
            let ip = args[2].clone();
            match send_command(&IpcCommand::BlockIp { ip: ip.clone() }).await? {
                IpcResponse::Ack => println!("\x1b[1;32m✅ IP {} bloqueado com sucesso no Netfilter O(1) Set!\x1b[0m", ip),
                IpcResponse::Error(e) => eprintln!("\x1b[1;31m❌ Falha ao bloquear {}: {}\x1b[0m", ip, e),
                other => println!("{:?}", other),
            }
        }
        "unblock" => {
            if args.len() < 3 {
                eprintln!("Uso: archshield-ctl unblock <IP>");
                return Ok(());
            }
            let ip = args[2].clone();
            match send_command(&IpcCommand::UnblockIp { ip: ip.clone() }).await? {
                IpcResponse::Ack => println!("\x1b[1;32m🔓 IP {} desarmado e liberado do Netfilter!\x1b[0m", ip),
                IpcResponse::Error(e) => eprintln!("\x1b[1;31m❌ Falha ao liberar {}: {}\x1b[0m", ip, e),
                other => println!("{:?}", other),
            }
        }
        "clear" => {
            match send_command(&IpcCommand::ClearTrap).await? {
                IpcResponse::Ack => println!("\x1b[1;32m🧹 Histórico de armadilha e canais encobertos limpo!\x1b[0m"),
                other => println!("{:?}", other),
            }
        }
        "ping" => {
            match send_command(&IpcCommand::Ping).await? {
                IpcResponse::Pong => println!("\x1b[1;32m🏓 PONG - Daemon ArchShield online e responsivo!\x1b[0m"),
                other => println!("{:?}", other),
            }
        }
        "notify" => {
            if args.len() == 2 || args[2] == "status" {
                match send_command(&IpcCommand::GetNotificationSettings).await? {
                    IpcResponse::NotificationSettings(cfg) => {
                        println!("\x1b[1;36m🔔 PREFERÊNCIAS DE NOTIFICAÇÃO NATIVA (DESKTOP):\x1b[0m");
                        println!("   Notificações Globais: {}", if cfg.enabled { "\x1b[1;32mATIVADO\x1b[0m" } else { "\x1b[1;31mDESATIVADO\x1b[0m" });
                        println!("   Alertas de Ring 0 (Rootkits/DKOM): {}", if cfg.notify_rootkit { "\x1b[1;32mATIVADO\x1b[0m" } else { "\x1b[1;31mDESATIVADO\x1b[0m" });
                        println!("   Canais Encobertos (DNS Tunneling): {}", if cfg.notify_covert { "\x1b[1;32mATIVADO\x1b[0m" } else { "\x1b[1;31mDESATIVADO\x1b[0m" });
                        println!("   Intrusos Isolados na Armadilha: {}", if cfg.notify_honeypot { "\x1b[1;32mATIVADO\x1b[0m" } else { "\x1b[1;31mDESATIVADO\x1b[0m" });
                    }
                    other => println!("{:?}", other),
                }
            } else if args[2] == "on" || args[2] == "off" {
                let enabled = args[2] == "on";
                let mut settings = match send_command(&IpcCommand::GetNotificationSettings).await? {
                    IpcResponse::NotificationSettings(cfg) => cfg,
                    _ => archshield_core::NotificationSettings::default(),
                };
                settings.enabled = enabled;
                match send_command(&IpcCommand::UpdateNotificationSettings { settings }).await? {
                    IpcResponse::Ack => println!("\x1b[1;32m🔔 Notificações desktop {}\x1b[0m", if enabled { "ativadas com sucesso!" } else { "completamente silenciadas!" }),
                    other => println!("{:?}", other),
                }
            } else {
                eprintln!("Uso: archshield-ctl notify [status|on|off]");
            }
        }
        _ => {
            eprintln!("Uso: archshield-ctl [status|watch|audit|json|block <ip>|unblock <ip>|clear|notify [status|on|off]|ping]");
        }
    }

    Ok(())
}

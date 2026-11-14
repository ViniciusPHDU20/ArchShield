// language: Rust, file: crates/daemon/src/main.rs, runtime: tokio, target: Linux
mod config;
mod conntrack;
mod dns;
mod feeds;
mod firewall;
mod ipc;
mod notify;
mod sniffer;
mod sni;
mod state;
mod whitelist;

use config::DaemonConfig;
use dns::DnsSniffer;
use feeds::ThreatFeeds;
use firewall::FirewallManager;
use notify::Notifier;
use ipc::IpcServer;
use sniffer::PacketSniffer;
use state::new_shared_state;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Inicializa subsistema de logs de alta performance
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_level(true)
        .init();

    println!("\x1b[1;36m");
    println!(r#"
   █████╗ ██████╗  ██████╗██╗  ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
  ██╔══██╗██╔══██╗██╔════╝██║  ██║██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
  ███████║██████╔╝██║     ███████║███████╗███████║██║█████╗  ██║     ██║  ██║
  ██╔══██║██╔══██╗██║     ██╔══██║╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
  ██║  ██║██║  ██║╚██████╗██║  ██║███████║██║  ██║██║███████╗███████╗██████╔╝
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 
             -- SOVEREIGN LOW-LEVEL DECEPTION DAEMON (RUST 2.1) --
             -- 0 PORTAS LOCAIS // COMUNICAÇÃO VIA UNIX SOCKET  --
    "#);
    println!("\x1b[0m");

    let is_root = unsafe { libc::geteuid() == 0 };
    if !is_root {
        println!("\x1b[1;33m⚠️ AVISO: Daemon rodando sem UID 0 (root). Modos de firewall e captura bruta podem exigir privilégios.\x1b[0m");
    }

    let config = DaemonConfig::load();
    info!("🔧 Interface padrão identificada: \x1b[1;32m{}\x1b[0m", config.interface);
    info!("🔌 Socket IPC Zero-Portas: \x1b[1;32m{:?}\x1b[0m", config.socket_path);

    // Inicializa o motor de firewall O(1) nftables com sets atômicos
    FirewallManager::init_engine();

    // Arma as portas de decepção cibernética (Blackhole Trap)
    FirewallManager::arm_ghost_ports(&config.ghost_ports);

    let state = new_shared_state();

    // Sincroniza IPs intrusos recuperados da persistência na blacklist nftables
    {
        let st = state.read().await;
        if !st.trapped_intruders.is_empty() {
            info!(
                "🛡️ [NETFILTER-SYNC] Re-armando blacklist no kernel para {} IPs bloqueados anteriormente",
                st.trapped_intruders.len()
            );
            for intruder in &st.trapped_intruders {
                FirewallManager::block_ip(&intruder.ip, config.dry_run);
            }
        }
    }

    // 1. Inicia o servidor IPC via UNIX Domain Socket (0 portas de rede abertas)
    let socket_path = config.socket_path.clone();
    let ipc_state = Arc::clone(&state);
    tokio::spawn(async move {
        IpcServer::start(socket_path, ipc_state).await;
    });

    // 2. Inicia o sniffer de telemetria DNS local na interface 'lo'
    DnsSniffer::start(Arc::clone(&state)).await;

    // 3. Inicia o motor de captura de pacotes raw e armadilha na interface principal
    PacketSniffer::start(config.clone(), Arc::clone(&state)).await;

    // 4. Timer de histórico de tráfego por segundo
    let ticker_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            ticker_state.write().await.tick_second();
        }
    });

    // 5. Sentinela de Ring 0: Auditoria Periódica de Integridade do Kernel & Rootkits (a cada 10s)
    let audit_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut audit_interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            audit_interval.tick().await;
            let report = archshield_core::RootkitHunter::audit();
            if !report.hidden_lkm_modules.is_empty() || !report.hidden_pids.is_empty() {
                let msg = format!(
                    "Atenção: Anomalia no Kernel detectada!\nMódulos LKM Ocultos: {}\nProcessos Fantasmas DKOM: {}",
                    report.hidden_lkm_modules.len(),
                    report.hidden_pids.len()
                );
                Notifier::send_alert("💀 ArchShield PRO: Alerta de Rootkit", &msg, "critical");
            }
            audit_state.write().await.update_kernel_report(report);
        }
    });

    // 6. Motor de Persistência em Disco: Salva contadores e histórico a cada 10s
    let persist_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut persist_interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            persist_interval.tick().await;
            persist_state.read().await.save_persistent();
        }
    });

    // 7. Sincronizador de Inteligência de Ameaças Globais (Spamhaus DROP & Abuse.ch)
    ThreatFeeds::start(config.dry_run).await;

    info!("🚀 [DAEMON-ONLINE] ArchShield Sovereign Daemon operacional com sucesso!");

    // Aguarda sinal de terminação (Ctrl+C ou SIGTERM do systemd/reboot)
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("🛑 Sinal SIGINT (Ctrl+C) detectado. Salvando estado atômico...");
        }
        _ = sigterm.recv() => {
            info!("🛑 Sinal SIGTERM (Systemd/Reboot) detectado. Salvando estado atômico...");
        }
    }

    // Flush final de persistência
    state.read().await.save_persistent();
    info!("💾 [PERSISTÊNCIA] Contadores e histórico salvos em disco com sucesso.");

    // Remove o socket local ao sair
    if config.socket_path.exists() {
        let _ = std::fs::remove_file(&config.socket_path);
    }

    info!("👋 Daemon finalizado com segurança.");
    Ok(())
}

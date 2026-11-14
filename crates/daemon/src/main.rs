// language: Rust, file: crates/daemon/src/main.rs, runtime: tokio, target: Linux
mod config;
mod conntrack;
mod dns;
mod firewall;
mod ipc;
mod sniffer;
mod sni;
mod state;

use config::DaemonConfig;
use dns::DnsSniffer;
use firewall::FirewallManager;
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

    // Arma as portas de decepção cibernética (Blackhole Trap)
    FirewallManager::arm_ghost_ports(&config.ghost_ports);

    let state = new_shared_state();

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

    info!("🚀 [DAEMON-ONLINE] ArchShield Sovereign Daemon operacional com sucesso!");

    // Aguarda sinal de terminação (Ctrl+C ou SIGTERM)
    tokio::signal::ctrl_c().await?;
    info!("🛑 Sinal de encerramento detectado. Desarmando componentes...");

    // Remove o socket local ao sair
    if config.socket_path.exists() {
        let _ = std::fs::remove_file(&config.socket_path);
    }

    info!("👋 Daemon finalizado com segurança.");
    Ok(())
}

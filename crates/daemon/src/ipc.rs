// language: Rust, file: crates/daemon/src/ipc.rs, runtime: tokio, target: Linux
use crate::conntrack::ProcessTracker;
use crate::firewall::FirewallManager;
use crate::state::SharedState;
use archshield_core::{IpcCommand, IpcResponse};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info, warn};

pub struct IpcServer;

impl IpcServer {
    pub async fn start<P: AsRef<Path>>(socket_path: P, state: SharedState) {
        let path = socket_path.as_ref();
        if path.exists() {
            let _ = fs::remove_file(path);
        }

        if let Some(parent) = path.parent() {
            if !parent.exists() {
                let _ = fs::create_dir_all(parent);
            }
        }

        let listener = match UnixListener::bind(path) {
            Ok(l) => l,
            Err(e) => {
                error!("❌ Falha ao vincular Unix Socket em {:?}: {}", path, e);
                return;
            }
        };

        // Torna o socket legível/gravável pelo usuário local para acesso sem sudo na UI
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o666));

        info!("🔌 [0-PORT-IPC] Servidor de comunicação Unix Domain Socket ativo em: {:?}", path);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let state = state.clone();
                    tokio::spawn(async move {
                        Self::handle_client(stream, state).await;
                    });
                }
                Err(e) => {
                    warn!("Aviso de conexão IPC: {}", e);
                }
            }
        }
    }

    async fn handle_client(stream: UnixStream, state: SharedState) {
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim().is_empty() {
                continue;
            }

            let response = match serde_json::from_str::<IpcCommand>(&line) {
                Ok(cmd) => Self::execute_command(cmd, &state).await,
                Err(e) => IpcResponse::Error(format!("Comando JSON inválido: {}", e)),
            };

            if let Ok(mut json_res) = serde_json::to_string(&response) {
                json_res.push('\n');
                if writer.write_all(json_res.as_bytes()).await.is_err() {
                    break;
                }
            }
        }
    }

    async fn execute_command(cmd: IpcCommand, state: &SharedState) -> IpcResponse {
        match cmd {
            IpcCommand::Ping => IpcResponse::Pong,
            IpcCommand::ClearTrap => {
                state.write().await.clear_trapped();
                IpcResponse::Ack
            }
            IpcCommand::BlockIp { ip } => {
                let success = FirewallManager::block_ip(&ip, false);
                if success {
                    IpcResponse::Ack
                } else {
                    IpcResponse::Error(format!("Falha ao bloquear IP {}", ip))
                }
            }
            IpcCommand::UnblockIp { ip } => {
                let success = FirewallManager::unblock_ip(&ip);
                if success {
                    IpcResponse::Ack
                } else {
                    IpcResponse::Error(format!("Falha ao desbloquear IP {}", ip))
                }
            }
            IpcCommand::GetStatus => {
                let mut conns = ProcessTracker::get_active_connections();
                let blocked = FirewallManager::get_active_blocks();

                let read_state = state.read().await;
                // Enriquece as conexões ativas com o cache de nomes de sites e ASN
                for conn in &mut conns {
                    let domain = read_state.get_domain_for_ip(&conn.remote_ip);
                    if !domain.is_empty() {
                        conn.site = domain;
                    }
                    let org = read_state.get_org_for_ip(&conn.remote_ip);
                    if !org.is_empty() {
                        conn.org = org;
                    }
                }

                let snapshot = read_state.build_snapshot(conns, blocked);
                IpcResponse::Status(snapshot)
            }
        }
    }
}

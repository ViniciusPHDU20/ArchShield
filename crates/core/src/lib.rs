// language: Rust, file: crates/core/src/lib.rs, runtime: pure-rust, target: Linux
pub mod fingerprint;
pub mod integrity;
pub mod models;

pub use fingerprint::{describe_port, fingerprint_syn, FingerprintResult};
pub use integrity::{analyze_process, hash_file, ProcessIntegrity, Sha256};
pub use models::{ConnectionInfo, IntruderEvent, IpcCommand, IpcResponse, SystemStatus};

pub const DEFAULT_SOCKET_PATH: &str = "/run/archshield/archshield.sock";

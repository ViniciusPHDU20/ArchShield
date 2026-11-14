// language: Rust, file: crates/core/src/lib.rs, runtime: pure-rust, target: Linux
pub mod covert;
pub mod fingerprint;
pub mod integrity;
pub mod models;
pub mod rootkit_hunter;

pub use covert::{analyze_dns_query, analyze_icmp_payload, shannon_entropy, CovertAlert};
pub use fingerprint::{describe_port, fingerprint_syn, FingerprintResult};
pub use integrity::{analyze_process, hash_file, ProcessIntegrity, Sha256};
pub use models::{ConnectionInfo, IntruderEvent, IpcCommand, IpcResponse, SystemStatus};
pub use rootkit_hunter::{KernelIntegrityReport, RootkitHunter};

pub const DEFAULT_SOCKET_PATH: &str = "/run/archshield/archshield.sock";

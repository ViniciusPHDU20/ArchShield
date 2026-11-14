pub mod fingerprint;
pub mod models;

pub use fingerprint::{describe_port, fingerprint_syn, FingerprintResult};
pub use models::{ConnectionInfo, IntruderEvent, IpcCommand, IpcResponse, SystemStatus};

pub const DEFAULT_SOCKET_PATH: &str = "/run/archshield/archshield.sock";

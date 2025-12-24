//! Network module
//!
//! This module provides TLS-based networking capabilities for Meshara nodes.
//! It handles secure peer-to-peer connections using TLS 1.3.

mod connection;
mod tls;

pub use connection::{Connection, ConnectionPool, ConnectionState};
pub use tls::{TlsConfig, TlsListener};

/// Maximum message size in bytes (16 MB)
/// This prevents DoS attacks via oversized messages
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// ALPN protocol identifier for Meshara
pub const MESHARA_ALPN: &[u8] = b"meshara/1.0";

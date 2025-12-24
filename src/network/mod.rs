//! Network module
//!
//! This module provides TLS-based networking capabilities for Meshara nodes.
//! It handles secure peer-to-peer connections using TLS 1.3.

mod connection;
mod discovery;
mod tls;

pub use connection::{Connection, ConnectionPool, ConnectionState};
pub use discovery::{DiscoveryConfig, DiscoveryMethod, PeerAddress, PeerInfo, PeerStore};
pub use tls::{TlsConfig, TlsListener};

// Re-export mDNS discovery when local-discovery feature is enabled
#[cfg(feature = "local-discovery")]
pub use discovery::{mdns_discovery_loop, MdnsDiscovery};

/// Maximum message size in bytes (16 MB)
/// This prevents DoS attacks via oversized messages
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// ALPN protocol identifier for Meshara
pub const MESHARA_ALPN: &[u8] = b"meshara/1.0";

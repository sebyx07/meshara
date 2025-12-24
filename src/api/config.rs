//! Configuration types for Meshara nodes
//!
//! This module defines the configuration structures and enums for configuring
//! a Node's behavior, network profile, and privacy level.

use crate::crypto::PublicKey;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Pre-configured network profiles for different use cases
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProfile {
    /// Minimal configuration for IoT devices and low-resource environments
    ///
    /// - Max 8 peers
    /// - No auto-discovery
    /// - Minimal features enabled
    /// - Optimized for low memory and CPU usage
    Minimal,

    /// Balanced configuration suitable for most applications (default)
    ///
    /// - Max 32 peers
    /// - Auto-discovery enabled
    /// - Most features enabled
    /// - Good balance of performance and resource usage
    #[default]
    Standard,

    /// High-connectivity configuration for relay/bridge nodes
    ///
    /// - Max 128 peers
    /// - Accepts incoming connections
    /// - Helps route traffic for other nodes
    /// - Higher resource requirements
    Bridge,

    /// Configuration for authority nodes that publish signed content
    ///
    /// - Authority key required
    /// - Can sign and publish updates
    /// - Accepts queries from other nodes
    /// - Specialized for content distribution
    Authority,
}

impl NetworkProfile {
    /// Get the default maximum number of peers for this profile
    pub fn default_max_peers(&self) -> usize {
        match self {
            Self::Minimal => 8,
            Self::Standard => 32,
            Self::Bridge => 128,
            Self::Authority => 32,
        }
    }

    /// Get whether auto-discovery is enabled by default for this profile
    pub fn default_auto_discovery(&self) -> bool {
        match self {
            Self::Minimal => false,
            Self::Standard => true,
            Self::Bridge => true,
            Self::Authority => true,
        }
    }
}

/// Privacy level configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PrivacyLevel {
    /// Standard privacy with basic encryption and signing
    ///
    /// - Direct connections where possible
    /// - Basic encryption for all messages
    /// - Some metadata may be visible (peer connections)
    /// - Lowest latency and bandwidth usage
    #[default]
    Standard,

    /// Enhanced privacy with additional protections
    ///
    /// - Use onion routing when available
    /// - Prefer multi-hop paths
    /// - More traffic padding
    /// - Moderate latency increase
    Enhanced,

    /// Maximum privacy protection
    ///
    /// - Always use onion routing
    /// - Generate cover traffic to obscure patterns
    /// - Maximum metadata protection
    /// - Higher latency and bandwidth cost
    /// - Best for high-security scenarios
    Maximum,
}

/// Complete node configuration
///
/// This structure contains all configuration parameters for a Meshara node.
/// Instances are created via `NodeBuilder` and validated before use.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Path to store identity and other persistent data
    pub storage_path: PathBuf,

    /// Port to listen on for incoming connections
    ///
    /// If set to 0, a random available port will be selected.
    pub listen_port: u16,

    /// Network profile determining resource usage and connectivity
    pub network_profile: NetworkProfile,

    /// Privacy level for traffic obfuscation
    pub privacy_level: PrivacyLevel,

    /// Maximum number of concurrent peer connections
    pub max_peers: usize,

    /// Whether to enable automatic peer discovery via mDNS
    pub auto_discovery: bool,

    /// List of bootstrap node addresses for initial connectivity
    ///
    /// These nodes help new nodes join the network.
    pub bootstrap_nodes: Vec<SocketAddr>,

    /// List of trusted authority public keys
    ///
    /// Updates from these authorities will be automatically verified.
    pub trusted_authorities: Vec<PublicKey>,

    /// Optional passphrase for encrypting stored identity
    ///
    /// If None, identity is stored unencrypted (development only).
    pub(crate) passphrase: Option<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        let network_profile = NetworkProfile::default();

        Self {
            storage_path: Self::default_storage_path(),
            listen_port: 0, // Random port
            network_profile,
            privacy_level: PrivacyLevel::default(),
            max_peers: network_profile.default_max_peers(),
            auto_discovery: network_profile.default_auto_discovery(),
            bootstrap_nodes: Vec::new(),
            trusted_authorities: Vec::new(),
            passphrase: None,
        }
    }
}

impl NodeConfig {
    /// Get the platform-specific default storage path
    ///
    /// - Linux: `~/.local/share/meshara`
    /// - macOS: `~/Library/Application Support/meshara`
    /// - Windows: `%APPDATA%/meshara`
    pub fn default_storage_path() -> PathBuf {
        directories::ProjectDirs::from("", "", "meshara")
            .map(|dirs| dirs.data_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("./meshara-data"))
    }

    /// Validate the configuration
    ///
    /// Checks that all configuration values are valid and consistent.
    ///
    /// # Errors
    ///
    /// Returns a `ConfigError` if any validation check fails:
    /// - `max_peers` must be greater than 0
    /// - `listen_port` must be valid (special case: 0 means random port)
    pub fn validate(&self) -> crate::Result<()> {
        use crate::error::ConfigError;

        // Validate max_peers
        if self.max_peers == 0 {
            return Err(ConfigError::MissingRequiredField {
                field: "max_peers".to_string(),
            }
            .into());
        }

        // Validate storage path (basic check - more thorough check happens at runtime)
        if self.storage_path.as_os_str().is_empty() {
            return Err(ConfigError::InvalidPath {
                path: self.storage_path.clone(),
            }
            .into());
        }

        // Port 0 is valid (means random port)
        // All other ports are technically valid, though < 1024 may require privileges

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_profile_defaults() {
        assert_eq!(NetworkProfile::default(), NetworkProfile::Standard);

        assert_eq!(NetworkProfile::Minimal.default_max_peers(), 8);
        assert_eq!(NetworkProfile::Standard.default_max_peers(), 32);
        assert_eq!(NetworkProfile::Bridge.default_max_peers(), 128);
        assert_eq!(NetworkProfile::Authority.default_max_peers(), 32);

        assert!(!NetworkProfile::Minimal.default_auto_discovery());
        assert!(NetworkProfile::Standard.default_auto_discovery());
        assert!(NetworkProfile::Bridge.default_auto_discovery());
        assert!(NetworkProfile::Authority.default_auto_discovery());
    }

    #[test]
    fn test_privacy_level_default() {
        assert_eq!(PrivacyLevel::default(), PrivacyLevel::Standard);
    }

    #[test]
    fn test_node_config_default() {
        let config = NodeConfig::default();

        assert_eq!(config.network_profile, NetworkProfile::Standard);
        assert_eq!(config.privacy_level, PrivacyLevel::Standard);
        assert_eq!(config.max_peers, 32);
        assert!(config.auto_discovery);
        assert_eq!(config.listen_port, 0); // Random port
        assert!(config.bootstrap_nodes.is_empty());
        assert!(config.trusted_authorities.is_empty());
        assert!(config.passphrase.is_none());
    }

    #[test]
    fn test_node_config_validation_success() {
        let config = NodeConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_node_config_validation_zero_peers() {
        let config = NodeConfig {
            max_peers: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_node_config_validation_empty_path() {
        let config = NodeConfig {
            storage_path: PathBuf::from(""),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_default_storage_path() {
        let path = NodeConfig::default_storage_path();
        assert!(!path.as_os_str().is_empty());
        // Path should contain "meshara" somewhere
        let path_str = path.to_string_lossy().to_lowercase();
        assert!(path_str.contains("meshara"));
    }
}

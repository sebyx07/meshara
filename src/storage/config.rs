//! Configuration storage and management
//!
//! This module handles persisting and loading node configuration.
//! Configuration is stored as human-readable JSON (not encrypted).

use crate::error::{ConfigError, Result, StorageError};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;

/// Network profile determines the node's behavior in the network
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProfile {
    /// Minimal resource usage, suitable for mobile/embedded devices
    Minimal,
    /// Standard node behavior, good balance of resources and functionality
    #[default]
    Standard,
    /// Bridge node helps with NAT traversal and relaying
    Bridge,
    /// Authority node for update distribution
    Authority,
}

/// Privacy level determines routing and encryption behavior
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum PrivacyLevel {
    /// Standard privacy with single-hop routing
    #[default]
    Standard,
    /// Enhanced privacy with some multi-hop routing
    Enhanced,
    /// Maximum privacy with onion routing
    Maximum,
}

/// Node configuration
///
/// This is stored as JSON and is not encrypted (public configuration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node ID (hex-encoded public key hash)
    pub node_id: String,

    /// Port to listen on for incoming connections
    pub listen_port: u16,

    /// Bootstrap nodes for initial network discovery
    #[serde(default)]
    pub bootstrap_nodes: Vec<SocketAddr>,

    /// Trusted authority public keys (as hex strings)
    #[serde(default)]
    pub trusted_authorities: Vec<String>,

    /// Network profile
    #[serde(default)]
    pub network_profile: NetworkProfile,

    /// Privacy level
    #[serde(default)]
    pub privacy_level: PrivacyLevel,

    /// Maximum number of peer connections
    #[serde(default = "default_max_peers")]
    pub max_peers: usize,
}

fn default_max_peers() -> usize {
    50
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_id: String::new(),
            listen_port: 0, // Will be assigned randomly
            bootstrap_nodes: Vec::new(),
            trusted_authorities: Vec::new(),
            network_profile: NetworkProfile::default(),
            privacy_level: PrivacyLevel::default(),
            max_peers: default_max_peers(),
        }
    }
}

impl NodeConfig {
    /// Create a new configuration with sensible defaults
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            ..Default::default()
        }
    }

    /// Create a configuration with a specific listen port
    pub fn with_port(mut self, port: u16) -> Self {
        self.listen_port = port;
        self
    }

    /// Add bootstrap nodes
    pub fn with_bootstrap_nodes(mut self, nodes: Vec<SocketAddr>) -> Self {
        self.bootstrap_nodes = nodes;
        self
    }

    /// Add trusted authorities
    pub fn with_trusted_authorities(mut self, authorities: Vec<String>) -> Self {
        self.trusted_authorities = authorities;
        self
    }

    /// Set network profile
    pub fn with_network_profile(mut self, profile: NetworkProfile) -> Self {
        self.network_profile = profile;
        self
    }

    /// Set privacy level
    pub fn with_privacy_level(mut self, level: PrivacyLevel) -> Self {
        self.privacy_level = level;
        self
    }

    /// Set maximum number of peers
    pub fn with_max_peers(mut self, max_peers: usize) -> Self {
        self.max_peers = max_peers;
        self
    }
}

/// Save configuration to a JSON file
///
/// # Arguments
///
/// * `path` - Path to the configuration file
/// * `config` - Configuration to save
///
/// # Example
///
/// ```no_run
/// use meshara::storage::config::{save_config, NodeConfig};
/// use std::path::Path;
///
/// let config = NodeConfig::default();
/// save_config(Path::new("config.json"), &config).unwrap();
/// ```
pub fn save_config(path: &Path, config: &NodeConfig) -> Result<()> {
    // Create parent directory if it doesn't exist
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(StorageError::from)?;
    }

    // Serialize to pretty JSON for human readability
    let json =
        serde_json::to_string_pretty(config).map_err(|e| StorageError::SerializationFailed {
            reason: format!("Failed to serialize config: {}", e),
        })?;

    // Write to file
    std::fs::write(path, json).map_err(StorageError::from)?;

    Ok(())
}

/// Load configuration from a JSON file
///
/// # Arguments
///
/// * `path` - Path to the configuration file
///
/// # Errors
///
/// Returns an error if:
/// - The file doesn't exist
/// - The file contains invalid JSON
/// - The JSON doesn't match the expected schema
///
/// # Example
///
/// ```no_run
/// use meshara::storage::config::load_config;
/// use std::path::Path;
///
/// let config = load_config(Path::new("config.json")).unwrap();
/// ```
pub fn load_config(path: &Path) -> Result<NodeConfig> {
    // Check if file exists
    if !path.exists() {
        return Err(StorageError::FileNotFound {
            path: path.to_path_buf(),
        }
        .into());
    }

    // Read file
    let json = std::fs::read_to_string(path).map_err(StorageError::from)?;

    // Deserialize
    let config: NodeConfig =
        serde_json::from_str(&json).map_err(|e| StorageError::SerializationFailed {
            reason: format!("Failed to deserialize config: {}", e),
        })?;

    // Validate fields
    validate_config(&config)?;

    Ok(config)
}

/// Check if a configuration file exists
///
/// # Arguments
///
/// * `path` - Path to check
///
/// # Example
///
/// ```no_run
/// use meshara::storage::config::config_exists;
/// use std::path::Path;
///
/// if config_exists(Path::new("config.json")) {
///     println!("Config exists");
/// }
/// ```
pub fn config_exists(path: &Path) -> bool {
    path.exists() && path.is_file()
}

/// Get default configuration
///
/// Returns sensible defaults that can be customized.
///
/// # Example
///
/// ```
/// use meshara::storage::config::default_config;
///
/// let config = default_config();
/// assert_eq!(config.max_peers, 50);
/// ```
pub fn default_config() -> NodeConfig {
    NodeConfig::default()
}

/// Validate configuration fields
fn validate_config(config: &NodeConfig) -> Result<()> {
    // Validate max_peers is reasonable
    if config.max_peers == 0 {
        return Err(ConfigError::InvalidPort { port: 0 }.into());
    }

    if config.max_peers > 10000 {
        return Err(ConfigError::InvalidPort { port: 65535 }.into());
    }

    // Validate trusted authorities are valid hex strings
    for auth in &config.trusted_authorities {
        if auth.len() != 128 {
            // 64 bytes = 128 hex chars
            return Err(ConfigError::MissingRequiredField {
                field: "trusted_authorities".to_string(),
            }
            .into());
        }

        if !auth.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ConfigError::MissingRequiredField {
                field: "trusted_authorities".to_string(),
            }
            .into());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = default_config();
        assert_eq!(config.max_peers, 50);
        assert_eq!(config.network_profile, NetworkProfile::Standard);
        assert_eq!(config.privacy_level, PrivacyLevel::Standard);
    }

    #[test]
    fn test_config_builder() {
        let config = NodeConfig::new("test_node".to_string())
            .with_port(8080)
            .with_max_peers(100)
            .with_network_profile(NetworkProfile::Bridge)
            .with_privacy_level(PrivacyLevel::Enhanced);

        assert_eq!(config.node_id, "test_node");
        assert_eq!(config.listen_port, 8080);
        assert_eq!(config.max_peers, 100);
        assert_eq!(config.network_profile, NetworkProfile::Bridge);
        assert_eq!(config.privacy_level, PrivacyLevel::Enhanced);
    }

    #[test]
    fn test_save_and_load_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.json");

        let original_config = NodeConfig::new("test_node".to_string())
            .with_port(9000)
            .with_max_peers(75);

        // Save config
        save_config(&config_path, &original_config).unwrap();

        // Check file exists
        assert!(config_exists(&config_path));

        // Load config
        let loaded_config = load_config(&config_path).unwrap();

        // Verify fields match
        assert_eq!(loaded_config.node_id, original_config.node_id);
        assert_eq!(loaded_config.listen_port, original_config.listen_port);
        assert_eq!(loaded_config.max_peers, original_config.max_peers);
    }

    #[test]
    fn test_load_nonexistent_config() {
        let result = load_config(Path::new("/nonexistent/config.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_json() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.json");

        // Write invalid JSON
        std::fs::write(&config_path, "not valid json").unwrap();

        let result = load_config(&config_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation_max_peers_zero() {
        let config = NodeConfig::new("test".to_string()).with_max_peers(0);
        let result = validate_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation_max_peers_too_high() {
        let config = NodeConfig::new("test".to_string()).with_max_peers(20000);
        let result = validate_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation_invalid_authority_length() {
        let config =
            NodeConfig::new("test".to_string()).with_trusted_authorities(vec!["short".to_string()]);
        let result = validate_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation_invalid_authority_hex() {
        let invalid_hex = "g".repeat(128); // 'g' is not a valid hex digit
        let config =
            NodeConfig::new("test".to_string()).with_trusted_authorities(vec![invalid_hex]);
        let result = validate_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_with_bootstrap_nodes() {
        let bootstrap = vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            8080,
        )];
        let config = NodeConfig::new("test".to_string()).with_bootstrap_nodes(bootstrap.clone());
        assert_eq!(config.bootstrap_nodes, bootstrap);
    }

    #[test]
    fn test_network_profile_serialization() {
        let profiles = vec![
            NetworkProfile::Minimal,
            NetworkProfile::Standard,
            NetworkProfile::Bridge,
            NetworkProfile::Authority,
        ];

        for profile in profiles {
            let json = serde_json::to_string(&profile).unwrap();
            let deserialized: NetworkProfile = serde_json::from_str(&json).unwrap();
            assert_eq!(profile, deserialized);
        }
    }

    #[test]
    fn test_privacy_level_serialization() {
        let levels = vec![
            PrivacyLevel::Standard,
            PrivacyLevel::Enhanced,
            PrivacyLevel::Maximum,
        ];

        for level in levels {
            let json = serde_json::to_string(&level).unwrap();
            let deserialized: PrivacyLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, deserialized);
        }
    }
}

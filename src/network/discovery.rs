//! Peer discovery and management
//!
//! This module provides mechanisms for nodes to discover and connect to peers:
//! - Manual peer addition
//! - mDNS local network discovery
//! - Bootstrap nodes
//! - Peer information storage and reputation tracking

use crate::crypto::{NodeId, PublicKey};
use crate::error::{NetworkError, Result};
use crate::storage::StorageBackend;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[cfg(feature = "local-discovery")]
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

/// Discovery methods for finding peers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    /// Manual peer addition by address
    Manual,
    /// Local network discovery via mDNS
    LocalMDNS,
    /// Connection to known bootstrap nodes
    Bootstrap,
}

/// Information about a discovered or connected peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Unique node identifier
    pub peer_id: NodeId,
    /// Peer's public key for verification
    pub public_key: PublicKey,
    /// Network address
    pub address: SocketAddr,
    /// When connection was established
    pub connected_since: Instant,
    /// Total bytes sent to this peer
    pub bytes_sent: u64,
    /// Total bytes received from this peer
    pub bytes_received: u64,
    /// Last time we heard from this peer
    pub last_seen: Instant,
    /// Reputation score (0.0 = bad, 1.0 = excellent)
    pub reputation: f64,
}

impl PeerInfo {
    /// Create new peer info
    pub fn new(peer_id: NodeId, public_key: PublicKey, address: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            peer_id,
            public_key,
            address,
            connected_since: now,
            bytes_sent: 0,
            bytes_received: 0,
            last_seen: now,
            reputation: 0.5, // Start with neutral reputation
        }
    }

    /// Update reputation based on successful interaction
    pub fn increase_reputation(&mut self, amount: f64) {
        self.reputation = (self.reputation + amount).min(1.0);
        self.last_seen = Instant::now();
    }

    /// Decrease reputation based on failed interaction
    pub fn decrease_reputation(&mut self, amount: f64) {
        self.reputation = (self.reputation - amount).max(0.0);
        self.last_seen = Instant::now();
    }

    /// Check if peer should be trusted
    pub fn is_trusted(&self) -> bool {
        self.reputation >= 0.6
    }

    /// Check if peer should be banned
    pub fn should_ban(&self) -> bool {
        self.reputation < 0.2
    }
}

/// Address of a discovered peer
#[derive(Debug, Clone)]
pub struct PeerAddress {
    /// Network address
    pub address: SocketAddr,
    /// Public key for verification
    pub public_key: PublicKey,
    /// Node identifier
    pub node_id: NodeId,
}

/// Configuration for peer discovery
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Enabled discovery methods
    pub enabled_methods: Vec<DiscoveryMethod>,
    /// mDNS discovery interval
    pub mdns_interval: Duration,
    /// Bootstrap node addresses
    pub bootstrap_nodes: Vec<SocketAddr>,
    /// Maximum number of peers to maintain
    pub max_peers: usize,
    /// Target number of peers to maintain
    pub target_peers: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled_methods: vec![DiscoveryMethod::Manual, DiscoveryMethod::LocalMDNS],
            mdns_interval: Duration::from_secs(30),
            bootstrap_nodes: vec![],
            max_peers: 32,
            target_peers: 16,
        }
    }
}

/// Peer information storage
pub struct PeerStore {
    storage: Arc<Mutex<Box<dyn StorageBackend + Send>>>,
}

impl PeerStore {
    /// Create new peer store
    pub fn new(storage: Box<dyn StorageBackend + Send>) -> Self {
        Self {
            storage: Arc::new(Mutex::new(storage)),
        }
    }

    /// Save peer information
    ///
    /// Note: Currently only stores basic peer metadata (address, reputation).
    /// For full persistence, consider implementing custom serialization.
    pub async fn save_peer(&self, peer: &PeerInfo) -> Result<()> {
        let key = format!("peer:{}", hex::encode(peer.peer_id.as_bytes()));

        // Manual serialization since PeerInfo contains non-serializable types
        let peer_data = format!(
            "{}:{}:{}",
            peer.address,
            peer.reputation,
            peer.bytes_sent + peer.bytes_received
        );

        let mut storage = self.storage.lock().await;
        storage.save(&key, peer_data.as_bytes())
    }

    /// Load all saved peers
    ///
    /// Note: This implementation is not optimal as it doesn't have a list_keys method.
    /// For production use, you'd want to either:
    /// 1. Extend StorageBackend trait with list_keys functionality
    /// 2. Maintain a separate index of peer keys
    /// 3. Use a database backend with query support
    ///
    /// For the MVP, we return an empty list since we can't efficiently list all peers.
    pub async fn load_peers(&self) -> Result<Vec<PeerInfo>> {
        // TODO: Implement proper peer listing when StorageBackend supports it
        // For now, return empty list
        Ok(Vec::new())
    }

    /// Remove peer from storage
    pub async fn remove_peer(&self, node_id: &NodeId) -> Result<()> {
        let key = format!("peer:{}", hex::encode(node_id.as_bytes()));
        let storage = self.storage.lock().await;
        storage.delete(&key)
    }
}

/// mDNS-based local network discovery
#[cfg(feature = "local-discovery")]
pub struct MdnsDiscovery {
    mdns: ServiceDaemon,
    #[allow(dead_code)]
    service_name: String,
    service_fullname: String,
}

#[cfg(feature = "local-discovery")]
impl MdnsDiscovery {
    const SERVICE_TYPE: &'static str = "_meshara._tcp.local.";

    /// Create new mDNS discovery service
    ///
    /// # Arguments
    ///
    /// * `node_id` - This node's identifier
    /// * `port` - Port this node is listening on
    /// * `public_key` - This node's public key to advertise
    pub fn new(node_id: &NodeId, port: u16, public_key: &PublicKey) -> Result<Self> {
        let mdns = ServiceDaemon::new().map_err(|e| NetworkError::DiscoveryFailed {
            reason: format!("Failed to create mDNS service: {}", e),
        })?;

        // Create unique service instance name
        let service_name = format!("meshara-{}", hex::encode(&node_id.as_bytes()[..8]));

        // Create service info with TXT records
        let mut properties = std::collections::HashMap::new();
        properties.insert("version".to_string(), "1".to_string());
        properties.insert("pubkey".to_string(), hex::encode(public_key.to_bytes()));
        properties.insert("node_id".to_string(), hex::encode(node_id.as_bytes()));

        let service_info = ServiceInfo::new(
            Self::SERVICE_TYPE,
            &service_name,
            &format!("{}.local.", &service_name),
            "",
            port,
            Some(properties),
        )
        .map_err(|e| NetworkError::DiscoveryFailed {
            reason: format!("Failed to create service info: {}", e),
        })?;

        let service_fullname = service_info.get_fullname().to_string();

        // Register the service
        mdns.register(service_info)
            .map_err(|e| NetworkError::DiscoveryFailed {
                reason: format!("Failed to register mDNS service: {}", e),
            })?;

        Ok(Self {
            mdns,
            service_name,
            service_fullname,
        })
    }

    /// Discover peers on the local network
    ///
    /// Returns a list of discovered peer addresses
    pub async fn discover_peers(&self) -> Result<Vec<PeerAddress>> {
        let receiver =
            self.mdns
                .browse(Self::SERVICE_TYPE)
                .map_err(|e| NetworkError::DiscoveryFailed {
                    reason: format!("Failed to browse mDNS services: {}", e),
                })?;

        let mut discovered_peers = Vec::new();
        let timeout = Duration::from_secs(5);
        let start = Instant::now();

        while start.elapsed() < timeout {
            if let Ok(Ok(ServiceEvent::ServiceResolved(info))) =
                tokio::time::timeout(Duration::from_millis(100), receiver.recv_async()).await
            {
                // Skip our own service
                if info.get_fullname() == self.service_fullname {
                    continue;
                }

                // Extract peer information from TXT records
                if let Some(peer_address) = Self::extract_peer_info(&info) {
                    discovered_peers.push(peer_address);
                }
            }
        }

        Ok(discovered_peers)
    }

    /// Extract peer information from mDNS resolved service
    fn extract_peer_info(info: &mdns_sd::ResolvedService) -> Option<PeerAddress> {
        let properties = info.get_properties();

        // Get public key
        let pubkey_prop = properties.get("pubkey")?;
        let pubkey_hex = pubkey_prop.val_str();
        let pubkey_bytes = hex::decode(pubkey_hex).ok()?;
        let public_key = PublicKey::from_bytes(&pubkey_bytes).ok()?;

        // Get node ID
        let node_id_prop = properties.get("node_id")?;
        let node_id_hex = node_id_prop.val_str();
        let node_id_bytes = hex::decode(node_id_hex).ok()?;
        if node_id_bytes.len() != 32 {
            return None;
        }
        let mut node_id_array = [0u8; 32];
        node_id_array.copy_from_slice(&node_id_bytes);
        let node_id = NodeId::from_bytes(node_id_array);

        // Get address - use hostname to create socket address
        // Note: mDNS resolved services should have valid addresses
        let hostname = info.get_hostname();
        let port = info.get_port();

        // Try to parse hostname as IP, otherwise use first address from resolved addresses
        let socket_addr = if let Ok(ip) = hostname.trim_end_matches('.').parse::<std::net::IpAddr>()
        {
            SocketAddr::new(ip, port)
        } else {
            // Use first resolved address
            let addresses = info.get_addresses();
            let addr_set = addresses.iter().next()?;
            // Create socket address from string representation
            format!("{}:{}", addr_set, port).parse().ok()?
        };

        Some(PeerAddress {
            address: socket_addr,
            public_key,
            node_id,
        })
    }

    /// Stop the mDNS service
    pub fn stop(&self) {
        let _ = self.mdns.unregister(&self.service_fullname);
        let _ = self.mdns.shutdown();
    }
}

#[cfg(feature = "local-discovery")]
impl Drop for MdnsDiscovery {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Continuous mDNS discovery loop
#[cfg(feature = "local-discovery")]
pub async fn mdns_discovery_loop<F>(
    discovery: Arc<Mutex<MdnsDiscovery>>,
    interval: Duration,
    mut on_peer_discovered: F,
) where
    F: FnMut(PeerAddress) + Send,
{
    loop {
        // Discover peers
        if let Ok(peers) = discovery.lock().await.discover_peers().await {
            for peer in peers {
                on_peer_discovered(peer);
            }
        }

        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_info_reputation() {
        let node_id = NodeId::from_bytes([1u8; 32]);
        let public_key = crate::crypto::Identity::generate().public_key();
        let addr: SocketAddr = "127.0.0.1:8443".parse().unwrap();

        let mut peer = PeerInfo::new(node_id, public_key, addr);

        // Initial reputation is neutral
        assert_eq!(peer.reputation, 0.5);
        assert!(!peer.is_trusted());
        assert!(!peer.should_ban());

        // Increase reputation
        peer.increase_reputation(0.2);
        assert_eq!(peer.reputation, 0.7);
        assert!(peer.is_trusted());

        // Decrease reputation
        peer.decrease_reputation(0.6);
        assert!((peer.reputation - 0.1).abs() < 0.001); // Floating point comparison
        assert!(peer.should_ban());

        // Reputation should be clamped
        peer.increase_reputation(10.0);
        assert_eq!(peer.reputation, 1.0);

        peer.decrease_reputation(10.0);
        assert_eq!(peer.reputation, 0.0);
    }

    #[test]
    fn test_discovery_config_default() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.enabled_methods.len(), 2);
        assert!(config.enabled_methods.contains(&DiscoveryMethod::Manual));
        assert!(config.enabled_methods.contains(&DiscoveryMethod::LocalMDNS));
        assert_eq!(config.max_peers, 32);
        assert_eq!(config.target_peers, 16);
    }

    #[tokio::test]
    async fn test_peer_store() {
        use crate::storage::MemoryStorage;

        let storage = Box::new(MemoryStorage::new());
        let store = PeerStore::new(storage);

        let node_id = NodeId::from_bytes([2u8; 32]);
        let public_key = crate::crypto::Identity::generate().public_key();
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();

        let peer = PeerInfo::new(node_id, public_key, addr);

        // Save peer
        store.save_peer(&peer).await.unwrap();

        // Note: load_peers() currently returns empty list due to lack of list_keys
        // in StorageBackend trait. This is a known limitation for MVP.
        let loaded_peers = store.load_peers().await.unwrap();
        assert_eq!(loaded_peers.len(), 0); // Known limitation

        // Remove peer (should succeed even though we can't list)
        store.remove_peer(&node_id).await.unwrap();
    }
}

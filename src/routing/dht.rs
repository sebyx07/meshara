//! Distributed Hash Table (DHT) for global peer discovery
//!
//! This module implements a DHT integration for discovering peers across the internet
//! without relying on central servers.
//!
//! **Note**: This is a simplified implementation for Phase 4-02. Full libp2p/Kademlia
//! integration is planned for future releases.
//!
//! The DHT is used to:
//! - Advertise node contact information (IP, port, public key)
//! - Look up peers by their node ID
//! - Discover authority nodes
//!
//! This module is feature-gated and only compiled when the "dht" feature is enabled.

#[cfg(feature = "dht")]
use crate::crypto::{NodeId, PublicKey};
#[cfg(feature = "dht")]
use crate::error::Result;
#[cfg(feature = "dht")]
use dashmap::DashMap;
#[cfg(feature = "dht")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "dht")]
use std::net::SocketAddr;
#[cfg(feature = "dht")]
use std::sync::Arc;

/// Contact information stored in the DHT
#[cfg(feature = "dht")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    /// Network address (IP and port)
    pub address: SocketAddr,
    /// Node's public key for verification
    pub public_key: PublicKey,
    /// Timestamp when advertised (milliseconds since epoch)
    pub advertised_at: i64,
}

#[cfg(feature = "dht")]
impl ContactInfo {
    /// Create new contact info
    pub fn new(address: SocketAddr, public_key: PublicKey) -> Self {
        Self {
            address,
            public_key,
            advertised_at: current_timestamp_ms(),
        }
    }

    /// Check if contact info is stale (older than 2 hours)
    pub fn is_stale(&self) -> bool {
        let age_ms = current_timestamp_ms() - self.advertised_at;
        age_ms > 7200000 // 2 hours in milliseconds
    }
}

/// Simplified DHT node for peer discovery
///
/// **Note**: This is a simplified in-memory implementation. Full Kademlia DHT
/// integration with libp2p is planned for future releases.
#[cfg(feature = "dht")]
pub struct DhtNode {
    /// In-memory storage of peer contact information
    storage: Arc<DashMap<Vec<u8>, ContactInfo>>,
}

#[cfg(feature = "dht")]
impl DhtNode {
    /// Create a new DHT node
    ///
    /// # Arguments
    /// * `_identity` - This node's identity (unused in simplified implementation)
    /// * `_bootstrap_peers` - List of bootstrap nodes (unused in simplified implementation)
    pub fn new(
        _identity: &crate::crypto::Identity,
        _bootstrap_peers: Vec<String>,
    ) -> Result<Self> {
        Ok(Self {
            storage: Arc::new(DashMap::new()),
        })
    }

    /// Get a handle to this DHT node
    pub fn handle(&self) -> DhtHandle {
        DhtHandle {
            storage: Arc::clone(&self.storage),
        }
    }

    /// Run the DHT event loop (no-op in simplified implementation)
    pub async fn run(self) {
        // In the full implementation, this would run the libp2p event loop
        // For now, we just keep the task alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        }
    }
}

/// Handle for interacting with a DHT node
#[cfg(feature = "dht")]
#[derive(Clone)]
pub struct DhtHandle {
    storage: Arc<DashMap<Vec<u8>, ContactInfo>>,
}

#[cfg(feature = "dht")]
impl DhtHandle {
    /// Store a key-value pair in the DHT
    pub async fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        use crate::error::ProtocolError;
        let contact_info: ContactInfo = bincode::deserialize(&value).map_err(|e| {
            ProtocolError::SerializationFailed {
                message_type: "ContactInfo".to_string(),
                reason: e.to_string(),
            }
        })?;
        self.storage.insert(key, contact_info);
        Ok(())
    }

    /// Retrieve a value from the DHT
    pub async fn get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
        use crate::error::ProtocolError;
        if let Some(contact_info) = self.storage.get(&key) {
            let value = bincode::serialize(&*contact_info).map_err(|e| {
                ProtocolError::SerializationFailed {
                    message_type: "ContactInfo".to_string(),
                    reason: e.to_string(),
                }
            })?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    /// Bootstrap to join the DHT network (no-op in simplified implementation)
    pub async fn bootstrap(&self) -> Result<()> {
        // In the full implementation, this would connect to bootstrap nodes
        Ok(())
    }
}

/// Advertise this node's contact information to the DHT
#[cfg(feature = "dht")]
pub async fn advertise_self(
    dht: &DhtHandle,
    node_id: &NodeId,
    address: SocketAddr,
    public_key: &PublicKey,
) -> Result<()> {
    use crate::error::ProtocolError;
    let contact_info = ContactInfo::new(address, public_key.clone());
    let value = bincode::serialize(&contact_info).map_err(|e| {
        ProtocolError::SerializationFailed {
            message_type: "ContactInfo".to_string(),
            reason: e.to_string(),
        }
    })?;
    dht.put(node_id.as_bytes().to_vec(), value).await
}

/// Look up a peer's contact information in the DHT
#[cfg(feature = "dht")]
pub async fn find_peer(dht: &DhtHandle, node_id: &NodeId) -> Result<Option<ContactInfo>> {
    use crate::error::ProtocolError;
    let value = dht.get(node_id.as_bytes().to_vec()).await?;

    if let Some(bytes) = value {
        let contact_info: ContactInfo = bincode::deserialize(&bytes).map_err(|e| {
            ProtocolError::SerializationFailed {
                message_type: "ContactInfo".to_string(),
                reason: e.to_string(),
            }
        })?;
        if contact_info.is_stale() {
            return Ok(None);
        }
        Ok(Some(contact_info))
    } else {
        Ok(None)
    }
}

/// Get current timestamp in milliseconds since Unix epoch
#[cfg(feature = "dht")]
fn current_timestamp_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(all(test, feature = "dht"))]
mod tests {
    use super::*;
    use crate::crypto::Identity;

    #[tokio::test]
    async fn test_contact_info_creation() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let identity = Identity::generate();
        let public_key = identity.public_key();

        let contact = ContactInfo::new(addr, public_key);

        assert_eq!(contact.address, addr);
        assert!(!contact.is_stale());
    }

    #[tokio::test]
    async fn test_contact_info_staleness() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let identity = Identity::generate();
        let public_key = identity.public_key();

        let mut contact = ContactInfo::new(addr, public_key);

        // Make it appear old (3 hours ago)
        contact.advertised_at = current_timestamp_ms() - 10800000;

        assert!(contact.is_stale());
    }

    #[tokio::test]
    async fn test_contact_info_serialization() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let identity = Identity::generate();
        let public_key = identity.public_key();

        let contact = ContactInfo::new(addr, public_key.clone());

        let serialized = bincode::serialize(&contact).unwrap();
        let deserialized: ContactInfo = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.address, contact.address);
        assert_eq!(deserialized.public_key, contact.public_key);
        assert_eq!(deserialized.advertised_at, contact.advertised_at);
    }

    #[tokio::test]
    async fn test_dht_put_get() {
        let identity = Identity::generate();
        let dht = DhtNode::new(&identity, vec![]).unwrap();
        let handle = dht.handle();

        let key = b"test_key".to_vec();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let contact = ContactInfo::new(addr, identity.public_key());
        let value = bincode::serialize(&contact).unwrap();

        // Store value
        handle.put(key.clone(), value.clone()).await.unwrap();

        // Retrieve value
        let retrieved = handle.get(key).await.unwrap();
        assert_eq!(retrieved, Some(value));
    }

    #[tokio::test]
    async fn test_advertise_and_find_peer() {
        let identity = Identity::generate();
        let node_id = identity.node_id();
        let dht = DhtNode::new(&identity, vec![]).unwrap();
        let handle = dht.handle();

        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let public_key = identity.public_key();

        // Advertise node
        advertise_self(&handle, &node_id, addr, &public_key)
            .await
            .unwrap();

        // Find peer
        let found = find_peer(&handle, &node_id).await.unwrap();
        assert!(found.is_some());

        let contact_info = found.unwrap();
        assert_eq!(contact_info.address, addr);
        assert_eq!(contact_info.public_key, public_key);
    }
}

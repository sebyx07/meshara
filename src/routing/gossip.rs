//! Gossip protocol for broadcast message propagation
//!
//! This module implements epidemic-style broadcast propagation where messages
//! are forwarded to all connected peers, with deduplication to prevent loops.

use crate::crypto::NodeId;
use crate::error::Result;
use crate::protocol::BaseMessage;
use crate::routing::router::Router;
use bloomfilter::Bloom;
use parking_lot::Mutex;
use std::sync::Arc;

/// Default Bloom filter capacity for broadcast tracking
const BROADCAST_BLOOM_CAPACITY: usize = 100_000;

/// Default Bloom filter false positive rate
const BROADCAST_BLOOM_FP_RATE: f64 = 0.01;

/// Maximum fanout for optimized gossip (how many peers to forward to)
const DEFAULT_FANOUT: usize = 8;

/// Gossip protocol for broadcast propagation
pub struct GossipProtocol {
    /// Reference to the router
    router: Arc<Router>,

    /// Bloom filter for tracking seen broadcasts
    seen_broadcasts: Arc<Mutex<Bloom<[u8]>>>,

    /// Maximum fanout (0 = unlimited)
    max_fanout: usize,
}

impl GossipProtocol {
    /// Create a new gossip protocol handler
    pub fn new(router: Arc<Router>) -> Self {
        Self {
            router,
            seen_broadcasts: Arc::new(Mutex::new(Bloom::new_for_fp_rate(
                BROADCAST_BLOOM_CAPACITY,
                BROADCAST_BLOOM_FP_RATE,
            ))),
            max_fanout: DEFAULT_FANOUT,
        }
    }

    /// Create a new gossip protocol with custom fanout
    pub fn with_fanout(router: Arc<Router>, max_fanout: usize) -> Self {
        Self {
            router,
            seen_broadcasts: Arc::new(Mutex::new(Bloom::new_for_fp_rate(
                BROADCAST_BLOOM_CAPACITY,
                BROADCAST_BLOOM_FP_RATE,
            ))),
            max_fanout,
        }
    }

    /// Broadcast a message to the network
    ///
    /// This marks the message as seen and forwards it to connected peers
    pub async fn broadcast(&self, message: BaseMessage) -> Result<()> {
        // Mark message as seen first
        self.mark_seen(&message.message_id);

        // Use router's broadcast mechanism
        self.router.broadcast_message(message).await
    }

    /// Handle a received broadcast message
    ///
    /// Checks if already seen, and if not:
    /// 1. Marks as seen
    /// 2. Delivers locally (to be implemented in phase with event system)
    /// 3. Forwards to peers
    pub async fn handle_broadcast(
        &self,
        message: BaseMessage,
        source_peer: Option<&NodeId>,
    ) -> Result<()> {
        // Check if already seen
        if self.has_seen(&message.message_id) {
            // Already processed, ignore
            return Ok(());
        }

        // Mark as seen
        self.mark_seen(&message.message_id);

        // TODO: Deliver locally to event handlers (Phase with event system)

        // Forward to peers (excluding source)
        self.forward_to_peers(message, source_peer).await
    }

    /// Forward message to peers, excluding source peer
    async fn forward_to_peers(
        &self,
        message: BaseMessage,
        source_peer: Option<&NodeId>,
    ) -> Result<()> {
        // Get all direct peers
        let mut peers = {
            let routing_table = self.router.routing_table();
            let table = routing_table.read();
            table.get_direct_peers()
        };

        // Remove source peer from list
        if let Some(source) = source_peer {
            peers.retain(|p| p != source);
        }

        if peers.is_empty() {
            return Ok(()); // No peers to forward to
        }

        // Apply fanout limit if configured
        if self.max_fanout > 0 && peers.len() > self.max_fanout {
            // Randomly select subset of peers
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            peers.shuffle(&mut rng);
            peers.truncate(self.max_fanout);
        }

        // Collect connections first to avoid holding lock across await
        let connections: Vec<_> = {
            let table = self.router.routing_table();
            let table_guard = table.read();
            peers
                .iter()
                .filter_map(|peer_id| table_guard.get_direct_connection(peer_id))
                .collect()
        };

        // Send to selected peers sequentially
        for conn in connections {
            let conn_guard = conn.lock().await;
            let _ = conn_guard.send_message(&message).await;
        }

        Ok(())
    }

    /// Check if a message has been seen before
    pub fn has_seen(&self, message_id: &[u8]) -> bool {
        let bloom = self.seen_broadcasts.lock();
        bloom.check(message_id)
    }

    /// Mark a message as seen
    pub fn mark_seen(&self, message_id: &[u8]) {
        let mut bloom = self.seen_broadcasts.lock();
        bloom.set(message_id);
    }

    /// Reset the bloom filter (for maintenance)
    pub fn reset_bloom_filter(&self) {
        let mut bloom = self.seen_broadcasts.lock();
        *bloom = Bloom::new_for_fp_rate(BROADCAST_BLOOM_CAPACITY, BROADCAST_BLOOM_FP_RATE);
    }

    /// Get current fanout setting
    pub fn fanout(&self) -> usize {
        self.max_fanout
    }

    /// Set maximum fanout
    pub fn set_fanout(&mut self, fanout: usize) {
        self.max_fanout = fanout;
    }
}

/// Optimized gossip with epidemic broadcast tree (EBT)
///
/// This is a future optimization that maintains a spanning tree
/// for more efficient broadcast propagation.
pub struct EpidemicBroadcastTree {
    // Placeholder for future implementation
    _marker: std::marker::PhantomData<()>,
}

impl EpidemicBroadcastTree {
    /// Create a new epidemic broadcast tree
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for EpidemicBroadcastTree {
    fn default() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Identity;
    use crate::network::ConnectionPool;
    use crate::protocol::MessageType;
    use rustls::ClientConfig;

    fn create_test_tls_config() -> Arc<rustls::ClientConfig> {
        use rustls::RootCertStore;

        let root_store = RootCertStore::empty();
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Arc::new(config)
    }

    #[tokio::test]
    async fn test_gossip_protocol_creation() {
        let identity = Identity::generate();
        let pool = Arc::new(ConnectionPool::new(100));
        let tls_config = create_test_tls_config();
        let router = Arc::new(Router::new(identity, pool, tls_config));

        let gossip = GossipProtocol::new(Arc::clone(&router));

        assert_eq!(gossip.fanout(), DEFAULT_FANOUT);
    }

    #[tokio::test]
    async fn test_gossip_with_custom_fanout() {
        let identity = Identity::generate();
        let pool = Arc::new(ConnectionPool::new(100));
        let tls_config = create_test_tls_config();
        let router = Arc::new(Router::new(identity, pool, tls_config));

        let gossip = GossipProtocol::with_fanout(Arc::clone(&router), 4);

        assert_eq!(gossip.fanout(), 4);
    }

    #[tokio::test]
    async fn test_mark_message_seen() {
        let identity = Identity::generate();
        let pool = Arc::new(ConnectionPool::new(100));
        let tls_config = create_test_tls_config();
        let router = Arc::new(Router::new(identity, pool, tls_config));

        let gossip = GossipProtocol::new(Arc::clone(&router));

        let message_id = b"unique_message_id_123";

        assert!(!gossip.has_seen(message_id));

        gossip.mark_seen(message_id);

        assert!(gossip.has_seen(message_id));
    }

    #[tokio::test]
    async fn test_duplicate_broadcast_ignored() {
        let identity = Identity::generate();
        let pool = Arc::new(ConnectionPool::new(100));
        let tls_config = create_test_tls_config();
        let router = Arc::new(Router::new(identity, pool, tls_config));

        let gossip = GossipProtocol::new(Arc::clone(&router));

        let message_id = vec![1, 2, 3, 4, 5];

        // Mark as seen
        gossip.mark_seen(&message_id);

        // Should be seen
        assert!(gossip.has_seen(&message_id));
    }

    #[tokio::test]
    async fn test_handle_broadcast_deduplication() {
        let identity = Identity::generate();
        let pool = Arc::new(ConnectionPool::new(100));
        let tls_config = create_test_tls_config();
        let router = Arc::new(Router::new(identity, pool, tls_config));

        let gossip = GossipProtocol::new(Arc::clone(&router));

        let message = BaseMessage {
            version: 1,
            message_id: vec![1, 2, 3, 4],
            message_type: MessageType::Broadcast.into(),
            timestamp: 0,
            sender_public_key: vec![],
            payload: vec![],
            signature: vec![],
            routing_info: None,
        };

        // First time should succeed
        let result = gossip.handle_broadcast(message.clone(), None).await;
        assert!(result.is_ok());

        // Message should now be seen
        assert!(gossip.has_seen(&message.message_id));

        // Second time should also succeed but be ignored internally
        let result = gossip.handle_broadcast(message.clone(), None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_reset_bloom_filter() {
        let identity = Identity::generate();
        let pool = Arc::new(ConnectionPool::new(100));
        let tls_config = create_test_tls_config();
        let router = Arc::new(Router::new(identity, pool, tls_config));

        let gossip = GossipProtocol::new(Arc::clone(&router));

        let message_id = b"test_message";

        gossip.mark_seen(message_id);
        assert!(gossip.has_seen(message_id));

        // Reset the filter
        gossip.reset_bloom_filter();

        // Message should no longer be seen
        assert!(!gossip.has_seen(message_id));
    }

    #[tokio::test]
    async fn test_set_fanout() {
        let identity = Identity::generate();
        let pool = Arc::new(ConnectionPool::new(100));
        let tls_config = create_test_tls_config();
        let router = Arc::new(Router::new(identity, pool, tls_config));

        let mut gossip = GossipProtocol::new(Arc::clone(&router));

        assert_eq!(gossip.fanout(), DEFAULT_FANOUT);

        gossip.set_fanout(16);

        assert_eq!(gossip.fanout(), 16);
    }
}

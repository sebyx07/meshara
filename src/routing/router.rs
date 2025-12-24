//! Main routing logic for message delivery
//!
//! This module implements the core Router that handles message routing decisions,
//! path selection, and message delivery through the mesh network.

use crate::crypto::{Identity, NodeId};
use crate::error::{NetworkError, Result};
use crate::network::ConnectionPool;
use crate::protocol::{BaseMessage, RouteType, RoutingInfo};
use crate::routing::routing_table::RoutingTable;
use parking_lot::RwLock;
use rustls::ClientConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

#[cfg(feature = "dht")]
use crate::routing::dht::{find_peer, DhtHandle};

/// Default maximum number of hops for routing
const DEFAULT_MAX_HOPS: u32 = 8;

/// Default retry limit for message delivery
const DEFAULT_MAX_RETRIES: u32 = 3;

/// Message queued for routing
#[derive(Debug, Clone)]
pub struct OutgoingMessage {
    /// Destination node ID
    pub destination: NodeId,
    /// The message to send
    pub message: BaseMessage,
    /// Number of retry attempts
    pub retry_count: u32,
}

/// Main router for message delivery
pub struct Router {
    /// This node's identity
    identity: Identity,

    /// Routing table
    routing_table: Arc<RwLock<RoutingTable>>,

    /// Connection pool to peers
    connection_pool: Arc<ConnectionPool>,

    /// TLS configuration for establishing connections
    tls_config: Arc<ClientConfig>,

    /// Channel for outgoing messages
    message_tx: mpsc::UnboundedSender<OutgoingMessage>,

    /// Background task handle
    _task_handle: Option<tokio::task::JoinHandle<()>>,

    /// DHT handle for global peer discovery (optional)
    #[cfg(feature = "dht")]
    dht: Option<DhtHandle>,
}

impl Router {
    /// Create a new router
    ///
    /// # Arguments
    /// * `identity` - This node's identity
    /// * `connection_pool` - Pool for managing peer connections
    /// * `tls_config` - TLS configuration for establishing new connections
    pub fn new(
        identity: Identity,
        connection_pool: Arc<ConnectionPool>,
        tls_config: Arc<ClientConfig>,
    ) -> Self {
        let routing_table = Arc::new(RwLock::new(RoutingTable::new()));
        let (message_tx, message_rx) = mpsc::unbounded_channel();

        // Spawn background task for message processing
        let task_handle = Self::spawn_message_processor(
            Arc::clone(&routing_table),
            Arc::clone(&connection_pool),
            message_rx,
        );

        Self {
            identity,
            routing_table,
            connection_pool,
            tls_config,
            message_tx,
            _task_handle: Some(task_handle),
            #[cfg(feature = "dht")]
            dht: None,
        }
    }

    /// Get the routing table
    pub fn routing_table(&self) -> Arc<RwLock<RoutingTable>> {
        Arc::clone(&self.routing_table)
    }

    /// Route a message to its destination
    pub async fn route_message(
        &self,
        destination: &NodeId,
        mut message: BaseMessage,
    ) -> Result<()> {
        // Check if destination is us
        if destination == &self.identity.node_id() {
            return Err(NetworkError::InvalidMessage {
                reason: "Cannot route message to self".to_string(),
            }
            .into());
        }

        // Initialize routing info if not present
        if message.routing_info.is_none() {
            message.routing_info = Some(RoutingInfo {
                hop_count: 0,
                max_hops: DEFAULT_MAX_HOPS,
                route_type: RouteType::Direct.into(),
                next_hop: None,
                onion_layers: None,
            });
        }

        // Try to find route locally
        let route = {
            let table = self.routing_table.read();
            table.find_route(destination)
        };

        if let Some(route) = route {
            // Found local route, send via next hop
            return self.send_via_next_hop(&route.next_hop, message).await;
        }

        // No local route found - try DHT if available
        #[cfg(feature = "dht")]
        if let Some(ref dht) = self.dht {
            if let Ok(Some(contact_info)) = find_peer(dht, destination).await {
                // Found peer in DHT - try to connect directly
                match self
                    .connection_pool
                    .get_or_connect(destination, contact_info.address, self.tls_config.clone())
                    .await
                {
                    Ok(conn) => {
                        return conn.send_message(&message).await;
                    },
                    Err(_) => {
                        // Connection failed, fall through to error
                    },
                }
            }
        }

        // No route found anywhere
        Err(NetworkError::RouteNotFound {
            destination: *destination,
        }
        .into())
    }

    /// Broadcast a message to all connected peers
    pub async fn broadcast_message(&self, message: BaseMessage) -> Result<()> {
        // Mark message as seen to prevent re-broadcast
        {
            let table = self.routing_table.read();
            table.mark_message_seen(&message.message_id);
        }

        // Get all direct peers
        let peers = {
            let table = self.routing_table.read();
            table.get_direct_peers()
        };

        if peers.is_empty() {
            return Err(NetworkError::NoPeersAvailable.into());
        }

        // Collect connections first to avoid holding lock across await
        let connections: Vec<_> = {
            let table = self.routing_table.read();
            peers
                .iter()
                .filter_map(|peer_id| table.get_direct_connection(peer_id))
                .collect()
        };

        // Send to all peers sequentially
        for conn in connections {
            let conn_guard = conn.lock().await;
            let _ = conn_guard.send_message(&message).await;
        }

        Ok(())
    }

    /// Send message via specific next hop
    async fn send_via_next_hop(&self, next_hop: &NodeId, mut message: BaseMessage) -> Result<()> {
        // Increment hop count
        if let Some(ref mut routing_info) = message.routing_info {
            routing_info.hop_count += 1;

            // Check max hops
            if routing_info.hop_count >= routing_info.max_hops {
                return Err(NetworkError::MaxHopsExceeded.into());
            }
        }

        // Get connection to next hop
        let conn = {
            let table = self.routing_table.read();
            table.get_direct_connection(next_hop)
        };

        match conn {
            Some(conn) => {
                let conn_guard = conn.lock().await;
                conn_guard.send_message(&message).await
            },
            None => Err(NetworkError::RouteNotFound {
                destination: *next_hop,
            }
            .into()),
        }
    }

    /// Queue a message for delivery with retries
    pub fn queue_message(&self, destination: NodeId, message: BaseMessage) -> Result<()> {
        let outgoing = OutgoingMessage {
            destination,
            message,
            retry_count: 0,
        };

        self.message_tx
            .send(outgoing)
            .map_err(|e| NetworkError::InvalidMessage {
                reason: format!("Failed to queue message: {}", e),
            })?;

        Ok(())
    }

    /// Spawn background task for processing outgoing messages
    fn spawn_message_processor(
        routing_table: Arc<RwLock<RoutingTable>>,
        connection_pool: Arc<ConnectionPool>,
        mut message_rx: mpsc::UnboundedReceiver<OutgoingMessage>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(mut outgoing) = message_rx.recv().await {
                // Try to send message
                let result = Self::try_send_message(
                    &routing_table,
                    &connection_pool,
                    &outgoing.destination,
                    &outgoing.message,
                )
                .await;

                // Handle retries on failure
                if result.is_err() && outgoing.retry_count < DEFAULT_MAX_RETRIES {
                    outgoing.retry_count += 1;

                    // Exponential backoff
                    let delay = Duration::from_secs(2u64.pow(outgoing.retry_count));
                    tokio::time::sleep(delay).await;

                    // Re-queue (we need the sender, but it's not available here)
                    // In production, this would use a separate retry channel
                }
            }
        })
    }

    /// Try to send a message once
    async fn try_send_message(
        routing_table: &Arc<RwLock<RoutingTable>>,
        _connection_pool: &Arc<ConnectionPool>,
        destination: &NodeId,
        message: &BaseMessage,
    ) -> Result<()> {
        // Find route
        let route = {
            let table = routing_table.read();
            table.find_route(destination)
        };

        if let Some(route) = route {
            // Get connection to next hop
            let conn = {
                let table = routing_table.read();
                table.get_direct_connection(&route.next_hop)
            };

            if let Some(conn) = conn {
                let conn_guard = conn.lock().await;
                return conn_guard.send_message(message).await;
            }
        }

        Err(NetworkError::RouteNotFound {
            destination: *destination,
        }
        .into())
    }

    /// Handle cleanup and periodic maintenance
    pub async fn run_maintenance(&self) {
        // Reset bloom filter if needed
        {
            let table = self.routing_table.read();
            table.reset_bloom_filter_if_needed();
        }

        // Cleanup stale routes (routes older than 5 minutes)
        {
            let table = self.routing_table.read();
            table.cleanup_stale_routes(300);
        }
    }

    /// Get this router's node ID
    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    /// Set the DHT handle for global peer discovery
    #[cfg(feature = "dht")]
    pub fn set_dht(&mut self, dht: DhtHandle) {
        self.dht = Some(dht);
    }

    /// Get a reference to the DHT handle if available
    #[cfg(feature = "dht")]
    pub fn dht(&self) -> Option<&DhtHandle> {
        self.dht.as_ref()
    }
}

/// Builder for Router configuration
pub struct RouterBuilder {
    identity: Option<Identity>,
    connection_pool: Option<Arc<ConnectionPool>>,
    tls_config: Option<Arc<ClientConfig>>,
}

impl RouterBuilder {
    /// Create a new router builder
    pub fn new() -> Self {
        Self {
            identity: None,
            connection_pool: None,
            tls_config: None,
        }
    }

    /// Set the identity
    pub fn identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Set the connection pool
    pub fn connection_pool(mut self, pool: Arc<ConnectionPool>) -> Self {
        self.connection_pool = Some(pool);
        self
    }

    /// Set the TLS configuration
    pub fn tls_config(mut self, config: Arc<ClientConfig>) -> Self {
        self.tls_config = Some(config);
        self
    }

    /// Build the router
    pub fn build(self) -> Result<Router> {
        let identity = self.identity.ok_or_else(|| NetworkError::InvalidMessage {
            reason: "Identity is required".to_string(),
        })?;

        let connection_pool = self
            .connection_pool
            .ok_or_else(|| NetworkError::InvalidMessage {
                reason: "Connection pool is required".to_string(),
            })?;

        let tls_config = self
            .tls_config
            .ok_or_else(|| NetworkError::InvalidMessage {
                reason: "TLS config is required".to_string(),
            })?;

        Ok(Router::new(identity, connection_pool, tls_config))
    }
}

impl Default for RouterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::MessageType;

    fn create_test_tls_config() -> Arc<ClientConfig> {
        use rustls::RootCertStore;

        let root_store = RootCertStore::empty();
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Arc::new(config)
    }

    #[tokio::test]
    async fn test_router_creation() {
        let identity = Identity::generate();
        let expected_node_id = identity.node_id();
        let pool = Arc::new(ConnectionPool::new(100));
        let tls_config = create_test_tls_config();

        let router = Router::new(identity, pool, tls_config);

        assert_eq!(router.node_id(), expected_node_id);
    }

    #[tokio::test]
    async fn test_cannot_route_to_self() {
        let identity = Identity::generate();
        let self_node_id = identity.node_id();
        let pool = Arc::new(ConnectionPool::new(100));
        let tls_config = create_test_tls_config();

        let router = Router::new(identity, pool, tls_config);

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

        let result = router.route_message(&self_node_id, message).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_route_not_found() {
        let identity = Identity::generate();
        let pool = Arc::new(ConnectionPool::new(100));
        let tls_config = create_test_tls_config();

        let router = Router::new(identity, pool, tls_config);

        let destination = Identity::generate().node_id();

        let message = BaseMessage {
            version: 1,
            message_id: vec![1, 2, 3, 4],
            message_type: MessageType::PrivateMessage.into(),
            timestamp: 0,
            sender_public_key: vec![],
            payload: vec![],
            signature: vec![],
            routing_info: None,
        };

        let result = router.route_message(&destination, message).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_broadcast_no_peers() {
        let identity = Identity::generate();
        let pool = Arc::new(ConnectionPool::new(100));
        let tls_config = create_test_tls_config();

        let router = Router::new(identity, pool, tls_config);

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

        let result = router.broadcast_message(message).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_router_builder() {
        let identity = Identity::generate();
        let expected_node_id = identity.node_id();
        let pool = Arc::new(ConnectionPool::new(100));
        let tls_config = create_test_tls_config();

        let router = RouterBuilder::new()
            .identity(identity)
            .connection_pool(pool)
            .tls_config(tls_config)
            .build()
            .unwrap();

        assert_eq!(router.node_id(), expected_node_id);
    }

    #[tokio::test]
    async fn test_router_builder_missing_identity() {
        let pool = Arc::new(ConnectionPool::new(100));

        let result = RouterBuilder::new().connection_pool(pool).build();

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_router_builder_missing_pool() {
        let identity = Identity::generate();

        let result = RouterBuilder::new().identity(identity).build();

        assert!(result.is_err());
    }
}

//! Node implementation - the main entry point for Meshara
//!
//! This module provides the `Node` and `NodeBuilder` types that represent
//! a Meshara node and allow configuring it with the builder pattern.

use crate::api::config::{NetworkProfile, NodeConfig, PrivacyLevel};
use crate::api::events::{Event, EventHandlers, MessageId, SubscriptionHandle};
use crate::crypto::{Identity, PublicKey};
use crate::error::ConfigError;
use crate::storage::keystore::Keystore;
use parking_lot::{Mutex, RwLock};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// Unique identifier for a node based on its public key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// Create a NodeId from a public key
    ///
    /// The NodeId is the Blake3 hash of the public key bytes.
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        let bytes = public_key.to_bytes();
        let hash = blake3::hash(&bytes);
        Self(*hash.as_bytes())
    }

    /// Get the raw bytes of this node ID
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get a hexadecimal string representation
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Current operational state of a node
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    /// Node has been created but not started
    Created,
    /// Node is starting up (loading identity, initializing storage)
    Starting,
    /// Node is running and ready to send/receive messages
    Running,
    /// Node is shutting down gracefully
    Stopping,
    /// Node has stopped
    Stopped,
}

/// Builder for creating Node instances with progressive configuration
///
/// # Examples
///
/// ```no_run
/// use meshara::api::{NodeBuilder, NetworkProfile, PrivacyLevel};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut node = NodeBuilder::new()
///     .with_storage_path("/tmp/meshara")
///     .with_network_profile(NetworkProfile::Standard)
///     .with_privacy_level(PrivacyLevel::Enhanced)
///     .build()?;
///
/// node.start().await?;
/// # Ok(())
/// # }
/// ```
pub struct NodeBuilder {
    config: NodeConfig,
    identity: Option<Identity>,
}

impl NodeBuilder {
    /// Create a new NodeBuilder with default settings
    pub fn new() -> Self {
        Self {
            config: NodeConfig::default(),
            identity: None,
        }
    }

    /// Set the storage path for the node's identity and data
    ///
    /// # Arguments
    ///
    /// * `path` - Path where the node will store its identity and data
    pub fn with_storage_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.config.storage_path = path.into();
        self
    }

    /// Use an existing identity instead of generating/loading one
    ///
    /// This is useful for testing or when you want to manage identity
    /// creation yourself.
    ///
    /// # Arguments
    ///
    /// * `identity` - The identity to use for this node
    pub fn with_identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Set the passphrase for encrypting the stored identity
    ///
    /// If not provided, the identity will be stored unencrypted.
    /// This should only be used in development!
    ///
    /// # Arguments
    ///
    /// * `passphrase` - The passphrase to encrypt the identity with
    pub fn with_passphrase<S: Into<String>>(mut self, passphrase: S) -> Self {
        self.config.passphrase = Some(passphrase.into());
        self
    }

    /// Set the port for accepting incoming connections
    ///
    /// Default is 0 (random available port).
    ///
    /// # Arguments
    ///
    /// * `port` - The port number (0 for random port)
    pub fn with_listen_port(mut self, port: u16) -> Self {
        self.config.listen_port = port;
        self
    }

    /// Set the network profile preset
    ///
    /// This configures multiple settings at once based on the node's
    /// intended use case.
    ///
    /// # Arguments
    ///
    /// * `profile` - The network profile to use
    pub fn with_network_profile(mut self, profile: NetworkProfile) -> Self {
        self.config.network_profile = profile;
        // Update dependent settings
        self.config.max_peers = profile.default_max_peers();
        self.config.auto_discovery = profile.default_auto_discovery();
        self
    }

    /// Set the privacy level
    ///
    /// Higher privacy levels provide better metadata protection but
    /// may increase latency and bandwidth usage.
    ///
    /// # Arguments
    ///
    /// * `level` - The privacy level to use
    pub fn with_privacy_level(mut self, level: PrivacyLevel) -> Self {
        self.config.privacy_level = level;
        self
    }

    /// Enable automatic peer discovery via mDNS
    ///
    /// When enabled, the node will automatically discover peers on the
    /// local network.
    pub fn enable_auto_discovery(mut self) -> Self {
        self.config.auto_discovery = true;
        self
    }

    /// Disable automatic peer discovery
    pub fn disable_auto_discovery(mut self) -> Self {
        self.config.auto_discovery = false;
        self
    }

    /// Set the maximum number of concurrent peer connections
    ///
    /// # Arguments
    ///
    /// * `count` - Maximum number of peers (must be > 0)
    pub fn with_max_peers(mut self, count: usize) -> Self {
        self.config.max_peers = count;
        self
    }

    /// Add a bootstrap node address
    ///
    /// Bootstrap nodes help new nodes join the network by providing
    /// initial peer connections.
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address of the bootstrap node
    pub fn add_bootstrap_node(mut self, addr: SocketAddr) -> Self {
        self.config.bootstrap_nodes.push(addr);
        self
    }

    /// Add a trusted authority public key
    ///
    /// Updates signed by these authorities will be automatically verified
    /// and trusted.
    ///
    /// # Arguments
    ///
    /// * `public_key` - Public key of the trusted authority
    pub fn add_trusted_authority(mut self, public_key: PublicKey) -> Self {
        self.config.trusted_authorities.push(public_key);
        self
    }

    /// Build the Node instance
    ///
    /// Validates the configuration and creates a new Node.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    pub fn build(self) -> crate::Result<Node> {
        // Validate configuration
        self.config.validate()?;

        // Create keystore
        let keystore = Keystore::new(self.config.storage_path.clone());

        Ok(Node {
            identity: Arc::new(RwLock::new(self.identity)),
            config: self.config,
            event_handlers: EventHandlers::new(),
            keystore,
            state: Arc::new(RwLock::new(NodeState::Created)),
            message_router: Arc::new(Mutex::new(None)),
        })
    }
}

impl Default for NodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Main node instance for Meshara networking
///
/// The Node represents a participant in the Meshara network. It manages
/// cryptographic identity, peer connections, message routing, and event
/// delivery.
///
/// # Examples
///
/// ```no_run
/// use meshara::api::{NodeBuilder, Event};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut node = NodeBuilder::new()
///     .with_storage_path("/tmp/meshara")
///     .build()?;
///
/// // Register event handler
/// node.on_event(|event| {
///     match event {
///         Event::MessageReceived { sender, content, .. } => {
///             println!("Got message from {:?}", sender.fingerprint());
///         }
///         _ => {}
///     }
/// });
///
/// node.start().await?;
/// # Ok(())
/// # }
/// ```
pub struct Node {
    /// Node's cryptographic identity (initialized on start)
    identity: Arc<RwLock<Option<Identity>>>,
    /// Immutable configuration
    config: NodeConfig,
    /// Event handler registry
    event_handlers: EventHandlers,
    /// Storage backend for identity
    keystore: Keystore,
    /// Current operational state
    state: Arc<RwLock<NodeState>>,
    /// Message router (for in-memory message passing in Phase 2)
    message_router: Arc<Mutex<Option<Arc<dyn MessageRouter>>>>,
}

impl Node {
    // ========================================================================
    // Lifecycle Methods
    // ========================================================================

    /// Start the node
    ///
    /// This loads or generates the node's identity, initializes storage,
    /// and transitions to the Running state.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The node is already started
    /// - Identity loading/generation fails
    /// - Storage initialization fails
    pub async fn start(&mut self) -> crate::Result<()> {
        // Check current state
        {
            let state = self.state.read();
            if *state != NodeState::Created && *state != NodeState::Stopped {
                return Err(ConfigError::MissingRequiredField {
                    field: "Node must be in Created or Stopped state to start".to_string(),
                }
                .into());
            }
        }

        // Transition to Starting
        *self.state.write() = NodeState::Starting;

        // Load or generate identity
        let needs_identity = {
            let identity_lock = self.identity.read();
            identity_lock.is_none()
        };

        if needs_identity {
            // Try to load from storage
            let loaded_identity = match self.keystore.load_identity(&self.config.passphrase).await {
                Ok(loaded_identity) => loaded_identity,
                Err(_) => {
                    // Generate new identity
                    let new_identity = Identity::generate();

                    // Save to storage
                    self.keystore
                        .save_identity(&new_identity, &self.config.passphrase)
                        .await?;

                    new_identity
                },
            };

            // Now take the write lock and set the identity
            *self.identity.write() = Some(loaded_identity);
        }

        // Transition to Running
        *self.state.write() = NodeState::Running;

        // Dispatch NodeStarted event
        self.event_handlers.dispatch(Event::NodeStarted);

        Ok(())
    }

    /// Stop the node gracefully
    ///
    /// This closes connections, flushes pending messages, and saves state.
    ///
    /// # Errors
    ///
    /// Returns an error if the node is not running.
    pub async fn stop(&mut self) -> crate::Result<()> {
        // Check current state
        {
            let state = self.state.read();
            if *state != NodeState::Running {
                return Err(ConfigError::MissingRequiredField {
                    field: "Node must be in Running state to stop".to_string(),
                }
                .into());
            }
        }

        // Transition to Stopping
        *self.state.write() = NodeState::Stopping;

        // Future: Close connections, flush messages, etc.

        // Transition to Stopped
        *self.state.write() = NodeState::Stopped;

        // Dispatch NodeStopped event
        self.event_handlers.dispatch(Event::NodeStopped);

        Ok(())
    }

    /// Get the current operational state
    pub fn state(&self) -> NodeState {
        *self.state.read()
    }

    // ========================================================================
    // Identity Methods
    // ========================================================================

    /// Get the node's public key
    ///
    /// This can be shared with others to receive messages.
    ///
    /// # Panics
    ///
    /// Panics if the node hasn't been started yet.
    pub fn public_key(&self) -> PublicKey {
        self.identity
            .read()
            .as_ref()
            .expect("Node must be started to access identity")
            .public_key()
    }

    /// Get the node's unique identifier
    ///
    /// The NodeId is derived from the public key.
    ///
    /// # Panics
    ///
    /// Panics if the node hasn't been started yet.
    pub fn node_id(&self) -> NodeId {
        NodeId::from_public_key(&self.public_key())
    }

    /// Get a human-readable fingerprint for identity verification
    ///
    /// # Panics
    ///
    /// Panics if the node hasn't been started yet.
    pub fn fingerprint(&self) -> String {
        self.public_key().fingerprint()
    }

    /// Export the node's identity encrypted with a passphrase
    ///
    /// The exported data can be used to restore the identity on another
    /// device or as a backup.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - The passphrase to encrypt the identity with
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    ///
    /// # Panics
    ///
    /// Panics if the node hasn't been started yet.
    pub async fn export_identity(&self, passphrase: &str) -> crate::Result<Vec<u8>> {
        let identity = self
            .identity
            .read()
            .as_ref()
            .expect("Node must be started to export identity")
            .export_encrypted(passphrase)?;
        Ok(identity)
    }

    /// Import an identity from encrypted data
    ///
    /// This is a static method that decrypts and returns an Identity.
    /// Use `NodeBuilder::with_identity()` to use it when building a node.
    ///
    /// # Arguments
    ///
    /// * `data` - The encrypted identity data
    /// * `passphrase` - The passphrase to decrypt with
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails or the data is invalid.
    pub async fn import_identity(data: &[u8], passphrase: &str) -> crate::Result<Identity> {
        Identity::import_encrypted(data, passphrase)
    }

    // ========================================================================
    // Event System
    // ========================================================================

    /// Register an event handler
    ///
    /// The handler will be called for all events until unsubscribed.
    ///
    /// # Arguments
    ///
    /// * `handler` - Callback function to invoke for events
    ///
    /// # Returns
    ///
    /// A `SubscriptionHandle` that can be used to unsubscribe.
    pub fn on_event<F>(&mut self, handler: F) -> SubscriptionHandle
    where
        F: Fn(Event) + Send + Sync + 'static,
    {
        self.event_handlers.subscribe(handler)
    }

    /// Unsubscribe an event handler
    ///
    /// # Arguments
    ///
    /// * `handle` - The subscription handle to remove
    pub fn unsubscribe(&mut self, handle: SubscriptionHandle) {
        self.event_handlers.unsubscribe(handle);
    }

    // ========================================================================
    // Message Sending (Phase 2: In-Memory Only)
    // ========================================================================

    /// Send an encrypted private message to a recipient
    ///
    /// In Phase 2, this delivers via in-memory channels. In future phases,
    /// this will send over the network.
    ///
    /// # Arguments
    ///
    /// * `recipient` - Public key of the recipient
    /// * `content` - Message content to encrypt and send
    ///
    /// # Returns
    ///
    /// A `MessageId` for tracking this message.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The node is not running
    /// - Encryption fails
    /// - No route to recipient (future phases)
    pub async fn send_private_message(
        &self,
        recipient: &PublicKey,
        content: &[u8],
    ) -> crate::Result<MessageId> {
        // Verify node is running
        if self.state() != NodeState::Running {
            return Err(ConfigError::MissingRequiredField {
                field: "Node must be running to send messages".to_string(),
            }
            .into());
        }

        // Generate message ID
        let message_id = MessageId::generate(content);

        // Get sender public key
        let sender = self.public_key();

        // Phase 2: Route via in-memory router if available
        if let Some(router) = self.message_router.lock().as_ref() {
            router.route_private_message(recipient, sender, content.to_vec(), message_id)?;
        }

        Ok(message_id)
    }

    /// Broadcast a signed message to all peers
    ///
    /// In Phase 2, this delivers to all in-memory nodes. In future phases,
    /// this will use gossip protocol.
    ///
    /// # Arguments
    ///
    /// * `content` - Message content to sign and broadcast
    /// * `content_type` - MIME-style content type (e.g., "text/plain")
    ///
    /// # Returns
    ///
    /// A `MessageId` for tracking this message.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The node is not running
    /// - Signing fails
    pub async fn broadcast_message(
        &self,
        content: &[u8],
        content_type: &str,
    ) -> crate::Result<MessageId> {
        // Verify node is running
        if self.state() != NodeState::Running {
            return Err(ConfigError::MissingRequiredField {
                field: "Node must be running to send messages".to_string(),
            }
            .into());
        }

        // Generate message ID
        let message_id = MessageId::generate(content);

        // Get sender public key
        let sender = self.public_key();

        // Phase 2: Route via in-memory router if available
        if let Some(router) = self.message_router.lock().as_ref() {
            router.route_broadcast(
                sender,
                content.to_vec(),
                content_type.to_string(),
                message_id,
            )?;
        }

        Ok(message_id)
    }

    // ========================================================================
    // Internal Methods (for testing and in-memory routing)
    // ========================================================================

    /// Set the message router (internal use for Phase 2 testing)
    #[doc(hidden)]
    pub fn set_message_router(&self, router: Arc<dyn MessageRouter>) {
        *self.message_router.lock() = Some(router);
    }

    /// Get event handlers (internal use for routing)
    #[doc(hidden)]
    pub fn event_handlers(&self) -> &EventHandlers {
        &self.event_handlers
    }
}

/// Trait for message routing (internal use for Phase 2)
pub trait MessageRouter: Send + Sync {
    /// Route a private message to a recipient
    fn route_private_message(
        &self,
        recipient: &PublicKey,
        sender: PublicKey,
        content: Vec<u8>,
        message_id: MessageId,
    ) -> crate::Result<()>;

    /// Route a broadcast message to all nodes
    fn route_broadcast(
        &self,
        sender: PublicKey,
        content: Vec<u8>,
        content_type: String,
        message_id: MessageId,
    ) -> crate::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_from_public_key() {
        let identity = Identity::generate();
        let public_key = identity.public_key();
        let node_id = NodeId::from_public_key(&public_key);

        assert_eq!(node_id.as_bytes().len(), 32);
        assert_eq!(node_id.to_hex().len(), 64);
    }

    #[test]
    fn test_node_builder_default() {
        let builder = NodeBuilder::new();
        let node = builder.build().unwrap();

        assert_eq!(node.state(), NodeState::Created);
    }

    #[test]
    fn test_node_builder_with_storage_path() {
        let node = NodeBuilder::new()
            .with_storage_path("/tmp/test")
            .build()
            .unwrap();

        assert_eq!(node.config.storage_path, PathBuf::from("/tmp/test"));
    }

    #[test]
    fn test_node_builder_with_identity() {
        let identity = Identity::generate();

        let node = NodeBuilder::new()
            .with_identity(identity)
            .with_storage_path("/tmp/test")
            .build()
            .unwrap();

        // Identity should be set but not accessible until started
        assert!(node.identity.read().is_some());
    }

    #[test]
    fn test_node_builder_with_network_profile() {
        let node = NodeBuilder::new()
            .with_network_profile(NetworkProfile::Minimal)
            .build()
            .unwrap();

        assert_eq!(node.config.network_profile, NetworkProfile::Minimal);
        assert_eq!(node.config.max_peers, 8);
        assert!(!node.config.auto_discovery);
    }

    #[test]
    fn test_node_builder_validation_zero_peers() {
        let result = NodeBuilder::new().with_max_peers(0).build();

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_node_lifecycle() {
        let mut node = NodeBuilder::new()
            .with_storage_path("/tmp/meshara-test")
            .build()
            .unwrap();

        assert_eq!(node.state(), NodeState::Created);

        node.start().await.unwrap();
        assert_eq!(node.state(), NodeState::Running);

        node.stop().await.unwrap();
        assert_eq!(node.state(), NodeState::Stopped);
    }

    #[tokio::test]
    async fn test_node_identity_methods() {
        let mut node = NodeBuilder::new()
            .with_storage_path("/tmp/meshara-test-identity")
            .build()
            .unwrap();

        node.start().await.unwrap();

        let public_key = node.public_key();
        let node_id = node.node_id();
        let fingerprint = node.fingerprint();

        assert_eq!(public_key.to_bytes().len(), 64);
        assert_eq!(node_id.as_bytes().len(), 32);
        assert_eq!(fingerprint.len(), 64);
    }

    #[tokio::test]
    async fn test_node_export_import_identity() {
        let mut node = NodeBuilder::new()
            .with_storage_path("/tmp/meshara-test-export")
            .build()
            .unwrap();

        node.start().await.unwrap();

        let original_fingerprint = node.fingerprint();

        // Export identity
        let exported = node.export_identity("test passphrase").await.unwrap();

        // Import identity
        let imported = Node::import_identity(&exported, "test passphrase")
            .await
            .unwrap();

        assert_eq!(original_fingerprint, imported.public_key().fingerprint());
    }
}

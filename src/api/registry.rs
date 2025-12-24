//! In-memory node registry for testing
//!
//! This module provides a NodeRegistry that enables in-memory message passing
//! between nodes without requiring network connectivity. This is useful for
//! testing and development.

use crate::api::events::{Event, EventHandlers, MessageId};
use crate::api::node::{MessageRouter, Node};
use crate::crypto::PublicKey;
use crate::error::{MesharaError, RoutingError};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::SystemTime;

/// Registry for managing in-memory nodes and routing messages between them
///
/// This allows multiple nodes to communicate in the same process without
/// requiring network connectivity.
///
/// # Examples
///
/// ```no_run
/// use meshara::api::{NodeBuilder, NodeRegistry};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let registry = NodeRegistry::new();
///
/// let mut node_a = NodeBuilder::new()
///     .with_storage_path("/tmp/node-a")
///     .build()?;
/// let mut node_b = NodeBuilder::new()
///     .with_storage_path("/tmp/node-b")
///     .build()?;
///
/// node_a.start().await?;
/// node_b.start().await?;
///
/// // Register nodes with registry
/// registry.register(&node_a);
/// registry.register(&node_b);
///
/// // Now messages sent from node_a will be delivered to node_b in-memory
/// # Ok(())
/// # }
/// ```
pub struct NodeRegistry {
    /// Shared router instance
    router: Arc<InMemoryRouter>,
}

impl NodeRegistry {
    /// Create a new node registry
    pub fn new() -> Self {
        let router = Arc::new(InMemoryRouter {
            handlers: DashMap::new(),
        });

        Self { router }
    }

    /// Register a node with the registry
    ///
    /// After registration, the node will be able to send and receive
    /// messages from other registered nodes.
    ///
    /// # Arguments
    ///
    /// * `node` - The node to register
    pub fn register(&self, node: &Node) {
        let public_key = node.public_key();
        let key_bytes = public_key.to_bytes();

        // Store the event handlers (which are cheaply cloneable)
        let handlers = node.event_handlers().clone();
        self.router.handlers.insert(key_bytes, handlers);

        // Set the router on the node
        node.set_message_router(Arc::clone(&self.router) as Arc<dyn MessageRouter>);
    }

    /// Unregister a node from the registry
    ///
    /// # Arguments
    ///
    /// * `public_key` - Public key of the node to unregister
    pub fn unregister(&self, public_key: &PublicKey) {
        let key_bytes = public_key.to_bytes();
        self.router.handlers.remove(&key_bytes);
    }

    /// Get the number of registered nodes
    pub fn node_count(&self) -> usize {
        self.router.handlers.len()
    }

    /// Clear all registered nodes
    pub fn clear(&self) {
        self.router.handlers.clear();
    }
}

impl Default for NodeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// In-memory message router for testing
struct InMemoryRouter {
    handlers: DashMap<Vec<u8>, EventHandlers>,
}

impl MessageRouter for InMemoryRouter {
    fn route_private_message(
        &self,
        recipient: &PublicKey,
        sender: PublicKey,
        content: Vec<u8>,
        message_id: MessageId,
    ) -> crate::Result<()> {
        let recipient_bytes = recipient.to_bytes();

        // Find the recipient's event handlers
        if let Some(handlers) = self.handlers.get(&recipient_bytes) {
            // Deliver the message as an event
            let event = Event::MessageReceived {
                message_id,
                sender,
                content,
                timestamp: SystemTime::now(),
                verified: true, // In-memory messages are always verified
            };

            handlers.dispatch(event);
            Ok(())
        } else {
            Err(MesharaError::Routing(RoutingError::PeerNotFound {
                peer_id: recipient.fingerprint(),
            }))
        }
    }

    fn route_broadcast(
        &self,
        sender: PublicKey,
        content: Vec<u8>,
        content_type: String,
        message_id: MessageId,
    ) -> crate::Result<()> {
        // Deliver to all nodes except sender
        let sender_bytes = sender.to_bytes();

        for entry in self.handlers.iter() {
            // Skip sender
            if entry.key() == &sender_bytes {
                continue;
            }

            let event = Event::BroadcastReceived {
                message_id,
                sender: sender.clone(),
                content: content.clone(),
                content_type: content_type.clone(),
                verified: true, // In-memory messages are always verified
            };

            entry.value().dispatch(event);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::NodeBuilder;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_registry_register_unregister() {
        let temp_dir = TempDir::new().unwrap();
        let registry = NodeRegistry::new();

        let mut node = NodeBuilder::new()
            .with_storage_path(temp_dir.path().join("node"))
            .build()
            .unwrap();

        node.start().await.unwrap();

        assert_eq!(registry.node_count(), 0);

        let public_key = node.public_key();
        registry.register(&node);
        assert_eq!(registry.node_count(), 1);

        registry.unregister(&public_key);
        assert_eq!(registry.node_count(), 0);
    }

    #[tokio::test]
    async fn test_in_memory_private_message() {
        let temp_dir = TempDir::new().unwrap();
        let registry = NodeRegistry::new();

        // Create two nodes
        let mut node_a = NodeBuilder::new()
            .with_storage_path(temp_dir.path().join("node-a"))
            .build()
            .unwrap();

        let mut node_b = NodeBuilder::new()
            .with_storage_path(temp_dir.path().join("node-b"))
            .build()
            .unwrap();

        node_a.start().await.unwrap();
        node_b.start().await.unwrap();

        // Register both nodes
        registry.register(&node_a);
        registry.register(&node_b);

        // Set up message counter for node_b
        let received_count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&received_count);

        node_b.on_event(move |event| {
            if let Event::MessageReceived { .. } = event {
                count_clone.fetch_add(1, Ordering::SeqCst);
            }
        });

        // Send message from node_a to node_b
        let recipient = node_b.public_key();
        node_a
            .send_private_message(&recipient, b"Hello, Node B!")
            .await
            .unwrap();

        // Give time for message delivery
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Verify message was received
        assert_eq!(received_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_in_memory_broadcast() {
        let temp_dir = TempDir::new().unwrap();
        let registry = NodeRegistry::new();

        // Create three nodes
        let mut node_a = NodeBuilder::new()
            .with_storage_path(temp_dir.path().join("node-a"))
            .build()
            .unwrap();

        let mut node_b = NodeBuilder::new()
            .with_storage_path(temp_dir.path().join("node-b"))
            .build()
            .unwrap();

        let mut node_c = NodeBuilder::new()
            .with_storage_path(temp_dir.path().join("node-c"))
            .build()
            .unwrap();

        node_a.start().await.unwrap();
        node_b.start().await.unwrap();
        node_c.start().await.unwrap();

        // Register all nodes
        registry.register(&node_a);
        registry.register(&node_b);
        registry.register(&node_c);

        // Set up message counters
        let b_count = Arc::new(AtomicUsize::new(0));
        let c_count = Arc::new(AtomicUsize::new(0));

        let b_count_clone = Arc::clone(&b_count);
        node_b.on_event(move |event| {
            if let Event::BroadcastReceived { .. } = event {
                b_count_clone.fetch_add(1, Ordering::SeqCst);
            }
        });

        let c_count_clone = Arc::clone(&c_count);
        node_c.on_event(move |event| {
            if let Event::BroadcastReceived { .. } = event {
                c_count_clone.fetch_add(1, Ordering::SeqCst);
            }
        });

        // Broadcast from node_a
        node_a
            .broadcast_message(b"Hello, everyone!", "text/plain")
            .await
            .unwrap();

        // Give time for message delivery
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Verify both node_b and node_c received the broadcast
        assert_eq!(b_count.load(Ordering::SeqCst), 1);
        assert_eq!(c_count.load(Ordering::SeqCst), 1);
    }
}

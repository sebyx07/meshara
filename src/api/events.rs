//! Event system for asynchronous message delivery
//!
//! This module defines the event types and event handler mechanism that
//! allows applications to receive notifications about messages, state changes,
//! and errors.

use crate::crypto::PublicKey;
use crate::error::MesharaError;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::SystemTime;

/// Unique identifier for a message
///
/// This is a Blake3 hash that uniquely identifies a message in the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageId([u8; 32]);

impl MessageId {
    /// Generate a new message ID from message content
    ///
    /// Uses Blake3 to hash the content plus a timestamp.
    pub fn generate(content: &[u8]) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let mut hasher = blake3::Hasher::new();
        hasher.update(content);
        hasher.update(&now.to_le_bytes());
        let hash = hasher.finalize();

        Self(*hash.as_bytes())
    }

    /// Create a message ID from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes of this message ID
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get a hexadecimal string representation
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Events that can be delivered to application handlers
#[derive(Debug, Clone)]
pub enum Event {
    /// A private encrypted message was received
    MessageReceived {
        /// Unique identifier for this message
        message_id: MessageId,
        /// Public key of the sender
        sender: PublicKey,
        /// Decrypted message content
        content: Vec<u8>,
        /// Time when message was received
        timestamp: SystemTime,
        /// Whether the signature was verified successfully
        verified: bool,
    },

    /// A broadcast message was received
    BroadcastReceived {
        /// Unique identifier for this message
        message_id: MessageId,
        /// Public key of the sender
        sender: PublicKey,
        /// Message content
        content: Vec<u8>,
        /// Content type identifier (e.g., "text/plain", "application/json")
        content_type: String,
        /// Whether the signature was verified successfully
        verified: bool,
    },

    /// Node has started successfully
    NodeStarted,

    /// Node has stopped
    NodeStopped,

    /// An error occurred during node operation
    Error {
        /// The error that occurred
        error: MesharaError,
    },
}

/// Handle for unsubscribing from events
///
/// When dropped, the associated event handler will NOT be automatically
/// unsubscribed. You must explicitly call `Node::unsubscribe()` to remove
/// the handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriptionHandle(u64);

impl SubscriptionHandle {
    /// Create a new subscription handle with the given ID
    pub(crate) fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the numeric ID of this handle
    #[allow(dead_code)]
    pub(crate) fn id(&self) -> u64 {
        self.0
    }
}

/// Type alias for event handler callbacks
pub type EventCallback = Arc<dyn Fn(Event) + Send + Sync + 'static>;

/// Manages event subscriptions and delivery
///
/// This structure maintains a list of registered event handlers and
/// provides methods to dispatch events to all subscribers.
pub struct EventHandlers {
    /// Map of subscription handles to callbacks
    handlers: Arc<RwLock<Vec<(SubscriptionHandle, EventCallback)>>>,
    /// Counter for generating unique subscription handles
    next_id: Arc<RwLock<u64>>,
}

impl EventHandlers {
    /// Create a new event handler registry
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(RwLock::new(Vec::new())),
            next_id: Arc::new(RwLock::new(0)),
        }
    }

    /// Register a new event handler
    ///
    /// The handler will be called for all future events until unsubscribed.
    ///
    /// # Arguments
    ///
    /// * `callback` - The callback function to invoke for events
    ///
    /// # Returns
    ///
    /// A `SubscriptionHandle` that can be used to unsubscribe later.
    pub fn subscribe<F>(&self, callback: F) -> SubscriptionHandle
    where
        F: Fn(Event) + Send + Sync + 'static,
    {
        let mut next_id = self.next_id.write();
        let id = *next_id;
        *next_id += 1;

        let handle = SubscriptionHandle::new(id);
        let callback_arc = Arc::new(callback);

        let mut handlers = self.handlers.write();
        handlers.push((handle, callback_arc));

        handle
    }

    /// Unsubscribe an event handler
    ///
    /// Removes the handler associated with the given subscription handle.
    /// If the handle is not found, this is a no-op.
    ///
    /// # Arguments
    ///
    /// * `handle` - The subscription handle to remove
    pub fn unsubscribe(&self, handle: SubscriptionHandle) {
        let mut handlers = self.handlers.write();
        handlers.retain(|(h, _)| *h != handle);
    }

    /// Dispatch an event to all registered handlers
    ///
    /// Handlers are called in the order they were registered.
    /// If a handler panics, the panic is caught and logged, but other
    /// handlers will still be called.
    ///
    /// # Arguments
    ///
    /// * `event` - The event to deliver to all handlers
    pub fn dispatch(&self, event: Event) {
        let handlers = self.handlers.read();

        for (handle, callback) in handlers.iter() {
            // Clone the event for each handler
            let event_clone = event.clone();

            // Call the handler, catching any panics
            if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                callback(event_clone);
            })) {
                tracing::error!(
                    "Event handler {:?} panicked: {:?}",
                    handle,
                    e.downcast_ref::<&str>()
                        .copied()
                        .or_else(|| e.downcast_ref::<String>().map(|s| s.as_str()))
                        .unwrap_or("unknown panic")
                );
            }
        }
    }

    /// Get the number of registered handlers
    pub fn handler_count(&self) -> usize {
        self.handlers.read().len()
    }
}

impl Default for EventHandlers {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for EventHandlers {
    fn clone(&self) -> Self {
        Self {
            handlers: Arc::clone(&self.handlers),
            next_id: Arc::clone(&self.next_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[test]
    fn test_message_id_generation() {
        let id1 = MessageId::generate(b"hello");
        let id2 = MessageId::generate(b"hello");

        // Different IDs even for same content (due to timestamp)
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_message_id_hex() {
        let id = MessageId::from_bytes([
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let hex = id.to_hex();
        assert!(hex.starts_with("123456789abcdef0"));
    }

    #[test]
    fn test_event_handlers_subscribe() {
        let handlers = EventHandlers::new();
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);

        let _handle = handlers.subscribe(move |_event| {
            called_clone.store(true, Ordering::SeqCst);
        });

        handlers.dispatch(Event::NodeStarted);
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_event_handlers_multiple_subscribers() {
        let handlers = EventHandlers::new();
        let count = Arc::new(AtomicUsize::new(0));

        let count1 = Arc::clone(&count);
        let _handle1 = handlers.subscribe(move |_event| {
            count1.fetch_add(1, Ordering::SeqCst);
        });

        let count2 = Arc::clone(&count);
        let _handle2 = handlers.subscribe(move |_event| {
            count2.fetch_add(1, Ordering::SeqCst);
        });

        handlers.dispatch(Event::NodeStarted);
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_event_handlers_unsubscribe() {
        let handlers = EventHandlers::new();
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);

        let handle = handlers.subscribe(move |_event| {
            called_clone.store(true, Ordering::SeqCst);
        });

        handlers.unsubscribe(handle);
        handlers.dispatch(Event::NodeStarted);

        assert!(!called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_event_handlers_count() {
        let handlers = EventHandlers::new();
        assert_eq!(handlers.handler_count(), 0);

        let h1 = handlers.subscribe(|_| {});
        assert_eq!(handlers.handler_count(), 1);

        let h2 = handlers.subscribe(|_| {});
        assert_eq!(handlers.handler_count(), 2);

        handlers.unsubscribe(h1);
        assert_eq!(handlers.handler_count(), 1);

        handlers.unsubscribe(h2);
        assert_eq!(handlers.handler_count(), 0);
    }

    #[test]
    fn test_event_handlers_panic_isolation() {
        let handlers = EventHandlers::new();
        let count = Arc::new(AtomicUsize::new(0));

        // Handler that panics
        let _handle1 = handlers.subscribe(|_event| {
            panic!("Handler panic");
        });

        // Handler that should still run
        let count_clone = Arc::clone(&count);
        let _handle2 = handlers.subscribe(move |_event| {
            count_clone.fetch_add(1, Ordering::SeqCst);
        });

        handlers.dispatch(Event::NodeStarted);

        // Second handler should have been called despite first panic
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}

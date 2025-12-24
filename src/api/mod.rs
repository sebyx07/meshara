//! High-level API for Meshara
//!
//! This module provides the public-facing API that developers use to interact
//! with Meshara nodes. The API is designed to be simple, type-safe, and async-first.

pub mod config;
pub mod events;
pub mod node;
pub mod registry;

// Re-export main types for convenience
pub use crate::crypto::NodeId;
pub use config::{NetworkProfile, NodeConfig, PrivacyLevel};
pub use events::{Event, MessageId, SubscriptionHandle};
pub use node::{Node, NodeBuilder, NodeState};
pub use registry::NodeRegistry;

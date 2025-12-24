//! Routing subsystem for Meshara network
//!
//! This module provides intelligent message routing through the mesh network,
//! including:
//! - Direct routing to connected peers
//! - Multi-hop routing through intermediate nodes
//! - Gossip protocol for broadcast propagation
//! - Message deduplication and loop prevention
//! - Route discovery and maintenance
//!
//! # Architecture
//!
//! The routing system consists of several components:
//!
//! - **Router**: Main routing engine that handles message delivery decisions
//! - **RoutingTable**: Stores routes and provides message deduplication
//! - **GossipProtocol**: Implements epidemic broadcast propagation
//! - **Forwarding**: Handles message forwarding and hop count management
//!
//! # Example
//!
//! ```no_run
//! use meshara::crypto::Identity;
//! use meshara::network::ConnectionPool;
//! use meshara::routing::Router;
//! use std::sync::Arc;
//!
//! # async fn example() -> meshara::error::Result<()> {
//! let identity = Identity::generate();
//! let pool = Arc::new(ConnectionPool::new());
//!
//! let router = Router::new(identity, pool);
//!
//! // Router is now ready to route messages
//! # Ok(())
//! # }
//! ```
//!
//! # Routing Strategies
//!
//! ## Direct Routing
//!
//! When a direct connection exists to the destination, the message is sent
//! directly in a single hop.
//!
//! ## Multi-Hop Routing
//!
//! When no direct connection exists, the router consults the routing table
//! to find the next hop toward the destination. Messages are forwarded
//! hop-by-hop until they reach their destination or exceed the maximum
//! hop count.
//!
//! ## Broadcast via Gossip
//!
//! Broadcast messages are propagated using an epidemic gossip protocol.
//! Each node forwards the broadcast to its connected peers (excluding the
//! source), with deduplication to prevent loops.
//!
//! # Message Deduplication
//!
//! Both the routing table and gossip protocol use Bloom filters for efficient
//! message deduplication. This prevents routing loops and redundant processing
//! of broadcast messages.
//!
//! # Route Discovery
//!
//! Routes are learned through:
//! 1. Direct connections to peers
//! 2. Route advertisements from peers
//! 3. Implicit learning from received messages
//!
//! Routes are periodically refreshed and stale routes are removed.

mod forwarding;
mod gossip;
mod router;
mod routing_table;

#[cfg(feature = "dht")]
mod dht;

// Public exports
pub use forwarding::{
    calculate_route_cost, handle_received_message, increment_hop_count, should_forward_message,
    validate_routing_info,
};
pub use gossip::{EpidemicBroadcastTree, GossipProtocol};
pub use router::{OutgoingMessage, Router, RouterBuilder};
pub use routing_table::{Route, RoutingTable};

#[cfg(feature = "dht")]
pub use dht::{advertise_self, find_peer, ContactInfo, DhtHandle, DhtNode};

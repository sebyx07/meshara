//! Routing table management for Meshara network
//!
//! This module provides the core routing table data structure that maintains
//! information about network topology, known routes, and message deduplication.

use crate::crypto::NodeId;
use crate::network::Connection;
use bloomfilter::Bloom;
use dashmap::DashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;
use tokio::sync::Mutex as TokioMutex;

/// Default Bloom filter capacity (1 million messages)
const BLOOM_CAPACITY: usize = 1_000_000;

/// Default Bloom filter false positive rate (1%)
const BLOOM_FP_RATE: f64 = 0.01;

/// Information about a route to a destination node
#[derive(Debug, Clone)]
pub struct Route {
    /// Destination node ID
    pub destination: NodeId,
    /// Next hop node ID (who to send to)
    pub next_hop: NodeId,
    /// Number of hops to reach destination
    pub hop_count: u32,
    /// When this route was last updated
    pub last_updated: Instant,
    /// Route quality metric (lower is better)
    pub cost: f64,
}

impl Route {
    /// Create a new route
    pub fn new(destination: NodeId, next_hop: NodeId, hop_count: u32) -> Self {
        Self {
            destination,
            next_hop,
            hop_count,
            last_updated: Instant::now(),
            cost: hop_count as f64,
        }
    }

    /// Update the route with new information
    pub fn update(&mut self, hop_count: u32) {
        self.hop_count = hop_count;
        self.last_updated = Instant::now();
        self.cost = hop_count as f64;
    }

    /// Check if this route is stale (older than timeout)
    pub fn is_stale(&self, timeout_secs: u64) -> bool {
        self.last_updated.elapsed().as_secs() > timeout_secs
    }
}

/// Routing table that maintains network topology and message deduplication
pub struct RoutingTable {
    /// Direct connections to peers (node_id -> connection)
    direct: DashMap<NodeId, Arc<TokioMutex<Connection>>>,

    /// Multi-hop routes (destination -> route)
    routes: DashMap<NodeId, Route>,

    /// Bloom filter for message deduplication
    seen_messages: Arc<StdMutex<Bloom<[u8]>>>,

    /// When the bloom filter was last reset
    bloom_reset_time: Arc<StdMutex<Instant>>,
}

impl RoutingTable {
    /// Create a new routing table
    pub fn new() -> Self {
        Self {
            direct: DashMap::new(),
            routes: DashMap::new(),
            seen_messages: Arc::new(StdMutex::new(Bloom::new_for_fp_rate(
                BLOOM_CAPACITY,
                BLOOM_FP_RATE,
            ))),
            bloom_reset_time: Arc::new(StdMutex::new(Instant::now())),
        }
    }

    /// Add a direct connection to a peer
    pub fn add_direct_route(&self, node_id: NodeId, conn: Arc<TokioMutex<Connection>>) {
        self.direct.insert(node_id, conn);

        // Also add as a 1-hop route
        let route = Route::new(node_id, node_id, 1);
        self.routes.insert(node_id, route);
    }

    /// Remove a route (typically when peer disconnects)
    pub fn remove_route(&self, node_id: &NodeId) {
        self.direct.remove(node_id);
        self.routes.remove(node_id);

        // Remove routes that go through this node
        self.routes
            .retain(|_dest, route| &route.next_hop != node_id);
    }

    /// Find a route to the destination
    pub fn find_route(&self, destination: &NodeId) -> Option<Route> {
        self.routes.get(destination).map(|r| r.clone())
    }

    /// Get direct connection to a peer
    pub fn get_direct_connection(&self, node_id: &NodeId) -> Option<Arc<TokioMutex<Connection>>> {
        self.direct.get(node_id).map(|c| c.clone())
    }

    /// Add or update a multi-hop route
    pub fn add_route(&self, destination: NodeId, next_hop: NodeId, hop_count: u32) {
        self.routes
            .entry(destination)
            .and_modify(|route| {
                // Only update if this route is better (fewer hops or fresher)
                if hop_count < route.hop_count
                    || (hop_count == route.hop_count && route.is_stale(60))
                {
                    route.next_hop = next_hop;
                    route.update(hop_count);
                }
            })
            .or_insert_with(|| Route::new(destination, next_hop, hop_count));
    }

    /// Check if a message has been seen before
    pub fn has_seen_message(&self, message_id: &[u8]) -> bool {
        let bloom = self.seen_messages.lock().unwrap();
        bloom.check(message_id)
    }

    /// Mark a message as seen
    pub fn mark_message_seen(&self, message_id: &[u8]) {
        let mut bloom = self.seen_messages.lock().unwrap();
        bloom.set(message_id);
    }

    /// Reset the bloom filter (periodically to prevent saturation)
    pub fn reset_bloom_filter_if_needed(&self) {
        let mut reset_time = self.bloom_reset_time.lock().unwrap();

        // Reset every hour
        if reset_time.elapsed().as_secs() > 3600 {
            let mut bloom = self.seen_messages.lock().unwrap();
            *bloom = Bloom::new_for_fp_rate(BLOOM_CAPACITY, BLOOM_FP_RATE);
            *reset_time = Instant::now();
        }
    }

    /// Get all known direct peers
    pub fn get_direct_peers(&self) -> Vec<NodeId> {
        self.direct.iter().map(|entry| *entry.key()).collect()
    }

    /// Get all known routes
    pub fn get_all_routes(&self) -> Vec<Route> {
        self.routes
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Remove stale routes older than timeout
    pub fn cleanup_stale_routes(&self, timeout_secs: u64) {
        self.routes
            .retain(|_dest, route| !route.is_stale(timeout_secs));
    }

    /// Get the number of known routes
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Get the number of direct connections
    pub fn direct_connection_count(&self) -> usize {
        self.direct.len()
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Identity;

    #[test]
    fn test_routing_table_creation() {
        let table = RoutingTable::new();
        assert_eq!(table.route_count(), 0);
        assert_eq!(table.direct_connection_count(), 0);
    }

    // Note: Tests for add_direct_route and remove_route require actual Connection objects
    // which are complex to mock. These should be covered by integration tests.

    #[test]
    fn test_add_multi_hop_route() {
        let table = RoutingTable::new();

        let dest_id = Identity::generate().node_id();
        let next_hop_id = Identity::generate().node_id();

        table.add_route(dest_id, next_hop_id, 3);

        let route = table.find_route(&dest_id);
        assert!(route.is_some());

        let route = route.unwrap();
        assert_eq!(route.destination, dest_id);
        assert_eq!(route.next_hop, next_hop_id);
        assert_eq!(route.hop_count, 3);
    }

    #[test]
    fn test_route_update_prefers_shorter() {
        let table = RoutingTable::new();

        let dest_id = Identity::generate().node_id();
        let next_hop1 = Identity::generate().node_id();
        let next_hop2 = Identity::generate().node_id();

        // Add route with 5 hops
        table.add_route(dest_id, next_hop1, 5);

        let route = table.find_route(&dest_id).unwrap();
        assert_eq!(route.hop_count, 5);

        // Add better route with 3 hops
        table.add_route(dest_id, next_hop2, 3);

        let route = table.find_route(&dest_id).unwrap();
        assert_eq!(route.hop_count, 3);
        assert_eq!(route.next_hop, next_hop2);
    }

    #[test]
    fn test_route_update_ignores_worse() {
        let table = RoutingTable::new();

        let dest_id = Identity::generate().node_id();
        let next_hop1 = Identity::generate().node_id();
        let next_hop2 = Identity::generate().node_id();

        // Add route with 3 hops
        table.add_route(dest_id, next_hop1, 3);

        // Try to add worse route with 5 hops
        table.add_route(dest_id, next_hop2, 5);

        // Should keep the better route
        let route = table.find_route(&dest_id).unwrap();
        assert_eq!(route.hop_count, 3);
        assert_eq!(route.next_hop, next_hop1);
    }

    #[test]
    fn test_message_deduplication() {
        let table = RoutingTable::new();

        let message_id1 = b"message_id_1_unique";
        let message_id2 = b"message_id_2_unique";

        // First time seeing message
        assert!(!table.has_seen_message(message_id1));

        // Mark as seen
        table.mark_message_seen(message_id1);

        // Should now be seen
        assert!(table.has_seen_message(message_id1));

        // Different message should not be seen
        assert!(!table.has_seen_message(message_id2));
    }

    #[test]
    fn test_remove_routes_through_node() {
        let table = RoutingTable::new();

        let next_hop = Identity::generate().node_id();
        let dest1 = Identity::generate().node_id();
        let dest2 = Identity::generate().node_id();
        let dest3 = Identity::generate().node_id();
        let other_hop = Identity::generate().node_id();

        // Add routes through next_hop
        table.add_route(dest1, next_hop, 2);
        table.add_route(dest2, next_hop, 3);

        // Add route through different hop
        table.add_route(dest3, other_hop, 2);

        assert_eq!(table.route_count(), 3);

        // Remove next_hop
        table.remove_route(&next_hop);

        // Routes through next_hop should be gone
        assert!(table.find_route(&dest1).is_none());
        assert!(table.find_route(&dest2).is_none());

        // Route through other_hop should remain
        assert!(table.find_route(&dest3).is_some());
    }

    // Note: test_get_direct_peers requires actual Connection objects
    // which are complex to mock. Should be covered by integration tests.

    #[test]
    fn test_route_is_stale() {
        let mut route = Route::new(
            Identity::generate().node_id(),
            Identity::generate().node_id(),
            1,
        );

        // Fresh route should not be stale
        assert!(!route.is_stale(60));

        // Manually set old timestamp
        route.last_updated = Instant::now() - std::time::Duration::from_secs(120);

        // Now it should be stale
        assert!(route.is_stale(60));
    }
}

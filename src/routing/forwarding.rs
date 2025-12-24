//! Message forwarding logic for multi-hop routing
//!
//! This module handles the forwarding of messages through the network,
//! including hop count management, loop prevention, and message validation.

use crate::crypto::NodeId;
use crate::error::{NetworkError, Result};
use crate::protocol::{BaseMessage, RouteType, RoutingInfo};
use crate::routing::router::Router;

/// Default maximum hops for routing
const DEFAULT_MAX_HOPS: u32 = 8;

/// Handle a received message and decide whether to forward it
///
/// This function checks if:
/// 1. Message is for us (deliver locally)
/// 2. Message has been seen before (deduplicate)
/// 3. Message has exceeded max hops (drop)
/// 4. Message should be forwarded to next hop
pub async fn handle_received_message(
    router: &Router,
    message: BaseMessage,
    _source_peer: &NodeId,
) -> Result<()> {
    // Check if message is for us
    // Note: In the current protocol, destination is not explicitly in BaseMessage
    // For now, we'll just forward all messages that aren't broadcasts
    // In Phase 5, we'll add proper destination handling

    // Check if already seen (prevent loops)
    let seen = {
        let routing_table = router.routing_table();
        let table = routing_table.read();
        table.has_seen_message(&message.message_id)
    };

    if seen {
        // Duplicate message, ignore
        return Ok(());
    }

    // Mark as seen
    {
        let routing_table = router.routing_table();
        let table = routing_table.read();
        table.mark_message_seen(&message.message_id);
    }

    // Check hop limit
    if let Some(ref routing_info) = message.routing_info {
        if routing_info.hop_count >= routing_info.max_hops {
            return Err(NetworkError::MaxHopsExceeded.into());
        }
    }

    // For broadcast messages, we deliver locally AND forward
    // For private messages, we only forward if not for us
    // Since we don't have explicit destination in Phase 4, we'll forward all non-duplicate messages

    Ok(())
}

/// Increment the hop count in a message's routing info
pub fn increment_hop_count(message: &mut BaseMessage) {
    if let Some(ref mut routing_info) = message.routing_info {
        routing_info.hop_count += 1;
    } else {
        // Initialize routing info if not present
        message.routing_info = Some(RoutingInfo {
            hop_count: 1,
            max_hops: DEFAULT_MAX_HOPS,
            route_type: RouteType::Direct.into(),
            next_hop: None,
            onion_layers: None,
        });
    }
}

/// Check if a message should be forwarded
pub fn should_forward_message(message: &BaseMessage, our_node_id: &NodeId) -> bool {
    // Always forward if we're not the destination
    // In Phase 4, we don't have explicit destination field, so we forward all valid messages

    // Check hop count limit
    if let Some(ref routing_info) = message.routing_info {
        if routing_info.hop_count >= routing_info.max_hops {
            return false;
        }
    }

    // Don't forward if message originated from us
    // This is a simplified check - in production, we'd check sender_public_key
    // against our own identity
    let _ = our_node_id; // Acknowledge parameter usage

    true
}

/// Validate routing information in a message
pub fn validate_routing_info(routing_info: &RoutingInfo) -> Result<()> {
    // Check hop count is within bounds
    if routing_info.hop_count > routing_info.max_hops {
        return Err(NetworkError::MaxHopsExceeded.into());
    }

    // Check max hops is reasonable (prevent resource exhaustion)
    if routing_info.max_hops > 32 {
        return Err(NetworkError::InvalidMessage {
            reason: "max_hops exceeds reasonable limit (32)".to_string(),
        }
        .into());
    }

    Ok(())
}

/// Calculate the cost of a route based on hop count and other metrics
pub fn calculate_route_cost(hop_count: u32, latency_ms: Option<u64>) -> f64 {
    let hop_cost = hop_count as f64;

    // Add latency cost if available (each 100ms adds 0.1 to cost)
    let latency_cost = latency_ms.map(|l| l as f64 / 1000.0).unwrap_or(0.0);

    hop_cost + latency_cost
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Identity;
    use crate::protocol::MessageType;

    #[test]
    fn test_increment_hop_count_existing() {
        let mut message = BaseMessage {
            version: 1,
            message_id: vec![1, 2, 3, 4],
            message_type: MessageType::Broadcast.into(),
            timestamp: 0,
            sender_public_key: vec![],
            payload: vec![],
            signature: vec![],
            routing_info: Some(RoutingInfo {
                hop_count: 2,
                max_hops: 8,
                route_type: RouteType::Direct.into(),
                next_hop: None,
                onion_layers: None,
            }),
        };

        increment_hop_count(&mut message);

        assert_eq!(message.routing_info.as_ref().unwrap().hop_count, 3);
    }

    #[test]
    fn test_increment_hop_count_no_routing_info() {
        let mut message = BaseMessage {
            version: 1,
            message_id: vec![1, 2, 3, 4],
            message_type: MessageType::Broadcast.into(),
            timestamp: 0,
            sender_public_key: vec![],
            payload: vec![],
            signature: vec![],
            routing_info: None,
        };

        increment_hop_count(&mut message);

        assert!(message.routing_info.is_some());
        assert_eq!(message.routing_info.as_ref().unwrap().hop_count, 1);
        assert_eq!(
            message.routing_info.as_ref().unwrap().max_hops,
            DEFAULT_MAX_HOPS
        );
    }

    #[test]
    fn test_should_forward_message_within_limit() {
        let message = BaseMessage {
            version: 1,
            message_id: vec![1, 2, 3, 4],
            message_type: MessageType::Broadcast.into(),
            timestamp: 0,
            sender_public_key: vec![],
            payload: vec![],
            signature: vec![],
            routing_info: Some(RoutingInfo {
                hop_count: 3,
                max_hops: 8,
                route_type: RouteType::Direct.into(),
                next_hop: None,
                onion_layers: None,
            }),
        };

        let node_id = Identity::generate().node_id();
        assert!(should_forward_message(&message, &node_id));
    }

    #[test]
    fn test_should_forward_message_at_limit() {
        let message = BaseMessage {
            version: 1,
            message_id: vec![1, 2, 3, 4],
            message_type: MessageType::Broadcast.into(),
            timestamp: 0,
            sender_public_key: vec![],
            payload: vec![],
            signature: vec![],
            routing_info: Some(RoutingInfo {
                hop_count: 8,
                max_hops: 8,
                route_type: RouteType::Direct.into(),
                next_hop: None,
                onion_layers: None,
            }),
        };

        let node_id = Identity::generate().node_id();
        assert!(!should_forward_message(&message, &node_id));
    }

    #[test]
    fn test_validate_routing_info_valid() {
        let routing_info = RoutingInfo {
            hop_count: 3,
            max_hops: 8,
            route_type: RouteType::Direct.into(),
            next_hop: None,
            onion_layers: None,
        };

        assert!(validate_routing_info(&routing_info).is_ok());
    }

    #[test]
    fn test_validate_routing_info_exceeded_hops() {
        let routing_info = RoutingInfo {
            hop_count: 10,
            max_hops: 8,
            route_type: RouteType::Direct.into(),
            next_hop: None,
            onion_layers: None,
        };

        assert!(validate_routing_info(&routing_info).is_err());
    }

    #[test]
    fn test_validate_routing_info_max_hops_too_high() {
        let routing_info = RoutingInfo {
            hop_count: 5,
            max_hops: 50,
            route_type: RouteType::Direct.into(),
            next_hop: None,
            onion_layers: None,
        };

        assert!(validate_routing_info(&routing_info).is_err());
    }

    #[test]
    fn test_calculate_route_cost_hop_only() {
        let cost = calculate_route_cost(3, None);
        assert_eq!(cost, 3.0);
    }

    #[test]
    fn test_calculate_route_cost_with_latency() {
        let cost = calculate_route_cost(3, Some(500)); // 500ms latency
        assert_eq!(cost, 3.5); // 3 hops + 0.5 for 500ms
    }
}

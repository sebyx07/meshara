//! Protocol module
//!
//! This module provides Protocol Buffer message definitions and serialization utilities
//! for all Meshara network communication. All message types use Protocol Buffers for
//! efficient, type-safe binary serialization with forward/backward compatibility.

// Suppress missing docs warning for generated protobuf code
#[allow(missing_docs)]
mod meshara;

pub mod versioning;

use prost::Message;
use thiserror::Error;

// Re-export all Protocol Buffer types for public API
pub use meshara::{
    Acknowledgment, BaseMessage, BroadcastPayload, MessageType, PrivateMessagePayload,
    QueryMessage, ResponseCode, ResponseMessage, RouteAdvertisement, RouteEntry, RouteType,
    RoutingInfo, UpdateAnnouncement, UpdateChunk, UpdatePackage, UpdateRequest,
};

// Re-export versioning types and utilities
pub use versioning::{
    check_version_compatibility, is_message_type_supported, message_type_phase, validate_message,
    MessageValidationResult, VersionCompatibility, PROTOCOL_VERSION as VERSIONING_PROTOCOL_VERSION,
};

/// Protocol-level errors
#[derive(Error, Debug, Clone, PartialEq)]
pub enum ProtocolError {
    /// Failed to serialize message to bytes
    #[error("Failed to serialize message: {0}")]
    SerializationFailed(String),

    /// Failed to deserialize bytes to message
    #[error("Failed to deserialize message: {0}")]
    DeserializationFailed(String),

    /// Invalid message type received
    #[error("Invalid message type: {0}")]
    InvalidMessageType(i32),

    /// Unsupported protocol version
    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u32),

    /// Invalid field value in message
    #[error("Invalid field value: {0}")]
    InvalidFieldValue(String),

    /// Message size exceeds maximum allowed
    #[error("Message too large: {0} bytes (max: {1} bytes)")]
    MessageTooLarge(usize, usize),

    /// Message truncated or corrupted
    #[error("Message truncated or corrupted")]
    MessageCorrupted,
}

/// Maximum message size (10 MB)
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Current protocol version
pub const PROTOCOL_VERSION: u32 = 1;

/// Serialize a Protocol Buffer message to bytes
///
/// # Arguments
/// * `message` - The message to serialize
///
/// # Returns
/// * `Ok(Vec<u8>)` - Serialized message bytes
/// * `Err(ProtocolError)` - If serialization fails
///
/// # Example
/// ```
/// use meshara::protocol::{BaseMessage, serialize_message};
///
/// let msg = BaseMessage {
///     version: 1,
///     message_id: vec![0u8; 32],
///     message_type: 0,
///     timestamp: 0,
///     sender_public_key: vec![0u8; 32],
///     payload: vec![],
///     signature: vec![0u8; 64],
///     routing_info: None,
/// };
///
/// let bytes = serialize_message(&msg).unwrap();
/// ```
pub fn serialize_message<T: Message>(message: &T) -> Result<Vec<u8>, ProtocolError> {
    let mut buf = Vec::new();

    // Try to encode the message
    message
        .encode(&mut buf)
        .map_err(|e| ProtocolError::SerializationFailed(format!("prost encode error: {}", e)))?;

    // Check size limit
    if buf.len() > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::MessageTooLarge(buf.len(), MAX_MESSAGE_SIZE));
    }

    Ok(buf)
}

/// Deserialize bytes to a Protocol Buffer message
///
/// # Arguments
/// * `bytes` - The bytes to deserialize
///
/// # Returns
/// * `Ok(T)` - Deserialized message
/// * `Err(ProtocolError)` - If deserialization fails
///
/// # Example
/// ```
/// use meshara::protocol::{BaseMessage, deserialize_message};
///
/// let bytes = vec![/* ... */];
/// let msg: BaseMessage = deserialize_message(&bytes).unwrap();
/// ```
pub fn deserialize_message<T: Message + Default>(bytes: &[u8]) -> Result<T, ProtocolError> {
    // Check size limit
    if bytes.len() > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::MessageTooLarge(
            bytes.len(),
            MAX_MESSAGE_SIZE,
        ));
    }

    // Decode the message
    // Note: Empty bytes are valid in protobuf and decode to default values
    T::decode(bytes)
        .map_err(|e| ProtocolError::DeserializationFailed(format!("prost decode error: {}", e)))
}

/// Validate a BaseMessage
///
/// Checks that all required fields are present and valid
pub fn validate_base_message(msg: &BaseMessage) -> Result<(), ProtocolError> {
    // Check protocol version
    if msg.version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(msg.version));
    }

    // Check message_id length (should be 32 bytes for Blake3)
    if msg.message_id.len() != 32 {
        return Err(ProtocolError::InvalidFieldValue(format!(
            "message_id must be 32 bytes, got {}",
            msg.message_id.len()
        )));
    }

    // Check sender_public_key length (should be 32 bytes for Ed25519)
    if msg.sender_public_key.len() != 32 {
        return Err(ProtocolError::InvalidFieldValue(format!(
            "sender_public_key must be 32 bytes, got {}",
            msg.sender_public_key.len()
        )));
    }

    // Check signature length (should be 64 bytes for Ed25519)
    if msg.signature.len() != 64 {
        return Err(ProtocolError::InvalidFieldValue(format!(
            "signature must be 64 bytes, got {}",
            msg.signature.len()
        )));
    }

    // Validate message type
    MessageType::try_from(msg.message_type)
        .map_err(|_| ProtocolError::InvalidMessageType(msg.message_type))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize_base_message() {
        let msg = BaseMessage {
            version: PROTOCOL_VERSION,
            message_id: vec![0u8; 32],
            message_type: MessageType::PrivateMessage as i32,
            timestamp: 1234567890,
            sender_public_key: vec![1u8; 32],
            payload: vec![2u8; 100],
            signature: vec![3u8; 64],
            routing_info: None,
        };

        // Serialize
        let bytes = serialize_message(&msg).unwrap();
        assert!(!bytes.is_empty());

        // Deserialize
        let decoded: BaseMessage = deserialize_message(&bytes).unwrap();
        assert_eq!(decoded.version, msg.version);
        assert_eq!(decoded.message_id, msg.message_id);
        assert_eq!(decoded.message_type, msg.message_type);
        assert_eq!(decoded.timestamp, msg.timestamp);
        assert_eq!(decoded.sender_public_key, msg.sender_public_key);
        assert_eq!(decoded.payload, msg.payload);
        assert_eq!(decoded.signature, msg.signature);
    }

    #[test]
    fn test_serialize_deserialize_private_message_payload() {
        let msg = PrivateMessagePayload {
            content: b"Hello, Meshara!".to_vec(),
            return_path: vec![],
            ephemeral_public_key: vec![5u8; 32],
            nonce: vec![6u8; 12],
        };

        let bytes = serialize_message(&msg).unwrap();
        let decoded: PrivateMessagePayload = deserialize_message(&bytes).unwrap();

        assert_eq!(decoded.content, msg.content);
        assert_eq!(decoded.ephemeral_public_key, msg.ephemeral_public_key);
        assert_eq!(decoded.nonce, msg.nonce);
    }

    #[test]
    fn test_serialize_deserialize_broadcast_payload() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("author".to_string(), "alice".to_string());
        metadata.insert("topic".to_string(), "announcements".to_string());

        let msg = BroadcastPayload {
            content: b"Public announcement".to_vec(),
            content_type: "text/plain".to_string(),
            metadata,
        };

        let bytes = serialize_message(&msg).unwrap();
        let decoded: BroadcastPayload = deserialize_message(&bytes).unwrap();

        assert_eq!(decoded.content, msg.content);
        assert_eq!(decoded.content_type, msg.content_type);
        assert_eq!(decoded.metadata.len(), 2);
    }

    #[test]
    fn test_serialize_deserialize_update_package() {
        let msg = UpdatePackage {
            version: "1.2.3".to_string(),
            package_data: vec![10u8; 1000],
            changelog: "Fixed bugs".to_string(),
            checksum: vec![11u8; 32],
            required_version: "1.0.0".to_string(),
            signatures: vec![vec![12u8; 64], vec![13u8; 64]],
            authority_public_keys: vec![vec![14u8; 32], vec![15u8; 32]],
        };

        let bytes = serialize_message(&msg).unwrap();
        let decoded: UpdatePackage = deserialize_message(&bytes).unwrap();

        assert_eq!(decoded.version, msg.version);
        assert_eq!(decoded.package_data.len(), msg.package_data.len());
        assert_eq!(decoded.signatures.len(), 2);
        assert_eq!(decoded.authority_public_keys.len(), 2);
    }

    #[test]
    fn test_serialize_deserialize_query_message() {
        let msg = QueryMessage {
            query_id: vec![20u8; 32],
            query_type: "check_update".to_string(),
            query_data: b"version=1.0.0".to_vec(),
            response_required: true,
            timeout_ms: 5000,
        };

        let bytes = serialize_message(&msg).unwrap();
        let decoded: QueryMessage = deserialize_message(&bytes).unwrap();

        assert_eq!(decoded.query_id, msg.query_id);
        assert_eq!(decoded.query_type, msg.query_type);
        assert_eq!(decoded.timeout_ms, msg.timeout_ms);
    }

    #[test]
    fn test_serialize_deserialize_response_message() {
        let msg = ResponseMessage {
            query_id: vec![20u8; 32],
            response_data: b"update_available=true".to_vec(),
            response_code: ResponseCode::Success as i32,
        };

        let bytes = serialize_message(&msg).unwrap();
        let decoded: ResponseMessage = deserialize_message(&bytes).unwrap();

        assert_eq!(decoded.query_id, msg.query_id);
        assert_eq!(decoded.response_data, msg.response_data);
        assert_eq!(decoded.response_code, ResponseCode::Success as i32);
    }

    #[test]
    fn test_deserialize_invalid_data() {
        let garbage = vec![255u8; 100];
        let result: Result<BaseMessage, _> = deserialize_message(&garbage);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_empty_data() {
        let empty: &[u8] = &[];
        let result: Result<BaseMessage, _> = deserialize_message(empty);
        // Empty data successfully deserializes to a default message in protobuf
        // This is expected behavior - an empty protobuf is valid and decodes to all default values
        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg.version, 0); // Default value
        assert_eq!(msg.message_id.len(), 0); // Default empty vec
    }

    #[test]
    fn test_message_too_large() {
        let huge_msg = BaseMessage {
            version: PROTOCOL_VERSION,
            message_id: vec![0u8; 32],
            message_type: MessageType::PrivateMessage as i32,
            timestamp: 1234567890,
            sender_public_key: vec![1u8; 32],
            payload: vec![0u8; MAX_MESSAGE_SIZE + 1],
            signature: vec![3u8; 64],
            routing_info: None,
        };

        let result = serialize_message(&huge_msg);
        assert!(matches!(result, Err(ProtocolError::MessageTooLarge(_, _))));
    }

    #[test]
    fn test_validate_base_message() {
        let valid_msg = BaseMessage {
            version: PROTOCOL_VERSION,
            message_id: vec![0u8; 32],
            message_type: MessageType::PrivateMessage as i32,
            timestamp: 1234567890,
            sender_public_key: vec![1u8; 32],
            payload: vec![2u8; 100],
            signature: vec![3u8; 64],
            routing_info: None,
        };

        assert!(validate_base_message(&valid_msg).is_ok());

        // Test invalid version
        let mut invalid_msg = valid_msg.clone();
        invalid_msg.version = 999;
        assert!(matches!(
            validate_base_message(&invalid_msg),
            Err(ProtocolError::UnsupportedVersion(999))
        ));

        // Test invalid message_id length
        let mut invalid_msg = valid_msg.clone();
        invalid_msg.message_id = vec![0u8; 16]; // Wrong length
        assert!(matches!(
            validate_base_message(&invalid_msg),
            Err(ProtocolError::InvalidFieldValue(_))
        ));

        // Test invalid signature length
        let mut invalid_msg = valid_msg.clone();
        invalid_msg.signature = vec![0u8; 32]; // Wrong length
        assert!(matches!(
            validate_base_message(&invalid_msg),
            Err(ProtocolError::InvalidFieldValue(_))
        ));
    }

    #[test]
    fn test_routing_info_serialization() {
        let routing = RoutingInfo {
            hop_count: 2,
            max_hops: 5,
            route_type: RouteType::Bridge as i32,
            next_hop: Some(vec![30u8; 32]),
            onion_layers: None,
        };

        let msg = BaseMessage {
            version: PROTOCOL_VERSION,
            message_id: vec![0u8; 32],
            message_type: MessageType::PrivateMessage as i32,
            timestamp: 1234567890,
            sender_public_key: vec![1u8; 32],
            payload: vec![2u8; 100],
            signature: vec![3u8; 64],
            routing_info: Some(routing),
        };

        let bytes = serialize_message(&msg).unwrap();
        let decoded: BaseMessage = deserialize_message(&bytes).unwrap();

        assert!(decoded.routing_info.is_some());
        let routing = decoded.routing_info.unwrap();
        assert_eq!(routing.hop_count, 2);
        assert_eq!(routing.max_hops, 5);
        assert_eq!(routing.route_type, RouteType::Bridge as i32);
    }

    #[test]
    fn test_all_response_codes() {
        assert_eq!(ResponseCode::Success as i32, 0);
        assert_eq!(ResponseCode::NotFound as i32, 1);
        assert_eq!(ResponseCode::Error as i32, 2);
        assert_eq!(ResponseCode::Timeout as i32, 3);
        assert_eq!(ResponseCode::Unauthorized as i32, 4);
    }

    #[test]
    fn test_all_message_types() {
        assert_eq!(MessageType::Broadcast as i32, 0);
        assert_eq!(MessageType::PrivateMessage as i32, 1);
        assert_eq!(MessageType::UpdatePackage as i32, 2);
        assert_eq!(MessageType::Query as i32, 3);
        assert_eq!(MessageType::Response as i32, 4);
    }

    #[test]
    fn test_all_route_types() {
        assert_eq!(RouteType::Direct as i32, 0);
        assert_eq!(RouteType::Bridge as i32, 1);
        assert_eq!(RouteType::OnionRouted as i32, 2);
    }

    #[test]
    fn test_serialize_deserialize_route_advertisement() {
        let routes = vec![
            RouteEntry {
                node_id: vec![50u8; 32],
                hop_count: 1,
                last_seen: 1234567890,
            },
            RouteEntry {
                node_id: vec![51u8; 32],
                hop_count: 2,
                last_seen: 1234567900,
            },
        ];

        let msg = RouteAdvertisement { routes };

        let bytes = serialize_message(&msg).unwrap();
        let decoded: RouteAdvertisement = deserialize_message(&bytes).unwrap();

        assert_eq!(decoded.routes.len(), 2);
        assert_eq!(decoded.routes[0].hop_count, 1);
        assert_eq!(decoded.routes[1].hop_count, 2);
    }

    #[test]
    fn test_serialize_deserialize_acknowledgment() {
        let msg = Acknowledgment {
            message_id: vec![60u8; 32],
            success: true,
            error_message: None,
        };

        let bytes = serialize_message(&msg).unwrap();
        let decoded: Acknowledgment = deserialize_message(&bytes).unwrap();

        assert_eq!(decoded.message_id, msg.message_id);
        assert!(decoded.success);
        assert_eq!(decoded.error_message, None);

        // Test with error message
        let msg_with_error = Acknowledgment {
            message_id: vec![61u8; 32],
            success: false,
            error_message: Some("Processing failed".to_string()),
        };

        let bytes = serialize_message(&msg_with_error).unwrap();
        let decoded: Acknowledgment = deserialize_message(&bytes).unwrap();

        assert!(!decoded.success);
        assert_eq!(decoded.error_message, Some("Processing failed".to_string()));
    }

    #[test]
    fn test_serialize_deserialize_update_announcement() {
        let msg = UpdateAnnouncement {
            version: "2.0.0".to_string(),
            update_id: vec![70u8; 32],
            size: 1048576, // 1 MB
            checksum: vec![71u8; 32],
            signatures: vec![vec![72u8; 64], vec![73u8; 64]],
        };

        let bytes = serialize_message(&msg).unwrap();
        let decoded: UpdateAnnouncement = deserialize_message(&bytes).unwrap();

        assert_eq!(decoded.version, msg.version);
        assert_eq!(decoded.update_id, msg.update_id);
        assert_eq!(decoded.size, 1048576);
        assert_eq!(decoded.signatures.len(), 2);
    }

    #[test]
    fn test_serialize_deserialize_update_request() {
        let msg = UpdateRequest {
            update_id: vec![80u8; 32],
            chunk_index: 42,
        };

        let bytes = serialize_message(&msg).unwrap();
        let decoded: UpdateRequest = deserialize_message(&bytes).unwrap();

        assert_eq!(decoded.update_id, msg.update_id);
        assert_eq!(decoded.chunk_index, 42);
    }

    #[test]
    fn test_serialize_deserialize_update_chunk() {
        let chunk_data = vec![90u8; 65536]; // 64 KB chunk

        let msg = UpdateChunk {
            update_id: vec![85u8; 32],
            chunk_index: 5,
            total_chunks: 20,
            data: chunk_data.clone(),
            chunk_hash: vec![86u8; 32],
        };

        let bytes = serialize_message(&msg).unwrap();
        let decoded: UpdateChunk = deserialize_message(&bytes).unwrap();

        assert_eq!(decoded.update_id, msg.update_id);
        assert_eq!(decoded.chunk_index, 5);
        assert_eq!(decoded.total_chunks, 20);
        assert_eq!(decoded.data.len(), 65536);
        assert_eq!(decoded.chunk_hash, msg.chunk_hash);
    }

    #[test]
    fn test_all_new_message_types() {
        // Verify all new message type enum values
        assert_eq!(MessageType::RouteAdvertisement as i32, 5);
        assert_eq!(MessageType::Acknowledgment as i32, 6);
        assert_eq!(MessageType::UpdateAnnouncement as i32, 7);
        assert_eq!(MessageType::UpdateRequest as i32, 8);
        assert_eq!(MessageType::UpdateChunk as i32, 9);
    }
}

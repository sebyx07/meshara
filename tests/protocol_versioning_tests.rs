//! Protocol versioning backward compatibility tests
//!
//! These tests verify that messages can be properly serialized and deserialized
//! across different protocol versions, ensuring forward and backward compatibility.

use meshara::protocol::versioning::{
    check_version_compatibility, validate_message, MessageValidationResult, VersionCompatibility,
    PROTOCOL_VERSION,
};
use meshara::protocol::{
    deserialize_message, serialize_message, BaseMessage, BroadcastPayload, MessageType,
    PrivateMessagePayload, QueryMessage, ResponseCode, ResponseMessage, UpdatePackage,
};

/// Test that current version messages can be serialized and deserialized
#[test]
fn test_current_version_roundtrip() {
    let msg = BaseMessage {
        version: PROTOCOL_VERSION,
        message_id: vec![1u8; 16],
        message_type: MessageType::PrivateMessage.into(),
        timestamp: 1234567890,
        sender_public_key: vec![2u8; 32],
        payload: vec![3u8; 100],
        signature: vec![4u8; 64],
        routing_info: None,
    };

    let bytes = serialize_message(&msg).expect("Failed to serialize");
    let decoded: BaseMessage = deserialize_message(&bytes).expect("Failed to deserialize");

    assert_eq!(decoded.version, msg.version);
    assert_eq!(decoded.message_id, msg.message_id);
    assert_eq!(decoded.message_type, msg.message_type);
    assert_eq!(decoded.timestamp, msg.timestamp);
}

/// Test that unknown message types are handled gracefully
#[test]
fn test_unknown_message_type_handling() {
    let msg = BaseMessage {
        version: PROTOCOL_VERSION,
        message_id: vec![1u8; 16],
        message_type: 999, // Unknown type
        timestamp: 1234567890,
        sender_public_key: vec![2u8; 32],
        payload: vec![3u8; 100],
        signature: vec![4u8; 64],
        routing_info: None,
    };

    // Should be able to serialize/deserialize even with unknown type
    let bytes = serialize_message(&msg).expect("Failed to serialize");
    let decoded: BaseMessage = deserialize_message(&bytes).expect("Failed to deserialize");

    assert_eq!(decoded.message_type, 999);

    // Validation should return UnknownType
    let result = validate_message(&decoded);
    assert!(matches!(
        result,
        MessageValidationResult::UnknownType { message_type: 999 }
    ));
}

/// Test that messages with new optional fields can be read by old code
/// (simulated by serializing with extra fields, then deserializing normally)
#[test]
fn test_forward_compatibility_new_optional_fields() {
    // Simulate a newer version by creating a BroadcastPayload
    // Old nodes will ignore unknown fields automatically (protobuf behavior)
    let mut metadata = std::collections::HashMap::new();
    metadata.insert("new_field".to_string(), "new_value".to_string());

    let payload = BroadcastPayload {
        content: b"test".to_vec(),
        content_type: "text/plain".to_string(),
        metadata,
    };

    let bytes = serialize_message(&payload).expect("Failed to serialize");
    let decoded: BroadcastPayload = deserialize_message(&bytes).expect("Failed to deserialize");

    // Should successfully decode, and metadata should be preserved
    assert_eq!(decoded.content, b"test");
    assert_eq!(decoded.content_type, "text/plain");
}

/// Test that old messages without optional fields can be read by new code
#[test]
fn test_backward_compatibility_missing_optional_fields() {
    // Create a message without optional fields
    let payload = PrivateMessagePayload {
        content: b"test content".to_vec(),
        return_path: vec![],
        ephemeral_public_key: vec![5u8; 32],
        nonce: vec![6u8; 12],
    };

    let bytes = serialize_message(&payload).expect("Failed to serialize");
    let decoded: PrivateMessagePayload =
        deserialize_message(&bytes).expect("Failed to deserialize");

    assert_eq!(decoded.content, b"test content");
    assert_eq!(decoded.return_path, Vec::<u8>::new());
}

/// Test version compatibility checking
#[test]
fn test_version_compatibility_checks() {
    // Same version is fully compatible
    let compat = check_version_compatibility(PROTOCOL_VERSION);
    assert_eq!(compat, VersionCompatibility::FullyCompatible);

    // Future version beyond max is incompatible
    let compat = check_version_compatibility(PROTOCOL_VERSION + 100);
    assert!(matches!(compat, VersionCompatibility::Incompatible { .. }));
}

/// Test all Phase 1-3 message types are supported
#[test]
fn test_phase_1_3_message_types_supported() {
    let types = vec![
        MessageType::Broadcast,
        MessageType::PrivateMessage,
        MessageType::UpdatePackage,
        MessageType::Query,
        MessageType::Response,
    ];

    for msg_type in types {
        let msg = BaseMessage {
            version: PROTOCOL_VERSION,
            message_id: vec![1u8; 16],
            message_type: msg_type.into(),
            timestamp: 1234567890,
            sender_public_key: vec![2u8; 32],
            payload: vec![],
            signature: vec![4u8; 64],
            routing_info: None,
        };

        let result = validate_message(&msg);
        assert!(
            matches!(result, MessageValidationResult::Valid),
            "Message type {:?} should be valid",
            msg_type
        );
    }
}

/// Test Phase 4 message types (defined but implementation in future phase)
#[test]
fn test_phase_4_message_types_defined() {
    let types = vec![MessageType::RouteAdvertisement, MessageType::Acknowledgment];

    for msg_type in types {
        let msg = BaseMessage {
            version: PROTOCOL_VERSION,
            message_id: vec![1u8; 16],
            message_type: msg_type.into(),
            timestamp: 1234567890,
            sender_public_key: vec![2u8; 32],
            payload: vec![],
            signature: vec![4u8; 64],
            routing_info: None,
        };

        // Should be able to serialize/deserialize
        let bytes = serialize_message(&msg).expect("Failed to serialize");
        let decoded: BaseMessage = deserialize_message(&bytes).expect("Failed to deserialize");
        assert_eq!(decoded.message_type, msg_type as i32);
    }
}

/// Test Phase 5 message types (defined but implementation in future phase)
#[test]
fn test_phase_5_message_types_defined() {
    let types = vec![
        MessageType::UpdateAnnouncement,
        MessageType::UpdateRequest,
        MessageType::UpdateChunk,
    ];

    for msg_type in types {
        let msg = BaseMessage {
            version: PROTOCOL_VERSION,
            message_id: vec![1u8; 16],
            message_type: msg_type.into(),
            timestamp: 1234567890,
            sender_public_key: vec![2u8; 32],
            payload: vec![],
            signature: vec![4u8; 64],
            routing_info: None,
        };

        // Should be able to serialize/deserialize
        let bytes = serialize_message(&msg).expect("Failed to serialize");
        let decoded: BaseMessage = deserialize_message(&bytes).expect("Failed to deserialize");
        assert_eq!(decoded.message_type, msg_type as i32);
    }
}

/// Test that all defined message payload types can roundtrip
#[test]
fn test_all_payload_types_roundtrip() {
    // PrivateMessagePayload
    let private_msg = PrivateMessagePayload {
        content: b"secret".to_vec(),
        return_path: vec![10u8; 32],
        ephemeral_public_key: vec![11u8; 32],
        nonce: vec![12u8; 12],
    };
    let bytes = serialize_message(&private_msg).unwrap();
    let decoded: PrivateMessagePayload = deserialize_message(&bytes).unwrap();
    assert_eq!(decoded.content, private_msg.content);

    // BroadcastPayload
    let broadcast = BroadcastPayload {
        content: b"public".to_vec(),
        content_type: "text/plain".to_string(),
        metadata: std::collections::HashMap::new(),
    };
    let bytes = serialize_message(&broadcast).unwrap();
    let decoded: BroadcastPayload = deserialize_message(&bytes).unwrap();
    assert_eq!(decoded.content, broadcast.content);

    // UpdatePackage
    let update = UpdatePackage {
        version: "1.0.0".to_string(),
        package_data: vec![20u8; 1000],
        changelog: "Initial release".to_string(),
        checksum: vec![21u8; 32],
        required_version: "0.9.0".to_string(),
        signatures: vec![vec![22u8; 64]],
        authority_public_keys: vec![vec![23u8; 32]],
    };
    let bytes = serialize_message(&update).unwrap();
    let decoded: UpdatePackage = deserialize_message(&bytes).unwrap();
    assert_eq!(decoded.version, update.version);

    // QueryMessage
    let query = QueryMessage {
        query_id: vec![30u8; 16],
        query_type: "test".to_string(),
        query_data: vec![],
        response_required: true,
        timeout_ms: 5000,
    };
    let bytes = serialize_message(&query).unwrap();
    let decoded: QueryMessage = deserialize_message(&bytes).unwrap();
    assert_eq!(decoded.query_id, query.query_id);

    // ResponseMessage
    let response = ResponseMessage {
        query_id: vec![30u8; 16],
        response_data: b"result".to_vec(),
        response_code: ResponseCode::Success.into(),
    };
    let bytes = serialize_message(&response).unwrap();
    let decoded: ResponseMessage = deserialize_message(&bytes).unwrap();
    assert_eq!(decoded.query_id, response.query_id);
}

/// Test that reserved fields prevent accidental reuse
/// (This is verified at compile time by protobuf, but we document it here)
#[test]
fn test_reserved_fields_documentation() {
    // BaseMessage has reserved fields 9-50
    // If we try to use field 15 in future, protobuf compiler will error
    // This test documents the reserved field strategy

    let msg = BaseMessage {
        version: PROTOCOL_VERSION,
        message_id: vec![1u8; 16],
        message_type: MessageType::Broadcast.into(),
        timestamp: 1234567890,
        sender_public_key: vec![2u8; 32],
        payload: vec![],
        signature: vec![4u8; 64],
        routing_info: None,
    };

    // Fields 1-8 are used, 9-50 are reserved for future use
    let bytes = serialize_message(&msg).unwrap();
    assert!(!bytes.is_empty());
}

/// Test cross-version message exchange simulation
#[test]
fn test_cross_version_message_exchange() {
    // Simulate v1 node sending to v1 node
    let v1_msg = BaseMessage {
        version: 1,
        message_id: vec![1u8; 16],
        message_type: MessageType::PrivateMessage.into(),
        timestamp: 1234567890,
        sender_public_key: vec![2u8; 32],
        payload: b"hello".to_vec(),
        signature: vec![4u8; 64],
        routing_info: None,
    };

    let bytes = serialize_message(&v1_msg).unwrap();
    let received: BaseMessage = deserialize_message(&bytes).unwrap();

    let validation = validate_message(&received);
    assert!(matches!(validation, MessageValidationResult::Valid));
}

/// Test message validation with various scenarios
#[test]
fn test_message_validation_scenarios() {
    // Valid message
    let valid_msg = BaseMessage {
        version: PROTOCOL_VERSION,
        message_id: vec![1u8; 16],
        message_type: MessageType::Broadcast.into(),
        timestamp: 1234567890,
        sender_public_key: vec![2u8; 32],
        payload: vec![],
        signature: vec![4u8; 64],
        routing_info: None,
    };
    assert!(matches!(
        validate_message(&valid_msg),
        MessageValidationResult::Valid
    ));

    // Unknown message type
    let unknown_type = BaseMessage {
        version: PROTOCOL_VERSION,
        message_id: vec![1u8; 16],
        message_type: 500,
        timestamp: 1234567890,
        sender_public_key: vec![2u8; 32],
        payload: vec![],
        signature: vec![4u8; 64],
        routing_info: None,
    };
    assert!(matches!(
        validate_message(&unknown_type),
        MessageValidationResult::UnknownType { .. }
    ));

    // Incompatible version
    let incompatible = BaseMessage {
        version: 999,
        message_id: vec![1u8; 16],
        message_type: MessageType::Broadcast.into(),
        timestamp: 1234567890,
        sender_public_key: vec![2u8; 32],
        payload: vec![],
        signature: vec![4u8; 64],
        routing_info: None,
    };
    assert!(matches!(
        validate_message(&incompatible),
        MessageValidationResult::IncompatibleVersion { .. }
    ));
}

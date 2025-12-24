//! Message construction and parsing
//!
//! This module provides internal APIs for constructing and parsing Meshara protocol messages.
//! It combines cryptographic operations with Protocol Buffer serialization to create complete,
//! signed, and (optionally) encrypted messages.

use crate::crypto::{
    decrypt_message, encrypt_for_recipient, hash_message, sign_message, verify_signature,
    EncryptedMessage, Identity, MessageId, PublicKey,
};
use crate::error::{CryptoError, ProtocolError};
use crate::protocol::{
    deserialize_message, serialize_message, validate_base_message, BaseMessage, BroadcastPayload,
    MessageType, PrivateMessagePayload, PROTOCOL_VERSION,
};
use crate::Result;
use std::time::{SystemTime, UNIX_EPOCH};

/// Helper to convert protocol module errors to error module errors
#[allow(dead_code)]
fn convert_protocol_error(e: crate::protocol::ProtocolError, message_type: &str) -> ProtocolError {
    match e {
        crate::protocol::ProtocolError::SerializationFailed(msg) => {
            ProtocolError::SerializationFailed {
                message_type: message_type.to_string(),
                reason: msg,
            }
        },
        crate::protocol::ProtocolError::DeserializationFailed(msg) => {
            ProtocolError::DeserializationFailed { reason: msg }
        },
        crate::protocol::ProtocolError::MessageTooLarge(size, max) => {
            ProtocolError::SerializationFailed {
                message_type: message_type.to_string(),
                reason: format!("Message too large: {} bytes (max: {} bytes)", size, max),
            }
        },
        crate::protocol::ProtocolError::InvalidFieldValue(msg) => {
            ProtocolError::InvalidFieldValue {
                field: "unknown".to_string(),
                reason: msg,
            }
        },
        _ => ProtocolError::SerializationFailed {
            message_type: message_type.to_string(),
            reason: e.to_string(),
        },
    }
}

/// Maximum timestamp skew: messages with timestamps more than 5 minutes in the future are rejected
#[allow(dead_code)]
const MAX_FUTURE_SKEW_MS: i64 = 5 * 60 * 1000;

/// Maximum message age: messages older than 24 hours are rejected
#[allow(dead_code)]
const MAX_MESSAGE_AGE_MS: i64 = 24 * 60 * 60 * 1000;

/// Parsed message types
#[derive(Debug, Clone)]
pub enum ParsedMessage {
    /// A decrypted private message
    PrivateMessage {
        /// Unique identifier for this message
        message_id: MessageId,
        /// Public key of the sender
        sender: PublicKey,
        /// Decrypted message content
        content: Vec<u8>,
        /// Timestamp when message was created (milliseconds since Unix epoch)
        timestamp: i64,
        /// Whether the signature was verified successfully
        verified: bool,
    },

    /// A broadcast message (not encrypted)
    Broadcast {
        /// Unique identifier for this message
        message_id: MessageId,
        /// Public key of the sender
        sender: PublicKey,
        /// Message content (plaintext)
        content: Vec<u8>,
        /// Content type identifier (e.g., "text/plain", "application/json")
        content_type: String,
        /// Timestamp when message was created (milliseconds since Unix epoch)
        timestamp: i64,
        /// Whether the signature was verified successfully
        verified: bool,
    },
}

/// Internal API for constructing protocol messages
#[allow(dead_code)]
pub(crate) struct MessageBuilder {
    identity: Identity,
}

#[allow(dead_code)]
impl MessageBuilder {
    /// Create a new MessageBuilder with the given identity
    pub fn new(identity: Identity) -> Self {
        Self { identity }
    }

    /// Build a private encrypted message
    ///
    /// # Arguments
    /// * `recipient` - The recipient's public key
    /// * `content` - The plaintext content to encrypt
    ///
    /// # Returns
    /// A complete, signed, encrypted BaseMessage ready for transmission
    pub fn build_private_message(
        &self,
        recipient: &PublicKey,
        content: &[u8],
    ) -> Result<BaseMessage> {
        // 1. Encrypt content for recipient
        let encrypted = encrypt_for_recipient(&self.identity, recipient, content)?;

        // 2. Create PrivateMessagePayload
        let payload = PrivateMessagePayload {
            content: encrypted.ciphertext.clone(),
            ephemeral_public_key: encrypted.ephemeral_public_key.to_vec(),
            nonce: encrypted.nonce.to_vec(),
            return_path: vec![], // Not used in MVP
        };

        // 3. Serialize payload
        let payload_bytes = serialize_message(&payload)
            .map_err(|e| convert_protocol_error(e, "PrivateMessagePayload"))?;

        // 4. Generate message ID from payload
        let message_id = hash_message(&payload_bytes);

        // 5. Create BaseMessage (without signature yet)
        let mut base_message = BaseMessage {
            version: PROTOCOL_VERSION,
            message_id: message_id.as_bytes().to_vec(),
            message_type: MessageType::PrivateMessage as i32,
            timestamp: current_timestamp_ms(),
            sender_public_key: self.identity.public_key().to_bytes().to_vec(),
            payload: payload_bytes.clone(),
            signature: vec![],
            routing_info: None,
        };

        // 6. Sign the payload
        let signature = sign_message(&self.identity, &payload_bytes);
        base_message.signature = signature.to_bytes().to_vec();

        Ok(base_message)
    }

    /// Build a broadcast message (not encrypted)
    ///
    /// # Arguments
    /// * `content` - The plaintext content to broadcast
    /// * `content_type` - MIME type or content identifier
    ///
    /// # Returns
    /// A complete, signed BaseMessage ready for transmission
    pub fn build_broadcast(&self, content: &[u8], content_type: &str) -> Result<BaseMessage> {
        // 1. Create BroadcastPayload
        let payload = BroadcastPayload {
            content: content.to_vec(),
            content_type: content_type.to_string(),
            metadata: std::collections::HashMap::new(),
        };

        // 2. Serialize payload
        let payload_bytes = serialize_message(&payload)
            .map_err(|e| convert_protocol_error(e, "BroadcastPayload"))?;

        // 3. Generate message ID from payload
        let message_id = hash_message(&payload_bytes);

        // 4. Create BaseMessage (without signature yet)
        let mut base_message = BaseMessage {
            version: PROTOCOL_VERSION,
            message_id: message_id.as_bytes().to_vec(),
            message_type: MessageType::Broadcast as i32,
            timestamp: current_timestamp_ms(),
            sender_public_key: self.identity.public_key().to_bytes().to_vec(),
            payload: payload_bytes.clone(),
            signature: vec![],
            routing_info: None,
        };

        // 5. Sign the payload
        let signature = sign_message(&self.identity, &payload_bytes);
        base_message.signature = signature.to_bytes().to_vec();

        Ok(base_message)
    }
}

/// Internal API for parsing protocol messages
#[allow(dead_code)]
pub(crate) struct MessageParser {
    identity: Identity,
}

#[allow(dead_code)]
impl MessageParser {
    /// Create a new MessageParser with the given identity
    pub fn new(identity: Identity) -> Self {
        Self { identity }
    }

    /// Parse a message from bytes
    ///
    /// # Arguments
    /// * `bytes` - The serialized BaseMessage
    ///
    /// # Returns
    /// A ParsedMessage with decrypted content (if applicable) and verification status
    pub fn parse_message(&self, bytes: &[u8]) -> Result<ParsedMessage> {
        // 1. Deserialize BaseMessage
        let base_message: BaseMessage =
            deserialize_message(bytes).map_err(|e| convert_protocol_error(e, "BaseMessage"))?;

        // 2. Validate structure
        validate_base_message(&base_message)
            .map_err(|e| convert_protocol_error(e, "BaseMessage"))?;

        // 3. Validate timestamp
        validate_timestamp(base_message.timestamp)?;

        // 4. Verify signature
        if base_message.sender_public_key.len() != 64 {
            return Err(ProtocolError::InvalidFieldValue {
                field: "sender_public_key".to_string(),
                reason: format!(
                    "Expected 64 bytes, got {}",
                    base_message.sender_public_key.len()
                ),
            }
            .into());
        }

        let sender = PublicKey::from_bytes(&base_message.sender_public_key)?;

        let verified = self.verify_signature(&base_message, &sender)?;

        // 5. Parse based on message type
        let message_type = MessageType::try_from(base_message.message_type).map_err(|_| {
            ProtocolError::InvalidMessageType {
                got: base_message.message_type as u32,
            }
        })?;

        match message_type {
            MessageType::PrivateMessage => {
                self.parse_private_message(&base_message, sender, verified)
            },
            MessageType::Broadcast => self.parse_broadcast(&base_message, sender, verified),
            _ => Err(ProtocolError::InvalidMessageType {
                got: base_message.message_type as u32,
            }
            .into()),
        }
    }

    /// Verify the signature on a BaseMessage
    fn verify_signature(&self, msg: &BaseMessage, sender: &PublicKey) -> Result<bool> {
        if msg.signature.len() != 64 {
            return Ok(false);
        }

        let signature_bytes: [u8; 64] =
            msg.signature
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidSignature {
                    context: "Invalid signature length".to_string(),
                })?;

        let signature = crate::crypto::Signature::from_bytes(&signature_bytes)?;
        let valid = verify_signature(sender, &msg.payload, &signature);
        Ok(valid)
    }

    /// Parse a private message payload
    fn parse_private_message(
        &self,
        msg: &BaseMessage,
        sender: PublicKey,
        verified: bool,
    ) -> Result<ParsedMessage> {
        // 1. Deserialize PrivateMessagePayload
        let payload: PrivateMessagePayload = deserialize_message(&msg.payload)
            .map_err(|e| convert_protocol_error(e, "PrivateMessagePayload"))?;

        // 2. Validate payload fields
        if payload.ephemeral_public_key.len() != 32 {
            return Err(ProtocolError::InvalidFieldValue {
                field: "ephemeral_public_key".to_string(),
                reason: format!(
                    "Expected 32 bytes, got {}",
                    payload.ephemeral_public_key.len()
                ),
            }
            .into());
        }

        if payload.nonce.len() != 12 {
            return Err(ProtocolError::InvalidFieldValue {
                field: "nonce".to_string(),
                reason: format!("Expected 12 bytes, got {}", payload.nonce.len()),
            }
            .into());
        }

        if payload.content.is_empty() {
            return Err(ProtocolError::InvalidFieldValue {
                field: "content".to_string(),
                reason: "Content cannot be empty in private message".to_string(),
            }
            .into());
        }

        // 3. Reconstruct EncryptedMessage
        let mut ephemeral_key = [0u8; 32];
        ephemeral_key.copy_from_slice(&payload.ephemeral_public_key);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&payload.nonce);

        let encrypted_msg = EncryptedMessage {
            ephemeral_public_key: ephemeral_key,
            nonce: nonce_bytes,
            ciphertext: payload.content,
        };

        // 4. Decrypt content
        let content = decrypt_message(&self.identity, &encrypted_msg)?;

        // 5. Create ParsedMessage
        if msg.message_id.len() != 32 {
            return Err(ProtocolError::InvalidFieldValue {
                field: "message_id".to_string(),
                reason: format!("Expected 32 bytes, got {}", msg.message_id.len()),
            }
            .into());
        }

        let mut message_id_bytes = [0u8; 32];
        message_id_bytes.copy_from_slice(&msg.message_id);
        let message_id = MessageId::from_bytes(message_id_bytes);

        Ok(ParsedMessage::PrivateMessage {
            message_id,
            sender,
            content,
            timestamp: msg.timestamp,
            verified,
        })
    }

    /// Parse a broadcast message payload
    fn parse_broadcast(
        &self,
        msg: &BaseMessage,
        sender: PublicKey,
        verified: bool,
    ) -> Result<ParsedMessage> {
        // 1. Deserialize BroadcastPayload
        let payload: BroadcastPayload = deserialize_message(&msg.payload)
            .map_err(|e| convert_protocol_error(e, "BroadcastPayload"))?;

        // 2. Validate payload
        if payload.content.is_empty() {
            return Err(ProtocolError::InvalidFieldValue {
                field: "content".to_string(),
                reason: "Content cannot be empty in broadcast".to_string(),
            }
            .into());
        }

        // 3. Create ParsedMessage
        if msg.message_id.len() != 32 {
            return Err(ProtocolError::InvalidFieldValue {
                field: "message_id".to_string(),
                reason: format!("Expected 32 bytes, got {}", msg.message_id.len()),
            }
            .into());
        }

        let mut message_id_bytes = [0u8; 32];
        message_id_bytes.copy_from_slice(&msg.message_id);
        let message_id = MessageId::from_bytes(message_id_bytes);

        Ok(ParsedMessage::Broadcast {
            message_id,
            sender,
            content: payload.content,
            content_type: payload.content_type,
            timestamp: msg.timestamp,
            verified,
        })
    }
}

/// Get current timestamp in milliseconds since Unix epoch
#[allow(dead_code)]
fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Validate timestamp is within acceptable range
#[allow(dead_code)]
fn validate_timestamp(timestamp: i64) -> Result<()> {
    let now = current_timestamp_ms();

    // Check if timestamp is too far in the future
    if timestamp > now + MAX_FUTURE_SKEW_MS {
        return Err(ProtocolError::InvalidFieldValue {
            field: "timestamp".to_string(),
            reason: format!("Timestamp too far in future: {} ms ahead", timestamp - now),
        }
        .into());
    }

    // Check if timestamp is too old
    if timestamp < now - MAX_MESSAGE_AGE_MS {
        return Err(ProtocolError::InvalidFieldValue {
            field: "timestamp".to_string(),
            reason: format!("Timestamp too old: {} ms ago", now - timestamp),
        }
        .into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_timestamp_ms() {
        let ts = current_timestamp_ms();
        assert!(ts > 0);
        // Should be reasonable (after 2020)
        assert!(ts > 1577836800000); // Jan 1, 2020
    }

    #[test]
    fn test_validate_timestamp_current() {
        let now = current_timestamp_ms();
        assert!(validate_timestamp(now).is_ok());
    }

    #[test]
    fn test_validate_timestamp_future() {
        let future = current_timestamp_ms() + MAX_FUTURE_SKEW_MS + 1000;
        assert!(validate_timestamp(future).is_err());
    }

    #[test]
    fn test_validate_timestamp_past() {
        let past = current_timestamp_ms() - MAX_MESSAGE_AGE_MS - 1000;
        assert!(validate_timestamp(past).is_err());
    }

    #[test]
    fn test_hash_message() {
        let payload = b"test payload";
        let id1 = hash_message(payload);
        let id2 = hash_message(payload);

        // Same payload should generate same ID
        assert_eq!(id1, id2);

        // Different payload should generate different ID
        let id3 = hash_message(b"different payload");
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_message_id_from_bytes() {
        let bytes = [42u8; 32];
        let id = MessageId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn test_build_private_message() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let builder = MessageBuilder::new(alice);
        let content = b"Hello Bob!";

        let msg = builder
            .build_private_message(&bob.public_key(), content)
            .unwrap();

        // Validate structure
        assert_eq!(msg.version, PROTOCOL_VERSION);
        assert_eq!(msg.message_id.len(), 32);
        assert_eq!(msg.message_type, MessageType::PrivateMessage as i32);
        assert_eq!(msg.sender_public_key.len(), 64); // 32 bytes Ed25519 + 32 bytes X25519
        assert_eq!(msg.signature.len(), 64);
        assert!(!msg.payload.is_empty());
    }

    #[test]
    fn test_build_broadcast() {
        let alice = Identity::generate();
        let builder = MessageBuilder::new(alice);

        let content = b"Hello everyone!";
        let content_type = "text/plain";

        let msg = builder.build_broadcast(content, content_type).unwrap();

        // Validate structure
        assert_eq!(msg.version, PROTOCOL_VERSION);
        assert_eq!(msg.message_id.len(), 32);
        assert_eq!(msg.message_type, MessageType::Broadcast as i32);
        assert_eq!(msg.sender_public_key.len(), 64); // 32 bytes Ed25519 + 32 bytes X25519
        assert_eq!(msg.signature.len(), 64);
        assert!(!msg.payload.is_empty());
    }

    #[test]
    fn test_private_message_round_trip() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        // Store Alice's public key before moving identity
        let alice_pubkey = alice.public_key();

        // Alice builds message for Bob
        let alice_builder = MessageBuilder::new(alice);
        let content = b"Secret message";
        let msg = alice_builder
            .build_private_message(&bob.public_key(), content)
            .unwrap();

        // Serialize
        let bytes = serialize_message(&msg).unwrap();

        // Bob parses message
        let bob_parser = MessageParser::new(bob);
        let parsed = bob_parser.parse_message(&bytes).unwrap();

        // Verify content
        match parsed {
            ParsedMessage::PrivateMessage {
                content: decrypted_content,
                sender,
                verified,
                ..
            } => {
                assert_eq!(decrypted_content, content);
                assert_eq!(sender.to_bytes(), alice_pubkey.to_bytes());
                assert!(verified);
            },
            _ => panic!("Expected PrivateMessage"),
        }
    }

    #[test]
    fn test_broadcast_round_trip() {
        let alice = Identity::generate();

        // Store Alice's public key before moving identity
        let alice_pubkey = alice.public_key();

        // Alice builds broadcast
        let alice_builder = MessageBuilder::new(alice);
        let content = b"Public announcement";
        let content_type = "text/plain";
        let msg = alice_builder
            .build_broadcast(content, content_type)
            .unwrap();

        // Serialize
        let bytes = serialize_message(&msg).unwrap();

        // Anyone can parse (using their own identity)
        let bob = Identity::generate();
        let bob_parser = MessageParser::new(bob);
        let parsed = bob_parser.parse_message(&bytes).unwrap();

        // Verify content
        match parsed {
            ParsedMessage::Broadcast {
                content: broadcast_content,
                content_type: ct,
                sender,
                verified,
                ..
            } => {
                assert_eq!(broadcast_content, content);
                assert_eq!(ct, content_type);
                assert_eq!(sender.to_bytes(), alice_pubkey.to_bytes());
                assert!(verified);
            },
            _ => panic!("Expected Broadcast"),
        }
    }

    #[test]
    fn test_invalid_signature_detected() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        // Alice builds message
        let alice_builder = MessageBuilder::new(alice);
        let content = b"Original message";
        let mut msg = alice_builder
            .build_private_message(&bob.public_key(), content)
            .unwrap();

        // Tamper with signature (not payload, to avoid deserialization errors)
        if let Some(byte) = msg.signature.first_mut() {
            *byte = byte.wrapping_add(1);
        }

        // Serialize tampered message
        let bytes = serialize_message(&msg).unwrap();

        // Bob tries to parse - signature verification should fail
        let bob_parser = MessageParser::new(bob);
        let parsed = bob_parser.parse_message(&bytes).unwrap();

        match parsed {
            ParsedMessage::PrivateMessage { verified, .. } => {
                assert!(!verified); // Signature should be invalid
            },
            _ => panic!("Expected PrivateMessage"),
        }
    }

    #[test]
    fn test_wrong_recipient_cannot_decrypt() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let charlie = Identity::generate();

        // Alice builds message for Bob
        let alice_builder = MessageBuilder::new(alice);
        let content = b"For Bob only";
        let msg = alice_builder
            .build_private_message(&bob.public_key(), content)
            .unwrap();

        // Serialize
        let bytes = serialize_message(&msg).unwrap();

        // Charlie tries to parse (wrong recipient)
        let charlie_parser = MessageParser::new(charlie);
        let result = charlie_parser.parse_message(&bytes);

        // Should fail to decrypt
        assert!(result.is_err());
    }

    #[test]
    fn test_message_ids_are_unique() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let alice_builder = MessageBuilder::new(alice);

        let msg1 = alice_builder
            .build_private_message(&bob.public_key(), b"message 1")
            .unwrap();
        let msg2 = alice_builder
            .build_private_message(&bob.public_key(), b"message 2")
            .unwrap();
        let msg3 = alice_builder
            .build_private_message(&bob.public_key(), b"message 1")
            .unwrap();

        // Different messages should have different IDs
        assert_ne!(msg1.message_id, msg2.message_id);

        // Same content but different timestamp/nonce means different ID
        // (because encryption uses random nonce)
        assert_ne!(msg1.message_id, msg3.message_id);
    }
}

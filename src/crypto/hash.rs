//! Cryptographic hashing using Blake3
//!
//! Provides fast, secure hashing for message IDs and node IDs.

use super::keys::PublicKey;
use crate::error::{CryptoError, Result};

/// A unique identifier for a message (32-byte Blake3 hash)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MessageId([u8; 32]);

impl MessageId {
    /// Create a MessageId from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hexadecimal string
    pub fn to_hex(&self) -> String {
        self.0
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    /// Parse from hexadecimal string
    pub fn from_hex(s: &str) -> Result<Self> {
        if s.len() != 64 {
            return Err(CryptoError::InvalidEncryptedData {
                context: "Invalid hex string length for MessageId".to_string(),
            }
            .into());
        }

        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| {
                CryptoError::InvalidEncryptedData {
                    context: "Invalid hex character".to_string(),
                }
            })?;
        }

        Ok(Self(bytes))
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A unique identifier for a node (32-byte Blake3 hash of public key)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// Create a NodeId from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hexadecimal string
    pub fn to_hex(&self) -> String {
        self.0
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    /// Parse from hexadecimal string
    pub fn from_hex(s: &str) -> Result<Self> {
        if s.len() != 64 {
            return Err(CryptoError::InvalidEncryptedData {
                context: "Invalid hex string length for NodeId".to_string(),
            }
            .into());
        }

        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| {
                CryptoError::InvalidEncryptedData {
                    context: "Invalid hex character".to_string(),
                }
            })?;
        }

        Ok(Self(bytes))
    }

    /// Calculate XOR distance to another NodeId (for DHT)
    pub fn xor_distance(&self, other: &NodeId) -> [u8; 32] {
        let mut result = [0u8; 32];
        for (i, item) in result.iter_mut().enumerate() {
            *item = self.0[i] ^ other.0[i];
        }
        result
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Hash arbitrary data to produce a MessageId
///
/// Uses Blake3 cryptographic hash function.
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Example
///
/// ```
/// use meshara::crypto::hash_message;
///
/// let data = b"Hello, Meshara!";
/// let message_id = hash_message(data);
/// println!("Message ID: {}", message_id);
/// ```
pub fn hash_message(data: &[u8]) -> MessageId {
    let hash = blake3::hash(data);
    MessageId(*hash.as_bytes())
}

/// Hash a public key to produce a NodeId
///
/// Uses Blake3 cryptographic hash function on the serialized public key.
/// The NodeId serves as a stable identifier for routing and DHT operations.
///
/// # Arguments
///
/// * `public_key` - The public key to hash
///
/// # Example
///
/// ```
/// use meshara::crypto::{Identity, hash_public_key};
///
/// let identity = Identity::generate();
/// let public_key = identity.public_key();
/// let node_id = hash_public_key(&public_key);
/// println!("Node ID: {}", node_id);
/// ```
pub fn hash_public_key(public_key: &PublicKey) -> NodeId {
    let key_bytes = public_key.to_bytes();
    let hash = blake3::hash(&key_bytes);
    NodeId(*hash.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Identity;

    #[test]
    fn test_hash_deterministic() {
        let data = b"Test message";
        let hash1 = hash_message(data);
        let hash2 = hash_message(data);

        // Hash is deterministic - same input produces same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_length() {
        let data = b"Any input";
        let hash = hash_message(data);

        // Hash is always 32 bytes
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_hash_empty() {
        // Hash empty input
        let hash = hash_message(b"");

        // Should succeed with valid hash
        assert_eq!(hash.as_bytes().len(), 32);

        // Empty input should hash deterministically
        let hash2 = hash_message(b"");
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hash_message() {
        let data = b"Test message";
        let hash1 = hash_message(data);
        let hash2 = hash_message(data);

        // Same input produces same hash
        assert_eq!(hash1, hash2);

        // Hash is correct length
        assert_eq!(hash1.as_bytes().len(), 32);
    }

    #[test]
    fn test_hash_different_messages() {
        let hash1 = hash_message(b"Message 1");
        let hash2 = hash_message(b"Message 2");

        // Different inputs produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_public_key() {
        let identity = Identity::generate();
        let public_key = identity.public_key();

        let node_id1 = hash_public_key(&public_key);
        let node_id2 = hash_public_key(&public_key);

        // Same key produces same hash
        assert_eq!(node_id1, node_id2);

        // Hash is correct length
        assert_eq!(node_id1.as_bytes().len(), 32);
    }

    #[test]
    fn test_hash_different_public_keys() {
        let identity1 = Identity::generate();
        let identity2 = Identity::generate();

        let node_id1 = hash_public_key(&identity1.public_key());
        let node_id2 = hash_public_key(&identity2.public_key());

        // Different keys produce different hashes
        assert_ne!(node_id1, node_id2);
    }

    #[test]
    fn test_message_id_hex() {
        let data = b"Test";
        let message_id = hash_message(data);

        let hex = message_id.to_hex();
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars

        let parsed = MessageId::from_hex(&hex).unwrap();
        assert_eq!(message_id, parsed);
    }

    #[test]
    fn test_node_id_hex() {
        let identity = Identity::generate();
        let node_id = hash_public_key(&identity.public_key());

        let hex = node_id.to_hex();
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars

        let parsed = NodeId::from_hex(&hex).unwrap();
        assert_eq!(node_id, parsed);
    }

    #[test]
    fn test_node_id_ordering() {
        let id1 = NodeId::from_bytes([0u8; 32]);
        let id2 = NodeId::from_bytes([1u8; 32]);

        assert!(id1 < id2);
    }

    #[test]
    fn test_xor_distance() {
        let id1 = NodeId::from_bytes([0b11110000; 32]);
        let id2 = NodeId::from_bytes([0b10101010; 32]);

        let distance = id1.xor_distance(&id2);
        assert_eq!(distance[0], 0b11110000 ^ 0b10101010);

        // Distance is symmetric
        let distance2 = id2.xor_distance(&id1);
        assert_eq!(distance, distance2);

        // Distance to self is zero
        let distance_self = id1.xor_distance(&id1);
        assert_eq!(distance_self, [0u8; 32]);
    }

    #[test]
    fn test_message_id_display() {
        let data = b"Test";
        let message_id = hash_message(data);
        let display = format!("{}", message_id);
        assert_eq!(display, message_id.to_hex());
    }

    #[test]
    fn test_node_id_display() {
        let identity = Identity::generate();
        let node_id = hash_public_key(&identity.public_key());
        let display = format!("{}", node_id);
        assert_eq!(display, node_id.to_hex());
    }

    // Property-based tests using proptest
    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Property: Hash should be deterministic
            #[test]
            fn prop_hash_deterministic(data: Vec<u8>) {
                let hash1 = hash_message(&data);
                let hash2 = hash_message(&data);
                prop_assert_eq!(hash1, hash2);
            }

            /// Property: Hash should always be 32 bytes
            #[test]
            fn prop_hash_length(data: Vec<u8>) {
                let hash = hash_message(&data);
                prop_assert_eq!(hash.as_bytes().len(), 32);
            }

            /// Property: Different inputs should produce different hashes
            #[test]
            fn prop_different_inputs_different_hashes(data1: Vec<u8>, data2: Vec<u8>) {
                prop_assume!(data1 != data2);
                let hash1 = hash_message(&data1);
                let hash2 = hash_message(&data2);
                prop_assert_ne!(hash1, hash2);
            }

            /// Property: MessageId hex roundtrip should preserve value
            #[test]
            fn prop_message_id_hex_roundtrip(data: Vec<u8>) {
                let message_id = hash_message(&data);
                let hex = message_id.to_hex();
                let parsed = MessageId::from_hex(&hex).unwrap();
                prop_assert_eq!(message_id, parsed);
            }

            /// Property: XOR distance should be symmetric
            #[test]
            fn prop_xor_distance_symmetric(bytes1: [u8; 32], bytes2: [u8; 32]) {
                let id1 = NodeId::from_bytes(bytes1);
                let id2 = NodeId::from_bytes(bytes2);
                let dist1 = id1.xor_distance(&id2);
                let dist2 = id2.xor_distance(&id1);
                prop_assert_eq!(dist1, dist2);
            }

            /// Property: XOR distance to self should be zero
            #[test]
            fn prop_xor_distance_self_is_zero(bytes: [u8; 32]) {
                let id = NodeId::from_bytes(bytes);
                let dist = id.xor_distance(&id);
                prop_assert_eq!(dist, [0u8; 32]);
            }
        }
    }
}

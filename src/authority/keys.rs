//! Authority key management and identity
//!
//! This module provides structures and methods for managing authority identities.
//! Authority nodes use these identities to sign official content like software updates
//! and announcements.

use crate::crypto::{Identity, PublicKey, Signature};
use crate::error::Result;
use crate::protocol::UpdatePackage;
use blake3;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Unique identifier for an authority (hash of public key)
///
/// This is a cryptographic hash of the authority's public key, providing a
/// stable, content-addressable identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthorityId(Vec<u8>);

impl AuthorityId {
    /// Create an authority ID from a public key
    ///
    /// The ID is the BLAKE3 hash of the public key bytes, providing a
    /// stable identifier that's derived from the key itself.
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        let hash = blake3::hash(&public_key.to_bytes());
        Self(hash.as_bytes().to_vec())
    }

    /// Get the raw bytes of the authority ID
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to hex string for display
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Create from raw bytes (for deserialization)
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Display for AuthorityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Metadata about an authority
///
/// This provides human-readable information about who the authority is
/// and what they're authorized to do.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityMetadata {
    /// Human-readable name of the authority
    pub name: String,
    /// Description of the authority's purpose/role
    pub description: String,
    /// URL for more information about the authority
    pub url: String,
    /// Timestamp when authority was created (milliseconds since epoch)
    pub created_at: i64,
}

impl AuthorityMetadata {
    /// Create new authority metadata
    pub fn new(name: String, description: String, url: String) -> Self {
        Self {
            name,
            description,
            url,
            created_at: current_timestamp_ms(),
        }
    }
}

/// Authority identity combining cryptographic identity with metadata
///
/// This represents a node that has authority to publish signed content.
/// Authority identities are long-lived and should be carefully protected.
///
/// Note: This type does NOT implement Clone for security reasons - private keys
/// should not be duplicated. Use export/import for backup and transfer.
pub struct AuthorityIdentity {
    /// Underlying cryptographic identity
    identity: Identity,
    /// Unique authority identifier (hash of public key)
    authority_id: AuthorityId,
    /// Human-readable metadata
    metadata: AuthorityMetadata,
}

impl AuthorityIdentity {
    /// Create a new authority identity with generated keys
    ///
    /// This generates a new cryptographic identity and derives the authority ID
    /// from its public key.
    ///
    /// # Arguments
    /// * `name` - Human-readable name of the authority
    /// * `description` - Description of the authority's purpose
    /// * `url` - URL for more information
    pub fn new(name: String, description: String, url: String) -> Self {
        let identity = Identity::generate();
        let authority_id = AuthorityId::from_public_key(&identity.public_key());
        let metadata = AuthorityMetadata::new(name, description, url);

        Self {
            identity,
            authority_id,
            metadata,
        }
    }

    /// Create an authority identity from an existing identity
    ///
    /// This allows promoting an existing node identity to an authority.
    ///
    /// # Arguments
    /// * `identity` - Existing cryptographic identity to use
    /// * `metadata` - Metadata describing the authority
    pub fn from_identity(identity: Identity, metadata: AuthorityMetadata) -> Self {
        let authority_id = AuthorityId::from_public_key(&identity.public_key());

        Self {
            identity,
            authority_id,
            metadata,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> PublicKey {
        self.identity.public_key()
    }

    /// Get the authority ID
    pub fn authority_id(&self) -> &AuthorityId {
        &self.authority_id
    }

    /// Get the metadata
    pub fn metadata(&self) -> &AuthorityMetadata {
        &self.metadata
    }

    /// Get the underlying identity
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Sign an update package
    ///
    /// This creates a signature over the entire update package content.
    /// The signature proves that this authority endorsed the update.
    ///
    /// # Arguments
    /// * `update` - The update package to sign
    pub fn sign_update(&self, update: &UpdatePackage) -> Result<Signature> {
        use prost::Message;

        // Serialize the update package
        let mut buf = Vec::new();
        update
            .encode(&mut buf)
            .map_err(|e| crate::error::ProtocolError::SerializationFailed {
                message_type: "UpdatePackage".to_string(),
                reason: e.to_string(),
            })?;

        // Sign the serialized bytes
        self.sign_content(&buf)
    }

    /// Sign arbitrary content
    ///
    /// This creates a signature over any content bytes.
    /// Use this for signing announcements, configurations, or other data.
    ///
    /// # Arguments
    /// * `content` - The content bytes to sign
    pub fn sign_content(&self, content: &[u8]) -> Result<Signature> {
        Ok(crate::crypto::sign_message(&self.identity, content))
    }

    /// Export authority identity to encrypted JSON
    ///
    /// This exports the complete authority identity (including private keys)
    /// encrypted with a passphrase. Use this for backup and transport.
    ///
    /// # Arguments
    /// * `passphrase` - Passphrase to encrypt the identity
    pub fn export(&self, passphrase: &str) -> Result<String> {
        use serde_json;

        // Export the underlying identity (returns encrypted bytes)
        let identity_bytes = self.identity.export_encrypted(passphrase)?;

        // Encode to base64 for JSON storage
        let identity_base64 = hex::encode(&identity_bytes);

        // Combine with metadata
        #[derive(Serialize)]
        struct ExportFormat {
            identity: String,
            metadata: AuthorityMetadata,
        }

        let export = ExportFormat {
            identity: identity_base64,
            metadata: self.metadata.clone(),
        };

        serde_json::to_string(&export).map_err(|e| {
            crate::error::ProtocolError::SerializationFailed {
                message_type: "AuthorityIdentity".to_string(),
                reason: e.to_string(),
            }
            .into()
        })
    }

    /// Import authority identity from encrypted JSON
    ///
    /// This imports an authority identity that was previously exported.
    ///
    /// # Arguments
    /// * `json` - The exported JSON string
    /// * `passphrase` - Passphrase to decrypt the identity
    pub fn import(json: &str, passphrase: &str) -> Result<Self> {
        use serde_json;

        #[derive(Deserialize)]
        struct ImportFormat {
            identity: String,
            metadata: AuthorityMetadata,
        }

        let import: ImportFormat = serde_json::from_str(json).map_err(|e| {
            crate::error::ProtocolError::DeserializationFailed {
                reason: e.to_string(),
            }
        })?;

        // Decode from hex
        let identity_bytes = hex::decode(&import.identity).map_err(|e| {
            crate::error::ProtocolError::DeserializationFailed {
                reason: format!("Invalid hex encoding: {}", e),
            }
        })?;

        let identity = Identity::import_encrypted(&identity_bytes, passphrase)?;

        Ok(Self::from_identity(identity, import.metadata))
    }
}

/// Get current timestamp in milliseconds since Unix epoch
fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authority_id_from_public_key() {
        let identity = Identity::generate();
        let public_key = identity.public_key();

        let authority_id = AuthorityId::from_public_key(&public_key);

        // Should have 32 bytes (BLAKE3 hash)
        assert_eq!(authority_id.as_bytes().len(), 32);
    }

    #[test]
    fn test_authority_id_consistency() {
        let identity = Identity::generate();
        let public_key = identity.public_key();

        let id1 = AuthorityId::from_public_key(&public_key);
        let id2 = AuthorityId::from_public_key(&public_key);

        // Same public key should produce same ID
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_authority_id_hex() {
        let identity = Identity::generate();
        let authority_id = AuthorityId::from_public_key(&identity.public_key());

        let hex = authority_id.to_hex();

        // Should be 64 hex characters (32 bytes)
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_authority_id_display() {
        let identity = Identity::generate();
        let authority_id = AuthorityId::from_public_key(&identity.public_key());

        let display = format!("{}", authority_id);

        // Should match hex representation
        assert_eq!(display, authority_id.to_hex());
    }

    #[test]
    fn test_authority_metadata_creation() {
        let metadata = AuthorityMetadata::new(
            "Test Authority".to_string(),
            "Testing authority system".to_string(),
            "https://example.com".to_string(),
        );

        assert_eq!(metadata.name, "Test Authority");
        assert_eq!(metadata.description, "Testing authority system");
        assert_eq!(metadata.url, "https://example.com");
        assert!(metadata.created_at > 0);
    }

    #[test]
    fn test_authority_identity_new() {
        let authority = AuthorityIdentity::new(
            "Test Authority".to_string(),
            "Testing".to_string(),
            "https://test.com".to_string(),
        );

        assert_eq!(authority.metadata().name, "Test Authority");
        assert_eq!(authority.metadata().description, "Testing");
        assert_eq!(authority.metadata().url, "https://test.com");

        // Authority ID should be derived from public key
        let expected_id = AuthorityId::from_public_key(&authority.public_key());
        assert_eq!(authority.authority_id(), &expected_id);
    }

    #[test]
    fn test_authority_identity_from_identity() {
        let identity = Identity::generate();
        let public_key = identity.public_key(); // Save public key before moving
        let metadata = AuthorityMetadata::new(
            "From Identity".to_string(),
            "Test".to_string(),
            "https://test.com".to_string(),
        );

        let authority = AuthorityIdentity::from_identity(identity, metadata.clone());

        assert_eq!(authority.public_key(), public_key);
        assert_eq!(authority.metadata(), &metadata);
    }

    #[test]
    fn test_sign_content() {
        let authority = AuthorityIdentity::new(
            "Test".to_string(),
            "Test".to_string(),
            "https://test.com".to_string(),
        );

        let content = b"Hello, World!";
        let signature = authority.sign_content(content).unwrap();

        // Verify the signature using the public key
        let public_key = authority.public_key();
        assert!(crate::crypto::verify_signature(
            &public_key,
            content,
            &signature
        ));
    }

    #[test]
    fn test_sign_invalid_content_verification_fails() {
        let authority = AuthorityIdentity::new(
            "Test".to_string(),
            "Test".to_string(),
            "https://test.com".to_string(),
        );

        let content = b"Hello, World!";
        let signature = authority.sign_content(content).unwrap();

        // Verify with different content should fail
        let wrong_content = b"Goodbye, World!";
        let public_key = authority.public_key();
        assert!(!crate::crypto::verify_signature(
            &public_key,
            wrong_content,
            &signature
        ));
    }

    #[test]
    fn test_export_import() {
        let authority = AuthorityIdentity::new(
            "Export Test".to_string(),
            "Testing export/import".to_string(),
            "https://export.test".to_string(),
        );

        let passphrase = "test_passphrase_12345";

        // Export
        let exported = authority.export(passphrase).unwrap();
        assert!(!exported.is_empty());

        // Import
        let imported = AuthorityIdentity::import(&exported, passphrase).unwrap();

        // Should have same metadata
        assert_eq!(imported.metadata(), authority.metadata());

        // Should have same public key
        assert_eq!(imported.public_key(), authority.public_key());

        // Should have same authority ID
        assert_eq!(imported.authority_id(), authority.authority_id());
    }

    #[test]
    fn test_import_wrong_passphrase_fails() {
        let authority = AuthorityIdentity::new(
            "Test".to_string(),
            "Test".to_string(),
            "https://test.com".to_string(),
        );

        let exported = authority.export("correct_passphrase").unwrap();

        // Try to import with wrong passphrase
        let result = AuthorityIdentity::import(&exported, "wrong_passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_different_authorities_have_different_ids() {
        let auth1 = AuthorityIdentity::new(
            "Authority 1".to_string(),
            "First".to_string(),
            "https://one.com".to_string(),
        );

        let auth2 = AuthorityIdentity::new(
            "Authority 2".to_string(),
            "Second".to_string(),
            "https://two.com".to_string(),
        );

        assert_ne!(auth1.authority_id(), auth2.authority_id());
    }

    #[test]
    fn test_authority_id_serialization() {
        let identity = Identity::generate();
        let authority_id = AuthorityId::from_public_key(&identity.public_key());

        let serialized = serde_json::to_string(&authority_id).unwrap();
        let deserialized: AuthorityId = serde_json::from_str(&serialized).unwrap();

        assert_eq!(authority_id, deserialized);
    }

    #[test]
    fn test_authority_metadata_serialization() {
        let metadata = AuthorityMetadata::new(
            "Test".to_string(),
            "Description".to_string(),
            "https://test.com".to_string(),
        );

        let serialized = serde_json::to_string(&metadata).unwrap();
        let deserialized: AuthorityMetadata = serde_json::from_str(&serialized).unwrap();

        assert_eq!(metadata, deserialized);
    }
}

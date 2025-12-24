//! Trust management for authorities
//!
//! This module provides trust store functionality for managing which authorities
//! a node trusts and for what purposes.

use crate::authority::keys::{AuthorityId, AuthorityMetadata};
use crate::crypto::{PublicKey, Signature};
use crate::error::{AuthorityError, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Level of trust granted to an authority
///
/// Different authorities may be trusted for different purposes.
/// This allows fine-grained control over what each authority can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Authority can publish software updates
    UpdateAuthority,
    /// Authority can sign general content (announcements, data)
    SigningAuthority,
    /// Authority can provide trusted peer lists for bootstrapping
    BootstrapAuthority,
    /// Authority has all above privileges
    FullTrust,
}

impl TrustLevel {
    /// Check if this trust level includes the specified capability
    pub fn includes(&self, capability: TrustLevel) -> bool {
        match self {
            TrustLevel::FullTrust => true, // Full trust includes everything
            _ => self == &capability,      // Otherwise must match exactly
        }
    }
}

/// Information about a trusted authority
///
/// This records when an authority was trusted, what level of trust it has,
/// and its associated metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedAuthority {
    /// Unique authority identifier
    pub authority_id: AuthorityId,
    /// Authority's public key for signature verification
    pub public_key: PublicKey,
    /// Human-readable metadata
    pub metadata: AuthorityMetadata,
    /// Level of trust granted to this authority
    pub trust_level: TrustLevel,
    /// Timestamp when authority was added (milliseconds since epoch)
    pub added_at: i64,
}

/// Store for managing trusted authorities
///
/// This is the central registry of which authorities a node trusts.
/// All authority verification goes through this store.
pub struct AuthorityTrustStore {
    /// Map of authority ID to trusted authority info
    trusted_authorities: Arc<DashMap<AuthorityId, TrustedAuthority>>,
}

impl AuthorityTrustStore {
    /// Create a new empty trust store
    pub fn new() -> Self {
        Self {
            trusted_authorities: Arc::new(DashMap::new()),
        }
    }

    /// Add an authority to the trust store
    ///
    /// This grants the specified trust level to the authority.
    /// If the authority already exists, it updates the trust level.
    ///
    /// # Arguments
    /// * `authority_id` - Unique identifier of the authority
    /// * `public_key` - Authority's public key for verification
    /// * `metadata` - Metadata about the authority
    /// * `trust_level` - Level of trust to grant
    pub fn add_authority(
        &self,
        authority_id: AuthorityId,
        public_key: PublicKey,
        metadata: AuthorityMetadata,
        trust_level: TrustLevel,
    ) -> Result<()> {
        let trusted = TrustedAuthority {
            authority_id: authority_id.clone(),
            public_key,
            metadata,
            trust_level,
            added_at: current_timestamp_ms(),
        };

        self.trusted_authorities.insert(authority_id, trusted);
        Ok(())
    }

    /// Remove an authority from the trust store
    ///
    /// After removal, signatures from this authority will no longer verify.
    ///
    /// # Arguments
    /// * `authority_id` - ID of authority to remove
    pub fn remove_authority(&self, authority_id: &AuthorityId) -> Result<()> {
        self.trusted_authorities.remove(authority_id);
        Ok(())
    }

    /// Get information about a trusted authority
    ///
    /// Returns None if the authority is not trusted.
    ///
    /// # Arguments
    /// * `authority_id` - ID of authority to look up
    pub fn get_authority(&self, authority_id: &AuthorityId) -> Option<TrustedAuthority> {
        self.trusted_authorities
            .get(authority_id)
            .map(|entry| entry.value().clone())
    }

    /// Verify a signature from an authority
    ///
    /// This checks:
    /// 1. Authority is in trust store
    /// 2. Signature is valid for the content
    ///
    /// Returns Ok(true) if signature is valid, Ok(false) if invalid signature,
    /// Err if authority is not trusted.
    ///
    /// # Arguments
    /// * `authority_id` - ID of authority that signed the content
    /// * `content` - The content that was signed
    /// * `signature` - The signature to verify
    pub fn verify_signature(
        &self,
        authority_id: &AuthorityId,
        content: &[u8],
        signature: &Signature,
    ) -> Result<bool> {
        // Look up the authority
        let authority =
            self.get_authority(authority_id)
                .ok_or_else(|| AuthorityError::UnknownAuthority {
                    authority_id: authority_id.to_string(),
                })?;

        // Verify the signature using crypto module
        let valid = crate::crypto::verify_signature(&authority.public_key, content, signature);
        Ok(valid)
    }

    /// Check if an authority is trusted for a specific purpose
    ///
    /// Returns true if the authority exists in the trust store and has
    /// the required trust level.
    ///
    /// # Arguments
    /// * `authority_id` - ID of authority to check
    /// * `level` - Required trust level
    pub fn is_trusted(&self, authority_id: &AuthorityId, level: TrustLevel) -> bool {
        self.get_authority(authority_id)
            .map(|auth| auth.trust_level.includes(level))
            .unwrap_or(false)
    }

    /// List all trusted authorities
    ///
    /// Returns a vector of all authorities in the trust store.
    pub fn list_authorities(&self) -> Vec<TrustedAuthority> {
        self.trusted_authorities
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Count of trusted authorities
    pub fn count(&self) -> usize {
        self.trusted_authorities.len()
    }

    /// Clear all trusted authorities
    ///
    /// This removes all authorities from the trust store.
    /// Use with caution - this will prevent verification of all authority content.
    pub fn clear(&self) {
        self.trusted_authorities.clear();
    }

    /// Update trust level for an existing authority
    ///
    /// Returns error if authority is not in trust store.
    ///
    /// # Arguments
    /// * `authority_id` - ID of authority to update
    /// * `new_level` - New trust level to grant
    pub fn update_trust_level(
        &self,
        authority_id: &AuthorityId,
        new_level: TrustLevel,
    ) -> Result<()> {
        self.trusted_authorities
            .get_mut(authority_id)
            .map(|mut entry| {
                entry.trust_level = new_level;
            })
            .ok_or_else(|| AuthorityError::UnknownAuthority {
                authority_id: authority_id.to_string(),
            })?;

        Ok(())
    }
}

impl Default for AuthorityTrustStore {
    fn default() -> Self {
        Self::new()
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
    use crate::authority::keys::AuthorityIdentity;

    #[test]
    fn test_trust_level_includes() {
        assert!(TrustLevel::FullTrust.includes(TrustLevel::UpdateAuthority));
        assert!(TrustLevel::FullTrust.includes(TrustLevel::SigningAuthority));
        assert!(TrustLevel::FullTrust.includes(TrustLevel::BootstrapAuthority));
        assert!(TrustLevel::FullTrust.includes(TrustLevel::FullTrust));

        assert!(TrustLevel::UpdateAuthority.includes(TrustLevel::UpdateAuthority));
        assert!(!TrustLevel::UpdateAuthority.includes(TrustLevel::SigningAuthority));
        assert!(!TrustLevel::UpdateAuthority.includes(TrustLevel::FullTrust));
    }

    #[test]
    fn test_trust_store_creation() {
        let store = AuthorityTrustStore::new();
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_add_authority() {
        let store = AuthorityTrustStore::new();
        let authority = AuthorityIdentity::new(
            "Test Authority".to_string(),
            "Testing".to_string(),
            "https://test.com".to_string(),
        );

        store
            .add_authority(
                authority.authority_id().clone(),
                authority.public_key(),
                authority.metadata().clone(),
                TrustLevel::UpdateAuthority,
            )
            .unwrap();

        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_get_authority() {
        let store = AuthorityTrustStore::new();
        let authority = AuthorityIdentity::new(
            "Test".to_string(),
            "Test".to_string(),
            "https://test.com".to_string(),
        );

        let auth_id = authority.authority_id().clone();

        store
            .add_authority(
                auth_id.clone(),
                authority.public_key(),
                authority.metadata().clone(),
                TrustLevel::SigningAuthority,
            )
            .unwrap();

        let retrieved = store.get_authority(&auth_id).unwrap();
        assert_eq!(retrieved.authority_id, auth_id);
        assert_eq!(retrieved.trust_level, TrustLevel::SigningAuthority);
    }

    #[test]
    fn test_get_unknown_authority() {
        let store = AuthorityTrustStore::new();
        let authority = AuthorityIdentity::new(
            "Unknown".to_string(),
            "Unknown".to_string(),
            "https://unknown.com".to_string(),
        );

        let result = store.get_authority(authority.authority_id());
        assert!(result.is_none());
    }

    #[test]
    fn test_remove_authority() {
        let store = AuthorityTrustStore::new();
        let authority = AuthorityIdentity::new(
            "Test".to_string(),
            "Test".to_string(),
            "https://test.com".to_string(),
        );

        let auth_id = authority.authority_id().clone();

        store
            .add_authority(
                auth_id.clone(),
                authority.public_key(),
                authority.metadata().clone(),
                TrustLevel::UpdateAuthority,
            )
            .unwrap();

        assert_eq!(store.count(), 1);

        store.remove_authority(&auth_id).unwrap();

        assert_eq!(store.count(), 0);
        assert!(store.get_authority(&auth_id).is_none());
    }

    #[test]
    fn test_verify_signature_valid() {
        let store = AuthorityTrustStore::new();
        let authority = AuthorityIdentity::new(
            "Test".to_string(),
            "Test".to_string(),
            "https://test.com".to_string(),
        );

        let auth_id = authority.authority_id().clone();

        store
            .add_authority(
                auth_id.clone(),
                authority.public_key(),
                authority.metadata().clone(),
                TrustLevel::SigningAuthority,
            )
            .unwrap();

        let content = b"Hello, World!";
        let signature = authority.sign_content(content).unwrap();

        let result = store.verify_signature(&auth_id, content, &signature);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_signature_invalid() {
        let store = AuthorityTrustStore::new();
        let authority = AuthorityIdentity::new(
            "Test".to_string(),
            "Test".to_string(),
            "https://test.com".to_string(),
        );

        let auth_id = authority.authority_id().clone();

        store
            .add_authority(
                auth_id.clone(),
                authority.public_key(),
                authority.metadata().clone(),
                TrustLevel::SigningAuthority,
            )
            .unwrap();

        let content = b"Hello, World!";
        let signature = authority.sign_content(content).unwrap();

        // Verify with different content
        let wrong_content = b"Goodbye, World!";
        let result = store.verify_signature(&auth_id, wrong_content, &signature);

        assert!(result.is_ok());
        assert!(!result.unwrap()); // Signature should not verify
    }

    #[test]
    fn test_verify_signature_unknown_authority() {
        let store = AuthorityTrustStore::new();
        let authority = AuthorityIdentity::new(
            "Unknown".to_string(),
            "Unknown".to_string(),
            "https://unknown.com".to_string(),
        );

        let content = b"Hello, World!";
        let signature = authority.sign_content(content).unwrap();

        let result = store.verify_signature(authority.authority_id(), content, &signature);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::error::MesharaError::Authority(AuthorityError::UnknownAuthority { .. })
        ));
    }

    #[test]
    fn test_is_trusted() {
        let store = AuthorityTrustStore::new();
        let authority = AuthorityIdentity::new(
            "Test".to_string(),
            "Test".to_string(),
            "https://test.com".to_string(),
        );

        let auth_id = authority.authority_id().clone();

        store
            .add_authority(
                auth_id.clone(),
                authority.public_key(),
                authority.metadata().clone(),
                TrustLevel::UpdateAuthority,
            )
            .unwrap();

        assert!(store.is_trusted(&auth_id, TrustLevel::UpdateAuthority));
        assert!(!store.is_trusted(&auth_id, TrustLevel::SigningAuthority));
        assert!(!store.is_trusted(&auth_id, TrustLevel::FullTrust));
    }

    #[test]
    fn test_is_trusted_full_trust() {
        let store = AuthorityTrustStore::new();
        let authority = AuthorityIdentity::new(
            "Test".to_string(),
            "Test".to_string(),
            "https://test.com".to_string(),
        );

        let auth_id = authority.authority_id().clone();

        store
            .add_authority(
                auth_id.clone(),
                authority.public_key(),
                authority.metadata().clone(),
                TrustLevel::FullTrust,
            )
            .unwrap();

        // Full trust should include all levels
        assert!(store.is_trusted(&auth_id, TrustLevel::UpdateAuthority));
        assert!(store.is_trusted(&auth_id, TrustLevel::SigningAuthority));
        assert!(store.is_trusted(&auth_id, TrustLevel::BootstrapAuthority));
        assert!(store.is_trusted(&auth_id, TrustLevel::FullTrust));
    }

    #[test]
    fn test_list_authorities() {
        let store = AuthorityTrustStore::new();

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

        store
            .add_authority(
                auth1.authority_id().clone(),
                auth1.public_key(),
                auth1.metadata().clone(),
                TrustLevel::UpdateAuthority,
            )
            .unwrap();

        store
            .add_authority(
                auth2.authority_id().clone(),
                auth2.public_key(),
                auth2.metadata().clone(),
                TrustLevel::SigningAuthority,
            )
            .unwrap();

        let authorities = store.list_authorities();
        assert_eq!(authorities.len(), 2);
    }

    #[test]
    fn test_clear() {
        let store = AuthorityTrustStore::new();
        let authority = AuthorityIdentity::new(
            "Test".to_string(),
            "Test".to_string(),
            "https://test.com".to_string(),
        );

        store
            .add_authority(
                authority.authority_id().clone(),
                authority.public_key(),
                authority.metadata().clone(),
                TrustLevel::FullTrust,
            )
            .unwrap();

        assert_eq!(store.count(), 1);

        store.clear();

        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_update_trust_level() {
        let store = AuthorityTrustStore::new();
        let authority = AuthorityIdentity::new(
            "Test".to_string(),
            "Test".to_string(),
            "https://test.com".to_string(),
        );

        let auth_id = authority.authority_id().clone();

        store
            .add_authority(
                auth_id.clone(),
                authority.public_key(),
                authority.metadata().clone(),
                TrustLevel::UpdateAuthority,
            )
            .unwrap();

        assert!(store.is_trusted(&auth_id, TrustLevel::UpdateAuthority));
        assert!(!store.is_trusted(&auth_id, TrustLevel::SigningAuthority));

        // Update to full trust
        store
            .update_trust_level(&auth_id, TrustLevel::FullTrust)
            .unwrap();

        assert!(store.is_trusted(&auth_id, TrustLevel::UpdateAuthority));
        assert!(store.is_trusted(&auth_id, TrustLevel::SigningAuthority));
    }

    #[test]
    fn test_update_trust_level_unknown_authority() {
        let store = AuthorityTrustStore::new();
        let authority = AuthorityIdentity::new(
            "Unknown".to_string(),
            "Unknown".to_string(),
            "https://unknown.com".to_string(),
        );

        let result = store.update_trust_level(authority.authority_id(), TrustLevel::FullTrust);

        assert!(result.is_err());
    }

    #[test]
    fn test_trusted_authority_serialization() {
        let authority = AuthorityIdentity::new(
            "Test".to_string(),
            "Test".to_string(),
            "https://test.com".to_string(),
        );

        let trusted = TrustedAuthority {
            authority_id: authority.authority_id().clone(),
            public_key: authority.public_key(),
            metadata: authority.metadata().clone(),
            trust_level: TrustLevel::FullTrust,
            added_at: current_timestamp_ms(),
        };

        let serialized = serde_json::to_string(&trusted).unwrap();
        let deserialized: TrustedAuthority = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.authority_id, trusted.authority_id);
        assert_eq!(deserialized.trust_level, trusted.trust_level);
    }
}

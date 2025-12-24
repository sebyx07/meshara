//! Update package handling and verification
//!
//! This module provides functionality for building, signing, and verifying
//! software update packages distributed through the authority system.

use crate::authority::keys::{AuthorityId, AuthorityIdentity};
use crate::authority::trust::{AuthorityTrustStore, TrustLevel};
use crate::crypto::Signature;
use crate::error::{AuthorityError, ProtocolError, Result};
use crate::protocol::UpdatePackage;
use prost::Message;

/// Builder for constructing update packages
///
/// This provides a fluent API for creating update packages with all required
/// fields and proper signing.
pub struct UpdatePackageBuilder {
    version: String,
    package_data: Vec<u8>,
    changelog: String,
    required_version: Option<String>,
}

impl UpdatePackageBuilder {
    /// Create a new update package builder
    ///
    /// # Arguments
    /// * `version` - Semantic version of the update (e.g., "1.2.3")
    pub fn new(version: String) -> Self {
        Self {
            version,
            package_data: Vec::new(),
            changelog: String::new(),
            required_version: None,
        }
    }

    /// Set the package data (binary content)
    ///
    /// # Arguments
    /// * `data` - Binary package data (can be compressed)
    pub fn with_package_data(mut self, data: Vec<u8>) -> Self {
        self.package_data = data;
        self
    }

    /// Set the changelog
    ///
    /// # Arguments
    /// * `changelog` - Human-readable changelog describing the changes
    pub fn with_changelog(mut self, changelog: String) -> Self {
        self.changelog = changelog;
        self
    }

    /// Set the minimum required version
    ///
    /// Updates will only be applied if the current version meets this requirement.
    ///
    /// # Arguments
    /// * `version` - Minimum required version
    pub fn with_required_version(mut self, version: String) -> Self {
        self.required_version = Some(version);
        self
    }

    /// Build and sign the update package with a single authority
    ///
    /// This computes the checksum and signs the package with the authority's key.
    ///
    /// # Arguments
    /// * `authority` - The authority identity to sign with
    pub fn build(self, authority: &AuthorityIdentity) -> Result<UpdatePackage> {
        // Compute checksum (BLAKE3 hash)
        let checksum = blake3::hash(&self.package_data);

        // Create the package structure
        let package = UpdatePackage {
            version: self.version,
            package_data: self.package_data,
            changelog: self.changelog,
            checksum: checksum.as_bytes().to_vec(),
            required_version: self.required_version.unwrap_or_default(),
            signatures: Vec::new(),
            authority_public_keys: Vec::new(),
        };

        // Sign the package
        let signature = sign_update_package(&package, authority)?;

        // Add signature and public key
        let signed_package = UpdatePackage {
            signatures: vec![signature.to_bytes().to_vec()],
            authority_public_keys: vec![authority.public_key().to_bytes()],
            ..package
        };

        Ok(signed_package)
    }

    /// Build a multi-signature update package
    ///
    /// This creates an update package that requires multiple authority signatures.
    /// The package is initially unsigned - use `add_signature` to sign with each authority.
    pub fn build_unsigned(self) -> Result<UpdatePackage> {
        // Compute checksum
        let checksum = blake3::hash(&self.package_data);

        Ok(UpdatePackage {
            version: self.version,
            package_data: self.package_data,
            changelog: self.changelog,
            checksum: checksum.as_bytes().to_vec(),
            required_version: self.required_version.unwrap_or_default(),
            signatures: Vec::new(),
            authority_public_keys: Vec::new(),
        })
    }
}

/// Sign an update package with an authority's private key
///
/// This creates a signature over the canonical representation of the update package.
///
/// # Arguments
/// * `package` - The update package to sign
/// * `authority` - The authority to sign with
fn sign_update_package(
    package: &UpdatePackage,
    authority: &AuthorityIdentity,
) -> Result<Signature> {
    // Create canonical representation (package without signatures)
    let canonical = UpdatePackage {
        signatures: Vec::new(),
        authority_public_keys: Vec::new(),
        ..package.clone()
    };

    // Serialize to bytes
    let mut buf = Vec::new();
    canonical
        .encode(&mut buf)
        .map_err(|e| ProtocolError::SerializationFailed {
            message_type: "UpdatePackage".to_string(),
            reason: e.to_string(),
        })?;

    // Sign the bytes
    authority.sign_content(&buf)
}

/// Verify an update package's integrity and signatures
///
/// This checks:
/// 1. Checksum matches package data
/// 2. All signatures are valid and from trusted authorities
/// 3. Required number of trusted authorities have signed
///
/// # Arguments
/// * `package` - The update package to verify
/// * `trust_store` - Trust store containing trusted authorities
/// * `min_signatures` - Minimum number of valid signatures required (for multi-sig)
pub fn verify_update_package(
    package: &UpdatePackage,
    trust_store: &AuthorityTrustStore,
    min_signatures: usize,
) -> Result<bool> {
    // Verify checksum
    let computed_checksum = blake3::hash(&package.package_data);
    if computed_checksum.as_bytes() != package.checksum.as_slice() {
        return Err(AuthorityError::UpdateVerificationFailed {
            reason: "Checksum mismatch".to_string(),
        }
        .into());
    }

    // Verify we have at least minimum required signatures
    if package.signatures.len() < min_signatures {
        return Err(AuthorityError::UpdateVerificationFailed {
            reason: format!(
                "Insufficient signatures: {} required, {} provided",
                min_signatures,
                package.signatures.len()
            ),
        }
        .into());
    }

    // Verify signatures match public keys
    if package.signatures.len() != package.authority_public_keys.len() {
        return Err(AuthorityError::UpdateVerificationFailed {
            reason: "Signature count doesn't match public key count".to_string(),
        }
        .into());
    }

    // Create canonical representation for signature verification
    let canonical = UpdatePackage {
        signatures: Vec::new(),
        authority_public_keys: Vec::new(),
        ..package.clone()
    };

    let mut buf = Vec::new();
    canonical
        .encode(&mut buf)
        .map_err(|e| ProtocolError::SerializationFailed {
            message_type: "UpdatePackage".to_string(),
            reason: e.to_string(),
        })?;

    // Verify each signature
    let mut valid_trusted_signatures = 0;

    for (sig_bytes, pubkey_bytes) in package
        .signatures
        .iter()
        .zip(package.authority_public_keys.iter())
    {
        // Parse public key
        let pubkey = crate::crypto::PublicKey::from_bytes(pubkey_bytes).map_err(|_| {
            AuthorityError::UpdateVerificationFailed {
                reason: "Invalid public key in package".to_string(),
            }
        })?;

        // Derive authority ID
        let authority_id = AuthorityId::from_public_key(&pubkey);

        // Check if authority is trusted for updates
        if !trust_store.is_trusted(&authority_id, TrustLevel::UpdateAuthority) {
            // Skip untrusted authorities (don't count their signatures)
            continue;
        }

        // Parse signature (convert Vec to array)
        let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
            AuthorityError::UpdateVerificationFailed {
                reason: "Invalid signature length".to_string(),
            }
        })?;
        let signature = Signature::from_bytes(&sig_array).map_err(|_| {
            AuthorityError::UpdateVerificationFailed {
                reason: "Invalid signature format".to_string(),
            }
        })?;

        // Verify signature
        match trust_store.verify_signature(&authority_id, &buf, &signature) {
            Ok(true) => valid_trusted_signatures += 1,
            Ok(false) => {
                return Err(AuthorityError::InvalidSignature {
                    authority_id: authority_id.to_string(),
                }
                .into());
            },
            Err(e) => return Err(e),
        }
    }

    // Check if we have enough trusted signatures
    if valid_trusted_signatures < min_signatures {
        return Err(AuthorityError::UpdateVerificationFailed {
            reason: format!(
                "Insufficient trusted signatures: {} required, {} valid",
                min_signatures, valid_trusted_signatures
            ),
        }
        .into());
    }

    Ok(true)
}

/// Add a signature to an update package
///
/// This is used for building multi-signature packages.
///
/// # Arguments
/// * `package` - The package to add signature to
/// * `authority` - The authority to sign with
pub fn add_signature(package: &mut UpdatePackage, authority: &AuthorityIdentity) -> Result<()> {
    let signature = sign_update_package(package, authority)?;

    package.signatures.push(signature.to_bytes().to_vec());
    package
        .authority_public_keys
        .push(authority.public_key().to_bytes());

    Ok(())
}

/// Check if the current version meets the update's requirements
///
/// # Arguments
/// * `required_version` - Required version string
/// * `current_version` - Current version string
pub fn meets_version_requirement(required_version: &str, current_version: &str) -> bool {
    if required_version.is_empty() {
        return true; // No requirement specified
    }

    // Simple string comparison (in production, use semver crate)
    // For now, just check if they're equal or current is "newer"
    current_version >= required_version
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_package_builder() {
        let authority = AuthorityIdentity::new(
            "Test Authority".to_string(),
            "Testing".to_string(),
            "https://test.com".to_string(),
        );

        let package_data = b"fake binary data".to_vec();

        let package = UpdatePackageBuilder::new("1.0.0".to_string())
            .with_package_data(package_data.clone())
            .with_changelog("Initial release".to_string())
            .with_required_version("0.9.0".to_string())
            .build(&authority)
            .unwrap();

        assert_eq!(package.version, "1.0.0");
        assert_eq!(package.package_data, package_data);
        assert_eq!(package.changelog, "Initial release");
        assert_eq!(package.required_version, "0.9.0");
        assert_eq!(package.signatures.len(), 1);
        assert_eq!(package.authority_public_keys.len(), 1);
    }

    #[test]
    fn test_update_package_checksum() {
        let authority = AuthorityIdentity::new(
            "Test".to_string(),
            "Test".to_string(),
            "https://test.com".to_string(),
        );

        let package_data = b"test data".to_vec();
        let expected_checksum = blake3::hash(&package_data);

        let package = UpdatePackageBuilder::new("1.0.0".to_string())
            .with_package_data(package_data)
            .build(&authority)
            .unwrap();

        assert_eq!(package.checksum, expected_checksum.as_bytes());
    }

    #[test]
    fn test_verify_update_package_valid() {
        let authority = AuthorityIdentity::new(
            "Test Authority".to_string(),
            "Testing".to_string(),
            "https://test.com".to_string(),
        );

        let trust_store = AuthorityTrustStore::new();
        trust_store
            .add_authority(
                authority.authority_id().clone(),
                authority.public_key(),
                authority.metadata().clone(),
                TrustLevel::UpdateAuthority,
            )
            .unwrap();

        let package = UpdatePackageBuilder::new("1.0.0".to_string())
            .with_package_data(b"test data".to_vec())
            .with_changelog("Test update".to_string())
            .build(&authority)
            .unwrap();

        let result = verify_update_package(&package, &trust_store, 1);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_update_package_untrusted_authority() {
        let authority = AuthorityIdentity::new(
            "Untrusted".to_string(),
            "Test".to_string(),
            "https://test.com".to_string(),
        );

        let trust_store = AuthorityTrustStore::new();
        // Don't add authority to trust store

        let package = UpdatePackageBuilder::new("1.0.0".to_string())
            .with_package_data(b"test data".to_vec())
            .build(&authority)
            .unwrap();

        let result = verify_update_package(&package, &trust_store, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_update_package_corrupted_checksum() {
        let authority = AuthorityIdentity::new(
            "Test".to_string(),
            "Test".to_string(),
            "https://test.com".to_string(),
        );

        let trust_store = AuthorityTrustStore::new();
        trust_store
            .add_authority(
                authority.authority_id().clone(),
                authority.public_key(),
                authority.metadata().clone(),
                TrustLevel::UpdateAuthority,
            )
            .unwrap();

        let mut package = UpdatePackageBuilder::new("1.0.0".to_string())
            .with_package_data(b"test data".to_vec())
            .build(&authority)
            .unwrap();

        // Corrupt the checksum
        package.checksum[0] ^= 0xFF;

        let result = verify_update_package(&package, &trust_store, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_multi_signature_package() {
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

        let trust_store = AuthorityTrustStore::new();

        trust_store
            .add_authority(
                auth1.authority_id().clone(),
                auth1.public_key(),
                auth1.metadata().clone(),
                TrustLevel::UpdateAuthority,
            )
            .unwrap();

        trust_store
            .add_authority(
                auth2.authority_id().clone(),
                auth2.public_key(),
                auth2.metadata().clone(),
                TrustLevel::UpdateAuthority,
            )
            .unwrap();

        // Build unsigned package
        let mut package = UpdatePackageBuilder::new("2.0.0".to_string())
            .with_package_data(b"multi-sig update".to_vec())
            .with_changelog("Multi-signature update".to_string())
            .build_unsigned()
            .unwrap();

        // Add signatures from both authorities
        add_signature(&mut package, &auth1).unwrap();
        add_signature(&mut package, &auth2).unwrap();

        assert_eq!(package.signatures.len(), 2);
        assert_eq!(package.authority_public_keys.len(), 2);

        // Verify with 2-of-2 threshold
        let result = verify_update_package(&package, &trust_store, 2);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_multi_signature_insufficient() {
        let auth1 = AuthorityIdentity::new(
            "Authority 1".to_string(),
            "First".to_string(),
            "https://one.com".to_string(),
        );

        let trust_store = AuthorityTrustStore::new();

        trust_store
            .add_authority(
                auth1.authority_id().clone(),
                auth1.public_key(),
                auth1.metadata().clone(),
                TrustLevel::UpdateAuthority,
            )
            .unwrap();

        // Build package with only one signature
        let package = UpdatePackageBuilder::new("2.0.0".to_string())
            .with_package_data(b"test".to_vec())
            .build(&auth1)
            .unwrap();

        // Require 2 signatures but only 1 provided
        let result = verify_update_package(&package, &trust_store, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_meets_version_requirement_empty() {
        assert!(meets_version_requirement("", "1.0.0"));
    }

    #[test]
    fn test_meets_version_requirement_equal() {
        assert!(meets_version_requirement("1.0.0", "1.0.0"));
    }

    #[test]
    fn test_meets_version_requirement_newer() {
        assert!(meets_version_requirement("1.0.0", "1.0.1"));
        assert!(meets_version_requirement("1.0.0", "2.0.0"));
    }

    #[test]
    fn test_meets_version_requirement_older() {
        assert!(!meets_version_requirement("2.0.0", "1.0.0"));
    }

    #[test]
    fn test_add_signature() {
        let auth1 = AuthorityIdentity::new(
            "Auth 1".to_string(),
            "First".to_string(),
            "https://one.com".to_string(),
        );

        let auth2 = AuthorityIdentity::new(
            "Auth 2".to_string(),
            "Second".to_string(),
            "https://two.com".to_string(),
        );

        let mut package = UpdatePackageBuilder::new("1.0.0".to_string())
            .with_package_data(b"data".to_vec())
            .build_unsigned()
            .unwrap();

        assert_eq!(package.signatures.len(), 0);

        add_signature(&mut package, &auth1).unwrap();
        assert_eq!(package.signatures.len(), 1);

        add_signature(&mut package, &auth2).unwrap();
        assert_eq!(package.signatures.len(), 2);
    }
}

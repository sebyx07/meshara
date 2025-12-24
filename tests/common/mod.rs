//! Common test helpers and utilities
//!
//! This module provides shared test fixtures and utilities for integration tests.

use meshara::crypto::Identity;
use tempfile::TempDir;

/// Create a test identity with default seed for deterministic testing
pub fn create_test_identity() -> Identity {
    Identity::generate()
}

/// Create a test identity from a specific seed value
///
/// This allows creating multiple different identities deterministically.
///
/// # Arguments
///
/// * `seed` - A single byte that will be repeated to form the 32-byte seed
pub fn create_test_identity_from_seed(seed: u8) -> Identity {
    let seed_bytes = [seed; 32];
    Identity::from_seed(&seed_bytes)
}

/// Create a test message with default content
pub fn create_test_message() -> Vec<u8> {
    b"test message".to_vec()
}

/// Create a temporary storage directory for tests
///
/// The directory will be automatically cleaned up when the returned `TempDir` is dropped.
pub fn create_temp_storage() -> TempDir {
    TempDir::new().unwrap()
}

/// Create multiple test identities for multi-party tests
///
/// # Arguments
///
/// * `count` - Number of identities to create
pub fn create_test_identities(count: usize) -> Vec<Identity> {
    (0..count)
        .map(|i| create_test_identity_from_seed(i as u8))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_test_identity() {
        let identity = create_test_identity();
        let public_key = identity.public_key();
        assert_eq!(public_key.to_bytes().len(), 64);
    }

    #[test]
    fn test_create_test_identity_from_seed() {
        let identity1 = create_test_identity_from_seed(1);
        let identity2 = create_test_identity_from_seed(1);
        let identity3 = create_test_identity_from_seed(2);

        // Same seed produces same identity
        assert_eq!(
            identity1.public_key().fingerprint(),
            identity2.public_key().fingerprint()
        );

        // Different seed produces different identity
        assert_ne!(
            identity1.public_key().fingerprint(),
            identity3.public_key().fingerprint()
        );
    }

    #[test]
    fn test_create_test_message() {
        let message = create_test_message();
        assert_eq!(message, b"test message");
    }

    #[test]
    fn test_create_temp_storage() {
        let temp_dir = create_temp_storage();
        assert!(temp_dir.path().exists());
    }

    #[test]
    fn test_create_test_identities() {
        let identities = create_test_identities(5);
        assert_eq!(identities.len(), 5);

        // Each identity should be unique
        for i in 0..identities.len() {
            for j in (i + 1)..identities.len() {
                assert_ne!(
                    identities[i].public_key().fingerprint(),
                    identities[j].public_key().fingerprint()
                );
            }
        }
    }
}

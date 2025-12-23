//! Digital signature operations using Ed25519
//!
//! Provides high-level functions for signing and verifying messages.

use super::keys::{Identity, PublicKey};
use crate::error::Result;
use ed25519_dalek::{Signature as Ed25519Signature, Signer, Verifier};

/// A digital signature (64 bytes)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(Ed25519Signature);

impl Signature {
    /// Convert signature to bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }

    /// Create signature from bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - The signature bytes (must be exactly 64 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes don't form a valid signature
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self> {
        let sig = Ed25519Signature::from_bytes(bytes);
        Ok(Signature(sig))
    }
}

/// Sign a message with an identity's signing key
///
/// Uses Ed25519 signature algorithm. The resulting signature is 64 bytes.
///
/// # Arguments
///
/// * `identity` - The identity to sign with
/// * `message` - The message bytes to sign
///
/// # Example
///
/// ```
/// use meshara::crypto::{Identity, sign_message};
///
/// let identity = Identity::generate();
/// let message = b"Hello, Meshara!";
/// let signature = sign_message(&identity, message);
/// ```
pub fn sign_message(identity: &Identity, message: &[u8]) -> Signature {
    let signature = identity.signing_keypair().sign(message);
    Signature(signature)
}

/// Verify a signature on a message
///
/// Uses constant-time comparison to prevent timing attacks.
///
/// # Arguments
///
/// * `public_key` - The public key of the signer
/// * `message` - The message bytes that were signed
/// * `signature` - The signature to verify
///
/// # Returns
///
/// `true` if the signature is valid, `false` otherwise
///
/// # Example
///
/// ```
/// use meshara::crypto::{Identity, sign_message, verify_signature};
///
/// let identity = Identity::generate();
/// let public_key = identity.public_key();
/// let message = b"Hello, Meshara!";
///
/// let signature = sign_message(&identity, message);
/// assert!(verify_signature(&public_key, message, &signature));
/// ```
pub fn verify_signature(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    public_key
        .signing_key()
        .verify(message, &signature.0)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let identity = Identity::generate();
        let public_key = identity.public_key();
        let message = b"Test message";

        let signature = sign_message(&identity, message);
        assert!(verify_signature(&public_key, message, &signature));
    }

    #[test]
    fn test_verify_fails_with_wrong_message() {
        let identity = Identity::generate();
        let public_key = identity.public_key();

        let message = b"Original message";
        let signature = sign_message(&identity, message);

        let wrong_message = b"Modified message";
        assert!(!verify_signature(&public_key, wrong_message, &signature));
    }

    #[test]
    fn test_verify_fails_with_wrong_key() {
        let identity1 = Identity::generate();
        let identity2 = Identity::generate();

        let message = b"Test message";
        let signature = sign_message(&identity1, message);

        let public_key2 = identity2.public_key();
        assert!(!verify_signature(&public_key2, message, &signature));
    }

    #[test]
    fn test_signature_serialization() {
        let identity = Identity::generate();
        let message = b"Test message";

        let signature = sign_message(&identity, message);
        let bytes = signature.to_bytes();

        let deserialized = Signature::from_bytes(&bytes).unwrap();
        assert_eq!(signature, deserialized);
    }

    #[test]
    fn test_various_message_sizes() {
        let identity = Identity::generate();
        let public_key = identity.public_key();

        // Empty message
        let sig = sign_message(&identity, b"");
        assert!(verify_signature(&public_key, b"", &sig));

        // Single byte
        let sig = sign_message(&identity, b"a");
        assert!(verify_signature(&public_key, b"a", &sig));

        // Large message
        let large_message = vec![0u8; 10000];
        let sig = sign_message(&identity, &large_message);
        assert!(verify_signature(&public_key, &large_message, &sig));
    }
}

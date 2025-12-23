//! Encryption operations using X25519 key exchange and ChaCha20-Poly1305 AEAD
//!
//! Provides high-level functions for encrypting and decrypting messages between nodes.

use super::keys::{Identity, PublicKey};
use crate::error::{CryptoError, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

/// An encrypted message containing ciphertext and cryptographic metadata
#[derive(Clone, Debug)]
pub struct EncryptedMessage {
    /// Ephemeral public key for key exchange
    pub ephemeral_public_key: [u8; 32],
    /// Nonce for ChaCha20-Poly1305
    pub nonce: [u8; 12],
    /// Ciphertext including authentication tag
    pub ciphertext: Vec<u8>,
}

impl EncryptedMessage {
    /// Serialize the encrypted message to bytes
    ///
    /// Format: \[ephemeral_public_key (32)\]\[nonce (12)\]\[ciphertext_len (4)\]\[ciphertext\]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 12 + 4 + self.ciphertext.len());
        bytes.extend_from_slice(&self.ephemeral_public_key);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialize an encrypted message from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 32 + 12 + 4 {
            return Err(CryptoError::InvalidEncryptedData {
                context: "Encrypted message too short".to_string(),
            }
            .into());
        }

        let mut ephemeral_public_key = [0u8; 32];
        ephemeral_public_key.copy_from_slice(&data[0..32]);

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[32..44]);

        let ciphertext_len = u32::from_le_bytes([data[44], data[45], data[46], data[47]]) as usize;

        if data.len() < 48 + ciphertext_len {
            return Err(CryptoError::InvalidEncryptedData {
                context: "Incomplete ciphertext".to_string(),
            }
            .into());
        }

        let ciphertext = data[48..48 + ciphertext_len].to_vec();

        Ok(Self {
            ephemeral_public_key,
            nonce,
            ciphertext,
        })
    }
}

/// Encrypt a message for a specific recipient
///
/// Uses X25519 Diffie-Hellman key exchange to derive a shared secret,
/// then encrypts with ChaCha20-Poly1305 AEAD.
///
/// # Arguments
///
/// * `sender_identity` - The sender's identity (for key exchange)
/// * `recipient_public_key` - The recipient's public key
/// * `plaintext` - The message to encrypt
///
/// # Example
///
/// ```
/// use meshara::crypto::{Identity, encrypt_for_recipient};
///
/// let sender = Identity::generate();
/// let recipient = Identity::generate();
/// let recipient_pubkey = recipient.public_key();
///
/// let plaintext = b"Secret message";
/// let encrypted = encrypt_for_recipient(&sender, &recipient_pubkey, plaintext).unwrap();
/// ```
pub fn encrypt_for_recipient(
    _sender_identity: &Identity,
    recipient_public_key: &PublicKey,
    plaintext: &[u8],
) -> Result<EncryptedMessage> {
    // Generate ephemeral keypair for this message
    let ephemeral_secret = X25519StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    // Perform key exchange to get shared secret
    let shared_secret = ephemeral_secret.diffie_hellman(recipient_public_key.encryption_key());

    // Derive encryption key from shared secret using Blake3
    let key_hash = blake3::hash(shared_secret.as_bytes());
    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(key_hash.as_bytes());

    // Create cipher
    let cipher = ChaCha20Poly1305::new(&encryption_key.into());

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext =
        cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed {
                reason: format!("ChaCha20-Poly1305 encryption failed: {}", e),
            })?;

    // Zeroize sensitive data
    encryption_key.zeroize();

    Ok(EncryptedMessage {
        ephemeral_public_key: ephemeral_public.to_bytes(),
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt a message encrypted for this identity
///
/// Uses X25519 Diffie-Hellman key exchange to derive the same shared secret,
/// then decrypts with ChaCha20-Poly1305 AEAD and verifies the authentication tag.
///
/// # Arguments
///
/// * `recipient_identity` - The recipient's identity (for key exchange)
/// * `encrypted` - The encrypted message
///
/// # Errors
///
/// Returns an error if:
/// - The authentication tag is invalid (message was tampered with)
/// - The ciphertext is corrupted
/// - Decryption fails for any reason
///
/// # Example
///
/// ```
/// use meshara::crypto::{Identity, encrypt_for_recipient, decrypt_message};
///
/// let sender = Identity::generate();
/// let recipient = Identity::generate();
/// let recipient_pubkey = recipient.public_key();
///
/// let plaintext = b"Secret message";
/// let encrypted = encrypt_for_recipient(&sender, &recipient_pubkey, plaintext).unwrap();
/// let decrypted = decrypt_message(&recipient, &encrypted).unwrap();
///
/// assert_eq!(decrypted, plaintext);
/// ```
pub fn decrypt_message(
    recipient_identity: &Identity,
    encrypted: &EncryptedMessage,
) -> Result<Vec<u8>> {
    // Reconstruct ephemeral public key
    let ephemeral_public = X25519PublicKey::from(encrypted.ephemeral_public_key);

    // Perform key exchange to get shared secret
    let shared_secret = recipient_identity
        .encryption_keypair()
        .diffie_hellman(&ephemeral_public);

    // Derive encryption key from shared secret
    let key_hash = blake3::hash(shared_secret.as_bytes());
    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(key_hash.as_bytes());

    // Create cipher
    let cipher = ChaCha20Poly1305::new(&encryption_key.into());

    // Decrypt
    let nonce = Nonce::from_slice(&encrypted.nonce);
    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed {
            reason: "ChaCha20-Poly1305 decryption failed (authentication tag mismatch)".to_string(),
        })?;

    // Zeroize sensitive data
    encryption_key.zeroize();

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let recipient_pubkey = recipient.public_key();

        let plaintext = b"Hello, Meshara!";
        let encrypted = encrypt_for_recipient(&sender, &recipient_pubkey, plaintext).unwrap();
        let decrypted = decrypt_message(&recipient, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_fails_with_wrong_recipient() {
        let sender = Identity::generate();
        let recipient1 = Identity::generate();
        let recipient2 = Identity::generate();

        let recipient1_pubkey = recipient1.public_key();

        let plaintext = b"Secret message";
        let encrypted = encrypt_for_recipient(&sender, &recipient1_pubkey, plaintext).unwrap();

        // Try to decrypt with wrong recipient
        let result = decrypt_message(&recipient2, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_fails_with_modified_ciphertext() {
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let recipient_pubkey = recipient.public_key();

        let plaintext = b"Secret message";
        let mut encrypted = encrypt_for_recipient(&sender, &recipient_pubkey, plaintext).unwrap();

        // Modify ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        let result = decrypt_message(&recipient, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_fails_with_modified_nonce() {
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let recipient_pubkey = recipient.public_key();

        let plaintext = b"Secret message";
        let mut encrypted = encrypt_for_recipient(&sender, &recipient_pubkey, plaintext).unwrap();

        // Modify nonce
        encrypted.nonce[0] ^= 0xFF;

        let result = decrypt_message(&recipient, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_various_plaintext_sizes() {
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let recipient_pubkey = recipient.public_key();

        // Empty message
        let encrypted = encrypt_for_recipient(&sender, &recipient_pubkey, b"").unwrap();
        let decrypted = decrypt_message(&recipient, &encrypted).unwrap();
        assert_eq!(decrypted, b"");

        // Single byte
        let encrypted = encrypt_for_recipient(&sender, &recipient_pubkey, b"a").unwrap();
        let decrypted = decrypt_message(&recipient, &encrypted).unwrap();
        assert_eq!(decrypted, b"a");

        // Large message
        let large = vec![0x42u8; 10000];
        let encrypted = encrypt_for_recipient(&sender, &recipient_pubkey, &large).unwrap();
        let decrypted = decrypt_message(&recipient, &encrypted).unwrap();
        assert_eq!(decrypted, large);
    }

    #[test]
    fn test_encrypted_message_serialization() {
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let recipient_pubkey = recipient.public_key();

        let plaintext = b"Test message";
        let encrypted = encrypt_for_recipient(&sender, &recipient_pubkey, plaintext).unwrap();

        let bytes = encrypted.to_bytes();
        let deserialized = EncryptedMessage::from_bytes(&bytes).unwrap();

        let decrypted = decrypt_message(&recipient, &deserialized).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_nonce_uniqueness() {
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let recipient_pubkey = recipient.public_key();

        let plaintext = b"Same message";

        let encrypted1 = encrypt_for_recipient(&sender, &recipient_pubkey, plaintext).unwrap();
        let encrypted2 = encrypt_for_recipient(&sender, &recipient_pubkey, plaintext).unwrap();

        // Nonces should be different (probabilistically)
        assert_ne!(encrypted1.nonce, encrypted2.nonce);

        // Both should decrypt correctly
        assert_eq!(decrypt_message(&recipient, &encrypted1).unwrap(), plaintext);
        assert_eq!(decrypt_message(&recipient, &encrypted2).unwrap(), plaintext);
    }
}

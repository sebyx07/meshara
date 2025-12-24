//! Key generation and management
//!
//! This module defines the Identity and PublicKey types that represent
//! a node's cryptographic identity in the Meshara network.

use crate::error::{CryptoError, Result};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A complete cryptographic identity for a Meshara node
///
/// Contains both signing and encryption keypairs. Must be kept secure.
#[derive(ZeroizeOnDrop)]
pub struct Identity {
    /// Ed25519 signing keypair
    signing_keypair: SigningKey,
    /// X25519 encryption keypair
    encryption_keypair: X25519StaticSecret,
}

impl Identity {
    /// Generate a new random identity
    ///
    /// Uses the system's cryptographically secure random number generator.
    ///
    /// # Example
    ///
    /// ```
    /// use meshara::crypto::Identity;
    ///
    /// let identity = Identity::generate();
    /// let public_key = identity.public_key();
    /// ```
    pub fn generate() -> Self {
        let mut csprng = OsRng;

        // Generate Ed25519 signing key
        let signing_keypair = SigningKey::generate(&mut csprng);

        // Generate X25519 encryption key
        let encryption_keypair = X25519StaticSecret::random_from_rng(csprng);

        Self {
            signing_keypair,
            encryption_keypair,
        }
    }

    /// Generate a deterministic identity from a seed
    ///
    /// This is useful for testing and for deterministic key derivation.
    /// The seed must be exactly 32 bytes.
    ///
    /// # Arguments
    ///
    /// * `seed` - A 32-byte seed for deterministic key generation
    ///
    /// # Panics
    ///
    /// Panics if the seed is not exactly 32 bytes (in debug builds)
    ///
    /// # Example
    ///
    /// ```
    /// use meshara::crypto::Identity;
    ///
    /// let seed = [0u8; 32];
    /// let identity = Identity::from_seed(&seed);
    /// ```
    pub fn from_seed(seed: &[u8]) -> Self {
        debug_assert_eq!(seed.len(), 32, "Seed must be exactly 32 bytes");

        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(&seed[..32.min(seed.len())]);

        // Generate Ed25519 signing key from first 32 bytes
        let signing_keypair = SigningKey::from_bytes(&seed_array);

        // Generate X25519 encryption key from same seed
        // In production, you might want to derive different keys
        let encryption_keypair = X25519StaticSecret::from(seed_array);

        Self {
            signing_keypair,
            encryption_keypair,
        }
    }

    /// Extract the public key portion that can be safely shared
    ///
    /// # Example
    ///
    /// ```
    /// use meshara::crypto::Identity;
    ///
    /// let identity = Identity::generate();
    /// let public_key = identity.public_key();
    /// // Share public_key with others
    /// ```
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            signing_key: self.signing_keypair.verifying_key(),
            encryption_key: X25519PublicKey::from(&self.encryption_keypair),
        }
    }

    /// Get the NodeId for this identity
    ///
    /// The NodeId is derived by hashing the public key with Blake3.
    /// It serves as a stable identifier for routing and DHT operations.
    ///
    /// # Example
    ///
    /// ```
    /// use meshara::crypto::Identity;
    ///
    /// let identity = Identity::generate();
    /// let node_id = identity.node_id();
    /// println!("Node ID: {}", node_id);
    /// ```
    pub fn node_id(&self) -> crate::crypto::NodeId {
        crate::crypto::hash_public_key(&self.public_key())
    }

    /// Export the identity encrypted with a passphrase
    ///
    /// Uses Argon2 for key derivation and ChaCha20-Poly1305 for encryption.
    /// The result can be safely stored on disk or backed up.
    ///
    /// Format: [salt (16 bytes)][nonce (12 bytes)][ciphertext][auth_tag (16 bytes)]
    ///
    /// # Arguments
    ///
    /// * `passphrase` - The passphrase to encrypt with
    ///
    /// # Example
    ///
    /// ```
    /// use meshara::crypto::Identity;
    ///
    /// let identity = Identity::generate();
    /// let encrypted = identity.export_encrypted("strong passphrase").unwrap();
    /// // Save encrypted data to disk
    /// ```
    pub fn export_encrypted(&self, passphrase: &str) -> Result<Vec<u8>> {
        // Generate random salt for Argon2
        let salt = SaltString::generate(&mut OsRng);

        // Derive key from passphrase using Argon2
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(passphrase.as_bytes(), &salt)
            .map_err(|e| CryptoError::KeyDerivationFailed {
                reason: format!("Key derivation failed: {}", e),
            })?;

        // Extract the derived key (32 bytes for ChaCha20-Poly1305)
        let derived_key = password_hash
            .hash
            .ok_or_else(|| CryptoError::KeyDerivationFailed {
                reason: "Failed to extract derived key".to_string(),
            })?;

        let key_bytes = derived_key.as_bytes();
        if key_bytes.len() < 32 {
            return Err(CryptoError::KeyDerivationFailed {
                reason: "Derived key too short".to_string(),
            }
            .into());
        }

        let mut cipher_key = [0u8; 32];
        cipher_key.copy_from_slice(&key_bytes[..32]);

        // Create cipher
        let cipher = ChaCha20Poly1305::new(&cipher_key.into());

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Serialize identity (signing key || encryption key)
        let signing_bytes = self.signing_keypair.to_bytes();
        let encryption_bytes = self.encryption_keypair.to_bytes();

        let mut plaintext = Vec::with_capacity(64);
        plaintext.extend_from_slice(&signing_bytes);
        plaintext.extend_from_slice(&encryption_bytes);

        // Encrypt
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).map_err(|e| {
            CryptoError::EncryptionFailed {
                reason: format!("Encryption failed: {}", e),
            }
        })?;

        // Build output: salt || nonce || ciphertext (includes auth tag)
        let salt_bytes = salt.as_str().as_bytes();
        let mut output = Vec::with_capacity(salt_bytes.len() + 12 + ciphertext.len());
        output.extend_from_slice(salt_bytes);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        // Zeroize sensitive data
        cipher_key.zeroize();
        plaintext.zeroize();

        Ok(output)
    }

    /// Import an identity from encrypted data
    ///
    /// Decrypts and deserializes an identity that was previously exported
    /// with `export_encrypted`.
    ///
    /// # Arguments
    ///
    /// * `data` - The encrypted identity data
    /// * `passphrase` - The passphrase to decrypt with
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The data is corrupted or invalid
    /// - The passphrase is incorrect
    /// - The authentication tag verification fails
    ///
    /// # Example
    ///
    /// ```
    /// use meshara::crypto::Identity;
    ///
    /// # let identity = Identity::generate();
    /// # let encrypted = identity.export_encrypted("strong passphrase").unwrap();
    /// let imported = Identity::import_encrypted(&encrypted, "strong passphrase").unwrap();
    /// ```
    pub fn import_encrypted(data: &[u8], passphrase: &str) -> Result<Self> {
        // Salt string is variable length but typically ~22 chars for base64
        // We'll look for the end of the salt string (should end with specific chars)
        // For simplicity, SaltString encoding is predictable - it's 22 chars
        if data.len() < 22 + 12 + 16 {
            return Err(CryptoError::InvalidEncryptedData {
                context: "Encrypted data too short".to_string(),
            }
            .into());
        }

        // Extract salt (first 22 bytes for SaltString)
        let salt_str =
            std::str::from_utf8(&data[..22]).map_err(|_| CryptoError::InvalidEncryptedData {
                context: "Invalid salt encoding".to_string(),
            })?;
        let salt =
            SaltString::from_b64(salt_str).map_err(|_| CryptoError::InvalidEncryptedData {
                context: "Invalid salt".to_string(),
            })?;

        // Extract nonce (next 12 bytes)
        let nonce_bytes = &data[22..34];
        let nonce = Nonce::from_slice(nonce_bytes);

        // Extract ciphertext (rest)
        let ciphertext = &data[34..];

        // Derive key from passphrase
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(passphrase.as_bytes(), &salt)
            .map_err(|e| CryptoError::KeyDerivationFailed {
                reason: format!("Key derivation failed: {}", e),
            })?;

        let derived_key = password_hash
            .hash
            .ok_or_else(|| CryptoError::KeyDerivationFailed {
                reason: "Failed to extract derived key".to_string(),
            })?;

        let key_bytes = derived_key.as_bytes();
        if key_bytes.len() < 32 {
            return Err(CryptoError::KeyDerivationFailed {
                reason: "Derived key too short".to_string(),
            }
            .into());
        }

        let mut cipher_key = [0u8; 32];
        cipher_key.copy_from_slice(&key_bytes[..32]);

        // Create cipher
        let cipher = ChaCha20Poly1305::new(&cipher_key.into());

        // Decrypt
        let mut plaintext =
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| CryptoError::DecryptionFailed {
                    reason: "Decryption failed (wrong passphrase or corrupted data)".to_string(),
                })?;

        // Verify length
        if plaintext.len() != 64 {
            plaintext.zeroize();
            return Err(CryptoError::InvalidEncryptedData {
                context: "Invalid identity data length".to_string(),
            }
            .into());
        }

        // Extract keys
        let mut signing_bytes = [0u8; 32];
        let mut encryption_bytes = [0u8; 32];
        signing_bytes.copy_from_slice(&plaintext[..32]);
        encryption_bytes.copy_from_slice(&plaintext[32..64]);

        let signing_keypair = SigningKey::from_bytes(&signing_bytes);
        let encryption_keypair = X25519StaticSecret::from(encryption_bytes);

        // Zeroize sensitive data
        cipher_key.zeroize();
        plaintext.zeroize();
        signing_bytes.zeroize();
        encryption_bytes.zeroize();

        Ok(Self {
            signing_keypair,
            encryption_keypair,
        })
    }

    /// Get reference to the signing keypair (internal use)
    pub(crate) fn signing_keypair(&self) -> &SigningKey {
        &self.signing_keypair
    }

    /// Get reference to the encryption keypair (internal use)
    pub(crate) fn encryption_keypair(&self) -> &X25519StaticSecret {
        &self.encryption_keypair
    }

    /// Create identity from raw key bytes (internal use only)
    ///
    /// This is used by the storage layer to reconstruct identities from disk.
    ///
    /// # Arguments
    ///
    /// * `signing_bytes` - Ed25519 signing key bytes (32 bytes)
    /// * `encryption_bytes` - X25519 encryption key bytes (32 bytes)
    ///
    /// # Security
    ///
    /// This method should only be used internally by trusted storage code.
    /// The caller must ensure bytes are zeroized after use.
    pub(crate) fn from_raw_bytes(signing_bytes: &[u8; 32], encryption_bytes: &[u8; 32]) -> Self {
        let signing_keypair = SigningKey::from_bytes(signing_bytes);
        let encryption_keypair = X25519StaticSecret::from(*encryption_bytes);

        Self {
            signing_keypair,
            encryption_keypair,
        }
    }
}

/// Public key that can be safely shared with others
///
/// Contains the public portions of both signing and encryption keys.
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// Ed25519 public signing key
    signing_key: VerifyingKey,
    /// X25519 public encryption key
    encryption_key: X25519PublicKey,
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for PublicKey {}

impl serde::Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::de::Deserialize::deserialize(deserializer)?;
        PublicKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl PublicKey {
    /// Get a human-readable fingerprint of this public key
    ///
    /// Uses Blake3 hash and returns a hexadecimal string.
    ///
    /// # Example
    ///
    /// ```
    /// use meshara::crypto::Identity;
    ///
    /// let identity = Identity::generate();
    /// let public_key = identity.public_key();
    /// println!("Fingerprint: {}", public_key.fingerprint());
    /// ```
    pub fn fingerprint(&self) -> String {
        let bytes = self.to_bytes();
        let hash = blake3::hash(&bytes);
        hash.as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    /// Serialize the public key to bytes
    ///
    /// Format: [signing_key (32 bytes)][encryption_key (32 bytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(self.signing_key.as_bytes());
        bytes.extend_from_slice(self.encryption_key.as_bytes());
        bytes
    }

    /// Deserialize a public key from bytes
    ///
    /// # Arguments
    ///
    /// * `data` - The serialized public key (64 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if the data is not exactly 64 bytes or is invalid.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != 64 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 64,
                got: data.len(),
            }
            .into());
        }

        let signing_key = VerifyingKey::from_bytes(data[..32].try_into().map_err(|_| {
            CryptoError::InvalidKeyLength {
                expected: 32,
                got: data[..32].len(),
            }
        })?)
        .map_err(|_e| CryptoError::InvalidKeyLength {
            expected: 32,
            got: 0,
        })?;

        let encryption_key =
            X25519PublicKey::from(<[u8; 32]>::try_from(&data[32..64]).map_err(|_| {
                CryptoError::InvalidKeyLength {
                    expected: 32,
                    got: data[32..64].len(),
                }
            })?);

        Ok(Self {
            signing_key,
            encryption_key,
        })
    }

    /// Get reference to the signing key (internal use)
    pub(crate) fn signing_key(&self) -> &VerifyingKey {
        &self.signing_key
    }

    /// Get reference to the encryption key (internal use)
    pub(crate) fn encryption_key(&self) -> &X25519PublicKey {
        &self.encryption_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let identity = Identity::generate();
        let public_key = identity.public_key();

        // Verify we can get fingerprint
        let fingerprint = public_key.fingerprint();
        assert_eq!(fingerprint.len(), 64); // Blake3 hash is 32 bytes = 64 hex chars
    }

    #[test]
    fn test_identity_from_seed() {
        let seed = [42u8; 32];
        let identity1 = Identity::from_seed(&seed);
        let identity2 = Identity::from_seed(&seed);

        let pk1 = identity1.public_key();
        let pk2 = identity2.public_key();

        assert_eq!(pk1.fingerprint(), pk2.fingerprint());
    }

    #[test]
    fn test_identity_different_seeds() {
        let seed_a = [1u8; 32];
        let seed_b = [2u8; 32];

        let identity_a = Identity::from_seed(&seed_a);
        let identity_b = Identity::from_seed(&seed_b);

        let pk_a = identity_a.public_key();
        let pk_b = identity_b.public_key();

        assert_ne!(pk_a.fingerprint(), pk_b.fingerprint());
    }

    #[test]
    fn test_fingerprint_generation() {
        let identity = Identity::generate();
        let public_key = identity.public_key();

        let fingerprint1 = public_key.fingerprint();
        let fingerprint2 = public_key.fingerprint();

        // Fingerprint is deterministic
        assert_eq!(fingerprint1, fingerprint2);

        // Fingerprint is human-readable (hex string)
        assert_eq!(fingerprint1.len(), 64); // 32 bytes * 2 hex chars
        assert!(fingerprint1.chars().all(|c| c.is_ascii_hexdigit()));

        // Fingerprint only contains lowercase hex
        assert!(fingerprint1
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn test_public_key_extraction() {
        let identity = Identity::generate();
        let public_key = identity.public_key();

        // Verify public key can be extracted
        assert_eq!(public_key.to_bytes().len(), 64); // 32 + 32 bytes

        // Verify fingerprint is valid
        let fingerprint = public_key.fingerprint();
        assert_eq!(fingerprint.len(), 64);
    }

    #[test]
    fn test_public_key_serialization() {
        let identity = Identity::generate();
        let public_key = identity.public_key();

        let bytes = public_key.to_bytes();
        assert_eq!(bytes.len(), 64);

        let deserialized = PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(public_key.fingerprint(), deserialized.fingerprint());
    }

    #[test]
    fn test_export_import_encrypted() {
        let identity = Identity::generate();
        let original_pubkey = identity.public_key();

        let passphrase = "test passphrase 12345";
        let encrypted = identity.export_encrypted(passphrase).unwrap();

        // Verify encrypted data has expected structure
        assert!(encrypted.len() > 22 + 12 + 32); // salt + nonce + ciphertext + tag

        let imported = Identity::import_encrypted(&encrypted, passphrase).unwrap();
        let imported_pubkey = imported.public_key();

        assert_eq!(original_pubkey.fingerprint(), imported_pubkey.fingerprint());
    }

    #[test]
    fn test_wrong_passphrase() {
        let identity = Identity::generate();
        let encrypted = identity.export_encrypted("correct passphrase").unwrap();

        let result = Identity::import_encrypted(&encrypted, "wrong passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_data() {
        let identity = Identity::generate();
        let mut encrypted = identity.export_encrypted("passphrase").unwrap();

        // Corrupt the ciphertext
        if encrypted.len() > 50 {
            encrypted[50] ^= 0xFF;
        }

        let result = Identity::import_encrypted(&encrypted, "passphrase");
        assert!(result.is_err());
    }
}

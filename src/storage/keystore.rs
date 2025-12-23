//! Encrypted identity storage
//!
//! This module handles secure storage of cryptographic identities on disk.
//! Identities are encrypted with a user-provided passphrase using Argon2 and ChaCha20-Poly1305.

use crate::crypto::Identity;
use crate::error::{Error, Result};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params, Version,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use std::path::Path;
use zeroize::Zeroize;

/// Magic bytes to identify Meshara identity files
const MAGIC_BYTES: &[u8; 8] = b"MESHARA1";

/// Current storage format version
const STORAGE_VERSION: u32 = 1;

/// Salt length for Argon2 (128 bits)
const SALT_LEN: usize = 16;

/// Nonce length for ChaCha20-Poly1305 (96 bits)
const NONCE_LEN: usize = 12;

/// Authentication tag length (128 bits)
const TAG_LEN: usize = 16;

/// Identity data length (signing key + encryption key = 32 + 32 bytes)
const IDENTITY_DATA_LEN: usize = 64;

/// Encrypted identity file format:
/// - magic_bytes: [u8; 8] = b"MESHARA1"
/// - version: u32 (little-endian)
/// - salt: [u8; 16]
/// - nonce: [u8; 12]
/// - ciphertext: [u8; 64] (encrypted identity)
/// - auth_tag: [u8; 16] (included in ciphertext from AEAD)
///
/// Save an identity to disk, encrypted with a passphrase
///
/// The identity is encrypted using ChaCha20-Poly1305 with a key derived from
/// the passphrase using Argon2. File permissions are set to user-read-only (0600 on Unix).
///
/// # Arguments
///
/// * `path` - Path where the identity file will be saved
/// * `identity` - The identity to save
/// * `passphrase` - Passphrase for encryption
///
/// # Security
///
/// - Uses Argon2 with OWASP-recommended parameters
/// - Generates random salt and nonce
/// - Zeroizes sensitive data after use
/// - Sets restrictive file permissions
///
/// # Example
///
/// ```no_run
/// use meshara::crypto::Identity;
/// use meshara::storage::keystore::save_identity;
/// use std::path::Path;
///
/// let identity = Identity::generate();
/// save_identity(Path::new("identity.enc"), &identity, "strong passphrase").unwrap();
/// ```
pub fn save_identity(path: &Path, identity: &Identity, passphrase: &str) -> Result<()> {
    // Create parent directory if it doesn't exist
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Generate random salt
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    // Derive key from passphrase using Argon2 with OWASP parameters
    // Memory: 64 MB, Iterations: 3, Parallelism: 4
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| Error::Crypto(format!("Failed to create Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let salt_string = SaltString::encode_b64(&salt)
        .map_err(|e| Error::Crypto(format!("Failed to encode salt: {}", e)))?;

    let password_hash = argon2
        .hash_password(passphrase.as_bytes(), &salt_string)
        .map_err(|e| Error::Crypto(format!("Key derivation failed: {}", e)))?;

    let derived_key = password_hash
        .hash
        .ok_or_else(|| Error::Crypto("Failed to extract derived key".to_string()))?;

    let key_bytes = derived_key.as_bytes();
    if key_bytes.len() < 32 {
        return Err(Error::Crypto("Derived key too short".to_string()));
    }

    let mut cipher_key = [0u8; 32];
    cipher_key.copy_from_slice(&key_bytes[..32]);

    // Create cipher
    let cipher = ChaCha20Poly1305::new(&cipher_key.into());

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Get the raw key bytes from identity
    // Serialize manually: signing_key (32) || encryption_key (32)
    let signing_bytes = identity.signing_keypair().to_bytes();
    let encryption_bytes = identity.encryption_keypair().to_bytes();

    let mut plaintext = Vec::with_capacity(IDENTITY_DATA_LEN);
    plaintext.extend_from_slice(&signing_bytes);
    plaintext.extend_from_slice(&encryption_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| Error::Crypto(format!("Encryption failed: {}", e)))?;

    // Build file: magic_bytes || version || salt || nonce || ciphertext (includes auth tag)
    let mut file_data = Vec::with_capacity(8 + 4 + SALT_LEN + NONCE_LEN + ciphertext.len());
    file_data.extend_from_slice(MAGIC_BYTES);
    file_data.extend_from_slice(&STORAGE_VERSION.to_le_bytes());
    file_data.extend_from_slice(&salt);
    file_data.extend_from_slice(&nonce_bytes);
    file_data.extend_from_slice(&ciphertext);

    // Write to file
    std::fs::write(path, &file_data)?;

    // Set file permissions to user-read-only (Unix: 0600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }

    // Zeroize sensitive data
    cipher_key.zeroize();
    plaintext.zeroize();

    Ok(())
}

/// Load an identity from disk, decrypting with a passphrase
///
/// # Arguments
///
/// * `path` - Path to the identity file
/// * `passphrase` - Passphrase for decryption
///
/// # Errors
///
/// Returns an error if:
/// - The file doesn't exist or can't be read
/// - The file has an invalid format
/// - The magic bytes or version don't match
/// - The passphrase is incorrect
/// - Decryption or authentication fails
///
/// # Example
///
/// ```no_run
/// use meshara::storage::keystore::load_identity;
/// use std::path::Path;
///
/// let identity = load_identity(Path::new("identity.enc"), "strong passphrase").unwrap();
/// ```
pub fn load_identity(path: &Path, passphrase: &str) -> Result<Identity> {
    // Check if file exists
    if !path.exists() {
        return Err(Error::FileNotFound(format!(
            "Identity file not found: {}",
            path.display()
        )));
    }

    // Read file
    let file_data = std::fs::read(path)?;

    // Verify minimum size
    let min_size = 8 + 4 + SALT_LEN + NONCE_LEN + TAG_LEN;
    if file_data.len() < min_size {
        return Err(Error::InvalidFormat(format!(
            "Identity file too short: expected at least {} bytes, got {}",
            min_size,
            file_data.len()
        )));
    }

    // Verify magic bytes
    if &file_data[0..8] != MAGIC_BYTES {
        return Err(Error::InvalidFormat(
            "Invalid magic bytes (not a Meshara identity file)".to_string(),
        ));
    }

    // Extract and verify version
    let version = u32::from_le_bytes([file_data[8], file_data[9], file_data[10], file_data[11]]);

    if version != STORAGE_VERSION {
        return Err(Error::InvalidFormat(format!(
            "Unsupported storage version: {} (expected {})",
            version, STORAGE_VERSION
        )));
    }

    // Extract salt
    let salt = &file_data[12..12 + SALT_LEN];

    // Extract nonce
    let nonce_bytes = &file_data[12 + SALT_LEN..12 + SALT_LEN + NONCE_LEN];
    let nonce = Nonce::from_slice(nonce_bytes);

    // Extract ciphertext (rest of file)
    let ciphertext = &file_data[12 + SALT_LEN + NONCE_LEN..];

    // Derive key from passphrase using same Argon2 parameters
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| Error::Crypto(format!("Failed to create Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| Error::Crypto(format!("Failed to encode salt: {}", e)))?;

    let password_hash = argon2
        .hash_password(passphrase.as_bytes(), &salt_string)
        .map_err(|e| Error::Crypto(format!("Key derivation failed: {}", e)))?;

    let derived_key = password_hash
        .hash
        .ok_or_else(|| Error::Crypto("Failed to extract derived key".to_string()))?;

    let key_bytes = derived_key.as_bytes();
    if key_bytes.len() < 32 {
        return Err(Error::Crypto("Derived key too short".to_string()));
    }

    let mut cipher_key = [0u8; 32];
    cipher_key.copy_from_slice(&key_bytes[..32]);

    // Create cipher
    let cipher = ChaCha20Poly1305::new(&cipher_key.into());

    // Decrypt
    let mut plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        Error::DecryptionFailed(
            "Decryption failed (wrong passphrase or corrupted data)".to_string(),
        )
    })?;

    // Verify plaintext length
    if plaintext.len() != IDENTITY_DATA_LEN {
        plaintext.zeroize();
        cipher_key.zeroize();
        return Err(Error::InvalidFormat(format!(
            "Invalid identity data length: expected {} bytes, got {}",
            IDENTITY_DATA_LEN,
            plaintext.len()
        )));
    }

    // Extract key material
    let mut signing_bytes = [0u8; 32];
    let mut encryption_bytes = [0u8; 32];
    signing_bytes.copy_from_slice(&plaintext[..32]);
    encryption_bytes.copy_from_slice(&plaintext[32..64]);

    // Reconstruct identity from raw bytes
    let identity = Identity::from_raw_bytes(&signing_bytes, &encryption_bytes);

    // Zeroize sensitive data
    plaintext.zeroize();
    cipher_key.zeroize();
    signing_bytes.zeroize();
    encryption_bytes.zeroize();

    Ok(identity)
}

/// Check if an identity file exists and is valid
///
/// Verifies that the file exists and has the correct magic bytes.
///
/// # Arguments
///
/// * `path` - Path to check
///
/// # Example
///
/// ```no_run
/// use meshara::storage::keystore::identity_exists;
/// use std::path::Path;
///
/// if identity_exists(Path::new("identity.enc")) {
///     println!("Identity file exists");
/// }
/// ```
pub fn identity_exists(path: &Path) -> bool {
    if !path.exists() || !path.is_file() {
        return false;
    }

    // Try to read and verify magic bytes
    if let Ok(data) = std::fs::read(path) {
        if data.len() >= 8 {
            return &data[0..8] == MAGIC_BYTES;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_save_and_load_identity() {
        let temp_dir = TempDir::new().unwrap();
        let identity_path = temp_dir.path().join("identity.enc");

        let identity = Identity::generate();
        let original_pubkey = identity.public_key();
        let passphrase = "test passphrase 12345";

        // Save identity
        save_identity(&identity_path, &identity, passphrase).unwrap();

        // Check file exists
        assert!(identity_exists(&identity_path));

        // Verify file has correct permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&identity_path).unwrap();
            let permissions = metadata.permissions();
            assert_eq!(permissions.mode() & 0o777, 0o600);
        }

        // Load identity
        let loaded_identity = load_identity(&identity_path, passphrase).unwrap();
        let loaded_pubkey = loaded_identity.public_key();

        // Verify public keys match
        assert_eq!(original_pubkey.fingerprint(), loaded_pubkey.fingerprint());
    }

    #[test]
    fn test_load_wrong_passphrase() {
        let temp_dir = TempDir::new().unwrap();
        let identity_path = temp_dir.path().join("identity.enc");

        let identity = Identity::generate();
        save_identity(&identity_path, &identity, "correct passphrase").unwrap();

        let result = load_identity(&identity_path, "wrong passphrase");
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, Error::DecryptionFailed(_)));
        }
    }

    #[test]
    fn test_load_corrupted_file() {
        let temp_dir = TempDir::new().unwrap();
        let identity_path = temp_dir.path().join("identity.enc");

        let identity = Identity::generate();
        save_identity(&identity_path, &identity, "passphrase").unwrap();

        // Corrupt the file
        let mut data = std::fs::read(&identity_path).unwrap();
        if data.len() > 50 {
            data[50] ^= 0xFF;
        }
        std::fs::write(&identity_path, data).unwrap();

        let result = load_identity(&identity_path, "passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_invalid_magic_bytes() {
        let temp_dir = TempDir::new().unwrap();
        let identity_path = temp_dir.path().join("identity.enc");

        // Write file with wrong magic bytes
        let mut data = vec![0u8; 100];
        data[0..8].copy_from_slice(b"WRONGMAG");
        std::fs::write(&identity_path, data).unwrap();

        let result = load_identity(&identity_path, "passphrase");
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidFormat(_)));
        }
    }

    #[test]
    fn test_load_nonexistent_file() {
        let result = load_identity(Path::new("/nonexistent/identity.enc"), "passphrase");
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, Error::FileNotFound(_)));
        }
    }

    #[test]
    fn test_identity_exists_nonexistent() {
        assert!(!identity_exists(Path::new("/nonexistent/identity.enc")));
    }

    #[test]
    fn test_identity_exists_invalid_magic() {
        let temp_dir = TempDir::new().unwrap();
        let identity_path = temp_dir.path().join("identity.enc");

        // Write file with wrong magic bytes
        std::fs::write(&identity_path, b"WRONGDATA").unwrap();

        assert!(!identity_exists(&identity_path));
    }

    #[test]
    fn test_file_format_structure() {
        let temp_dir = TempDir::new().unwrap();
        let identity_path = temp_dir.path().join("identity.enc");

        let identity = Identity::generate();
        save_identity(&identity_path, &identity, "passphrase").unwrap();

        let data = std::fs::read(&identity_path).unwrap();

        // Verify structure
        assert_eq!(&data[0..8], MAGIC_BYTES);

        let version = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        assert_eq!(version, STORAGE_VERSION);

        // Verify minimum size (magic + version + salt + nonce + ciphertext + tag)
        assert!(data.len() >= 8 + 4 + 16 + 12 + 64 + 16);
    }

    #[test]
    fn test_multiple_save_load_cycles() {
        let temp_dir = TempDir::new().unwrap();
        let identity_path = temp_dir.path().join("identity.enc");

        let identity = Identity::generate();
        let original_fingerprint = identity.public_key().fingerprint();
        let passphrase = "test passphrase";

        // Save and load multiple times
        for _ in 0..3 {
            save_identity(&identity_path, &identity, passphrase).unwrap();
            let loaded = load_identity(&identity_path, passphrase).unwrap();
            assert_eq!(loaded.public_key().fingerprint(), original_fingerprint);
        }
    }
}

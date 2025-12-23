//! Cryptography module
//!
//! This module provides all cryptographic primitives for Meshara:
//! - Ed25519 digital signatures
//! - X25519 key exchange
//! - ChaCha20-Poly1305 AEAD encryption
//! - Blake3 cryptographic hashing
//!
//! All implementations use audited crates from the RustCrypto project.

pub mod encryption;
pub mod hash;
pub mod keys;
pub mod signing;

// Re-export main types
pub use encryption::{decrypt_message, encrypt_for_recipient, EncryptedMessage};
pub use hash::{hash_message, hash_public_key, MessageId, NodeId};
pub use keys::{Identity, PublicKey};
pub use signing::{sign_message, verify_signature, Signature};

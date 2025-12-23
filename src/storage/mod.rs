//! Storage layer for Meshara
//!
//! This module provides secure storage for cryptographic identities and node configuration.
//!
//! # Components
//!
//! - **Keystore**: Encrypted identity storage with passphrase protection
//! - **Config**: Node configuration persistence (JSON format)
//! - **Backend**: Pluggable storage backend abstraction
//!
//! # Security
//!
//! - Identities are encrypted with ChaCha20-Poly1305
//! - Passphrases are hashed with Argon2 using OWASP-recommended parameters
//! - File permissions are restricted to user-only access
//! - Sensitive data is zeroized after use
//!
//! # Example
//!
//! ```no_run
//! use meshara::crypto::Identity;
//! use meshara::storage::{keystore, config};
//! use std::path::Path;
//!
//! // Generate and save identity
//! let identity = Identity::generate();
//! keystore::save_identity(Path::new("identity.enc"), &identity, "passphrase").unwrap();
//!
//! // Load identity
//! let loaded = keystore::load_identity(Path::new("identity.enc"), "passphrase").unwrap();
//!
//! // Save configuration
//! let config = config::NodeConfig::new("node_id".to_string());
//! config::save_config(Path::new("config.json"), &config).unwrap();
//! ```

pub mod backend;
pub mod config;
pub mod keystore;

// Re-export commonly used types
pub use backend::{FileSystemStorage, StorageBackend};
pub use config::{NetworkProfile, NodeConfig, PrivacyLevel};

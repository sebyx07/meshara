//! Authority system for signed content distribution
//!
//! This module provides the authority system that allows designated nodes to publish
//! signed content such as software updates and announcements. Regular nodes can verify
//! signatures from trusted authorities before accepting updates or other content.
//!
//! # Overview
//!
//! The authority system consists of several key components:
//!
//! ## Authority Identities
//!
//! Authority nodes use `AuthorityIdentity` which wraps a regular cryptographic identity
//! with metadata (name, description, URL). Authority identities are long-lived and should
//! be carefully protected.
//!
//! ```rust
//! use meshara::authority::AuthorityIdentity;
//!
//! // Create a new authority
//! let authority = AuthorityIdentity::new(
//!     "My Software Project".to_string(),
//!     "Official update authority".to_string(),
//!     "https://myproject.com".to_string(),
//! );
//!
//! // Export for backup (encrypted with passphrase)
//! let exported = authority.export("secure_passphrase").unwrap();
//!
//! // Import from backup
//! let restored = AuthorityIdentity::import(&exported, "secure_passphrase").unwrap();
//! ```
//!
//! ## Trust Management
//!
//! Nodes maintain a `AuthorityTrustStore` that tracks which authorities they trust
//! and for what purposes (updates, signing, etc.).
//!
//! ```rust
//! use meshara::authority::{AuthorityTrustStore, TrustLevel, AuthorityIdentity};
//!
//! let authority = AuthorityIdentity::new(
//!     "Trusted Authority".to_string(),
//!     "Description".to_string(),
//!     "https://example.com".to_string(),
//! );
//!
//! let mut trust_store = AuthorityTrustStore::new();
//!
//! // Add authority to trust store
//! trust_store.add_authority(
//!     authority.authority_id().clone(),
//!     authority.public_key(),
//!     authority.metadata().clone(),
//!     TrustLevel::UpdateAuthority,
//! ).unwrap();
//!
//! // Check if authority is trusted
//! assert!(trust_store.is_trusted(authority.authority_id(), TrustLevel::UpdateAuthority));
//! ```
//!
//! ## Update Packages
//!
//! Authorities can create and sign update packages that regular nodes can verify
//! and apply.
//!
//! ```rust
//! use meshara::authority::{AuthorityIdentity, UpdatePackageBuilder, verify_update_package, AuthorityTrustStore, TrustLevel};
//!
//! // Authority creates update
//! let authority = AuthorityIdentity::new(
//!     "Software Project".to_string(),
//!     "Update authority".to_string(),
//!     "https://project.com".to_string(),
//! );
//!
//! let update = UpdatePackageBuilder::new("2.0.0".to_string())
//!     .with_package_data(vec![/* binary data */])
//!     .with_changelog("New features and bug fixes".to_string())
//!     .with_required_version("1.0.0".to_string())
//!     .build(&authority)
//!     .unwrap();
//!
//! // Node verifies update
//! let trust_store = AuthorityTrustStore::new();
//! trust_store.add_authority(
//!     authority.authority_id().clone(),
//!     authority.public_key(),
//!     authority.metadata().clone(),
//!     TrustLevel::UpdateAuthority,
//! ).unwrap();
//!
//! let verified = verify_update_package(&update, &trust_store, 1).unwrap();
//! assert!(verified);
//! ```
//!
//! ## Multi-Signature Updates
//!
//! For critical updates, multiple authorities can sign the same package:
//!
//! ```rust
//! use meshara::authority::{AuthorityIdentity, UpdatePackageBuilder, add_signature, verify_update_package, AuthorityTrustStore, TrustLevel};
//!
//! let auth1 = AuthorityIdentity::new("Authority 1".to_string(), "First".to_string(), "https://one.com".to_string());
//! let auth2 = AuthorityIdentity::new("Authority 2".to_string(), "Second".to_string(), "https://two.com".to_string());
//!
//! // Build unsigned package
//! let mut update = UpdatePackageBuilder::new("3.0.0".to_string())
//!     .with_package_data(vec![/* data */])
//!     .build_unsigned()
//!     .unwrap();
//!
//! // Add signatures from multiple authorities
//! add_signature(&mut update, &auth1).unwrap();
//! add_signature(&mut update, &auth2).unwrap();
//!
//! // Verify requires both signatures
//! let trust_store = AuthorityTrustStore::new();
//! trust_store.add_authority(auth1.authority_id().clone(), auth1.public_key(), auth1.metadata().clone(), TrustLevel::UpdateAuthority).unwrap();
//! trust_store.add_authority(auth2.authority_id().clone(), auth2.public_key(), auth2.metadata().clone(), TrustLevel::UpdateAuthority).unwrap();
//!
//! let verified = verify_update_package(&update, &trust_store, 2).unwrap();
//! assert!(verified);
//! ```
//!
//! ## Query/Response Protocol
//!
//! Nodes can query authorities for information like version checks and update availability:
//!
//! ```rust
//! use meshara::authority::{QueryType, QueryResponse, UpdateInfo};
//!
//! // Create query
//! let query = QueryType::UpdateAvailable {
//!     current_version: "1.0.0".to_string(),
//! };
//!
//! // Authority responds
//! let update_info = UpdateInfo {
//!     version: "2.0.0".to_string(),
//!     changelog: "New features".to_string(),
//!     size: 1024000,
//!     critical: false,
//! };
//!
//! let response = QueryResponse::success(&update_info).unwrap();
//! ```

mod application;
mod distribution;
mod keys;
mod queries;
mod trust;
mod updates;

// Re-export public APIs
pub use application::{apply_update_safely, UpdateApplicator, UpdateConfig, UpdateEvent};
pub use distribution::{
    create_update_announcement, create_update_request, BandwidthLimiter, DownloadState,
    UpdateCache, UpdateDownloader, UpdateId, CHUNK_SIZE, DEFAULT_MAX_CACHE_SIZE,
};
pub use keys::{AuthorityId, AuthorityIdentity, AuthorityMetadata};
pub use queries::{generate_query_id, QueryEvent, QueryResponse, QueryType, UpdateInfo};
pub use trust::{AuthorityTrustStore, TrustLevel, TrustedAuthority};
pub use updates::{
    add_signature, meets_version_requirement, verify_update_package, UpdatePackageBuilder,
};

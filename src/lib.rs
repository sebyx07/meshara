//! # Meshara
//!
//! A developer-friendly library for decentralized, privacy-preserving communication.
//!
//! ## Quick Start
//!
//! ```no_run
//! use meshara::{Node, NodeBuilder};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut node = NodeBuilder::new()
//!         .with_storage_path("./meshara-data")
//!         .build()?;
//!
//!     node.start().await?;
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod api;
pub mod authority;
pub mod crypto;
pub mod error;
pub mod network;
pub mod protocol;
pub mod routing;
pub mod storage;

// Re-export main types
pub use api::{
    Event, MessageId, NetworkProfile, Node, NodeBuilder, NodeId, NodeRegistry, NodeState,
    PrivacyLevel, SubscriptionHandle,
};
pub use authority::{
    add_signature, generate_query_id, meets_version_requirement, verify_update_package,
    AuthorityId, AuthorityIdentity, AuthorityMetadata, AuthorityTrustStore, QueryEvent,
    QueryResponse, QueryType, TrustLevel, TrustedAuthority, UpdateInfo, UpdatePackageBuilder,
};
pub use crypto::{Identity, PublicKey};
pub use error::{
    AuthorityError, ConfigError, CryptoError, MesharaError, NetworkError, ProtocolError, Result,
    RoutingError, StorageError,
};
pub use routing::{GossipProtocol, Route, Router, RouterBuilder, RoutingTable};

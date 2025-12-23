//! Error types for Meshara

use thiserror::Error;

/// Main error type for Meshara operations
#[derive(Error, Debug)]
pub enum Error {
    /// Network-related errors
    #[error("Network error: {0}")]
    Network(String),

    /// Cryptographic errors
    #[error("Cryptography error: {0}")]
    Crypto(String),

    /// Storage errors
    #[error("Storage error: {0}")]
    Storage(String),

    /// Protocol errors
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// Routing errors
    #[error("Routing error: {0}")]
    Routing(String),

    /// Authority errors
    #[error("Authority error: {0}")]
    Authority(String),

    /// I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Generic error
    #[error("{0}")]
    Other(String),
}

/// Result type alias
pub type Result<T> = std::result::Result<T, Error>;

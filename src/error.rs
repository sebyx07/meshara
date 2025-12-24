//! Error types for Meshara
//!
//! This module defines comprehensive error types for all subsystems.
//! Errors are designed to be:
//! - Machine-readable: Error codes/types for programmatic handling
//! - Human-readable: Clear messages for developers
//! - Contextual: Include what operation failed
//! - Chainable: Preserve underlying error causes
//! - Recoverable: Indicate whether retry makes sense

use std::path::PathBuf;
use thiserror::Error;

/// Main error type for all Meshara operations
///
/// This is the public-facing error type returned by all library APIs.
/// Each variant wraps a more specific subsystem error.
#[derive(Error, Debug, Clone)]
pub enum MesharaError {
    /// Cryptographic operation error
    #[error("Cryptography error: {0}")]
    Crypto(#[from] CryptoError),

    /// Protocol serialization/deserialization error
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    /// Storage operation error
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    /// Network operation error
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    /// Routing operation error
    #[error("Routing error: {0}")]
    Routing(#[from] RoutingError),

    /// Authority operation error
    #[error("Authority error: {0}")]
    Authority(#[from] AuthorityError),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),
}

/// Cryptographic operation errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid key length provided
    ///
    /// This occurs when a cryptographic key doesn't match the expected length.
    /// Most commonly happens with imported keys or corrupted key data.
    ///
    /// This error is NOT retryable - the key data is invalid.
    #[error("Invalid key length: expected {expected} bytes, got {got} bytes")]
    InvalidKeyLength {
        /// Expected key length in bytes
        expected: usize,
        /// Actual key length received
        got: usize,
    },

    /// Signature verification failed
    ///
    /// This occurs when a message's signature doesn't match the claimed sender.
    /// This could indicate:
    /// - Message was tampered with
    /// - Sender's key is incorrect
    /// - Potential security issue
    ///
    /// This error is NOT retryable - the message should be rejected.
    #[error("Signature verification failed: {context}")]
    InvalidSignature {
        /// Context about what signature validation failed
        context: String,
    },

    /// Decryption operation failed
    ///
    /// This occurs when encrypted data cannot be decrypted. Common causes:
    /// - Wrong decryption key
    /// - Corrupted ciphertext
    /// - Invalid authentication tag
    ///
    /// This error is NOT retryable - decryption fundamentally failed.
    #[error("Decryption failed: {reason}")]
    DecryptionFailed {
        /// Reason why decryption failed
        reason: String,
    },

    /// Encryption operation failed
    ///
    /// This occurs when data cannot be encrypted. Usually indicates:
    /// - Invalid recipient public key
    /// - RNG failure
    /// - System resource issues
    ///
    /// This error MAY be retryable if caused by temporary resource issues.
    #[error("Encryption failed: {reason}")]
    EncryptionFailed {
        /// Reason why encryption failed
        reason: String,
    },

    /// Invalid passphrase provided
    ///
    /// This occurs when attempting to decrypt a key with wrong passphrase.
    /// User should be prompted to re-enter passphrase.
    ///
    /// This error is NOT retryable automatically - requires user input.
    #[error("Invalid passphrase")]
    InvalidPassphrase,

    /// Encrypted data is invalid or corrupted
    ///
    /// This occurs when encrypted data structure is malformed.
    /// Common causes:
    /// - File corruption
    /// - Incompatible format version
    /// - Truncated data
    ///
    /// This error is NOT retryable - data is fundamentally corrupted.
    #[error("Invalid encrypted data: {context}")]
    InvalidEncryptedData {
        /// Context about what encrypted data was invalid
        context: String,
    },

    /// Key derivation operation failed
    ///
    /// This occurs when deriving a key from a passphrase fails.
    /// Usually indicates system resource issues or invalid parameters.
    ///
    /// This error MAY be retryable if system resources recover.
    #[error("Key derivation failed: {reason}")]
    KeyDerivationFailed {
        /// Reason why key derivation failed
        reason: String,
    },

    /// Invalid nonce length
    ///
    /// This occurs when an encryption nonce has wrong length.
    /// Indicates a programming error or data corruption.
    ///
    /// This error is NOT retryable - indicates invalid data.
    #[error("Invalid nonce length: expected {expected} bytes, got {got} bytes")]
    InvalidNonce {
        /// Expected nonce length in bytes
        expected: usize,
        /// Actual nonce length received
        got: usize,
    },

    /// Signing operation failed
    ///
    /// This occurs when creating a signature fails.
    /// Usually indicates invalid signing key or system issues.
    ///
    /// This error MAY be retryable if caused by temporary issues.
    #[error("Signing failed: {reason}")]
    SigningFailed {
        /// Reason why signing failed
        reason: String,
    },
}

/// Protocol serialization and message handling errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// Protocol Buffer serialization failed
    ///
    /// This occurs when encoding a message to bytes fails.
    /// Usually indicates programming error or invalid field values.
    ///
    /// This error is NOT retryable - message data is invalid.
    #[error("Serialization failed for {message_type}: {reason}")]
    SerializationFailed {
        /// Type of message that failed to serialize
        message_type: String,
        /// Reason why serialization failed
        reason: String,
    },

    /// Protocol Buffer deserialization failed
    ///
    /// This occurs when decoding bytes into a message fails.
    /// Common causes:
    /// - Corrupted message data
    /// - Incompatible protocol version
    /// - Malformed wire format
    ///
    /// This error is NOT retryable - message is fundamentally invalid.
    #[error("Deserialization failed: {reason}")]
    DeserializationFailed {
        /// Reason why deserialization failed
        reason: String,
    },

    /// Unknown or invalid message type
    ///
    /// This occurs when receiving a message with unrecognized type ID.
    /// May indicate version incompatibility or corrupted message.
    ///
    /// This error is NOT retryable - message type is unknown.
    #[error("Invalid message type: {got}")]
    InvalidMessageType {
        /// The message type ID that was received
        got: u32,
    },

    /// Unsupported protocol version
    ///
    /// This occurs when receiving a message with incompatible version.
    /// Sender may be using newer or deprecated protocol version.
    ///
    /// This error is NOT retryable - version mismatch must be resolved.
    #[error("Unsupported protocol version {version}, supported: {supported}")]
    UnsupportedVersion {
        /// Protocol version received
        version: u32,
        /// Supported version range (as string)
        supported: String,
    },

    /// Invalid value in message field
    ///
    /// This occurs when a message field contains invalid data.
    /// Indicates sender sent malformed message or data corruption.
    ///
    /// This error is NOT retryable - field value is invalid.
    #[error("Invalid field value for '{field}': {reason}")]
    InvalidFieldValue {
        /// Name of the field with invalid value
        field: String,
        /// Reason why the value is invalid
        reason: String,
    },

    /// Message exceeds maximum allowed size
    ///
    /// This occurs when a message is too large to process.
    /// Prevents DoS attacks via oversized messages.
    ///
    /// This error is NOT retryable - message must be split or rejected.
    #[error("Message too large: {size} bytes exceeds maximum {max} bytes")]
    MessageTooLarge {
        /// Actual message size in bytes
        size: usize,
        /// Maximum allowed size in bytes
        max: usize,
    },

    /// Required message field is missing
    ///
    /// This occurs when a required field is not present in message.
    /// Indicates incomplete message or protocol violation.
    ///
    /// This error is NOT retryable - message is incomplete.
    #[error("Missing required field: {field}")]
    MissingRequiredField {
        /// Name of the missing required field
        field: String,
    },

    /// Message signature validation failed
    ///
    /// This occurs when message signature doesn't verify.
    /// See CryptoError::InvalidSignature for detailed info.
    ///
    /// This error is NOT retryable - message should be rejected.
    #[error("Message signature validation failed")]
    InvalidSignature,
}

/// Storage and file system errors
#[derive(Error, Debug, Clone)]
pub enum StorageError {
    /// File not found at expected path
    ///
    /// This occurs when attempting to read a file that doesn't exist.
    /// Common for first-time operations before initialization.
    ///
    /// This error MAY be retryable if file is expected to be created.
    #[error("File not found: {path}")]
    FileNotFound {
        /// Path to the file that was not found
        path: PathBuf,
    },

    /// Permission denied accessing file or directory
    ///
    /// This occurs when process lacks permissions for file operation.
    /// User should check file permissions or run with appropriate privileges.
    ///
    /// This error is NOT retryable without fixing permissions.
    #[error("Permission denied: {path}")]
    PermissionDenied {
        /// Path where permission was denied
        path: PathBuf,
    },

    /// File format is invalid or corrupted
    ///
    /// This occurs when a file's structure doesn't match expected format.
    /// Common causes:
    /// - File corruption
    /// - Wrong file type
    /// - Incompatible version
    ///
    /// This error is NOT retryable - file is fundamentally invalid.
    #[error("Invalid format in file '{file}': {reason}")]
    InvalidFormat {
        /// Name of the file with invalid format
        file: String,
        /// Reason why format is invalid
        reason: String,
    },

    /// Decryption of stored data failed
    ///
    /// This occurs when encrypted storage cannot be decrypted.
    /// Usually indicates wrong passphrase or corrupted data.
    ///
    /// This error is NOT retryable - requires user to provide correct passphrase.
    #[error("Decryption of stored data failed")]
    DecryptionFailed,

    /// Stored data is corrupted
    ///
    /// This occurs when data integrity check fails.
    /// Indicates file system corruption or tampering.
    ///
    /// This error is NOT retryable - data is lost or corrupted.
    #[error("Corrupted data in file: {file}")]
    CorruptedData {
        /// Name of the file with corrupted data
        file: String,
    },

    /// I/O operation failed
    ///
    /// This wraps standard library I/O errors.
    /// Can indicate disk errors, network file system issues, etc.
    ///
    /// This error MAY be retryable depending on underlying cause.
    #[error("I/O error: {message}")]
    IoError {
        /// Description of the I/O error
        message: String,
    },

    /// Serialization to storage format failed
    ///
    /// This occurs when converting data to storage format fails.
    /// Usually indicates programming error or invalid data.
    ///
    /// This error is NOT retryable - data is invalid.
    #[error("Serialization to storage failed: {reason}")]
    SerializationFailed {
        /// Reason why serialization failed
        reason: String,
    },
}

/// Network communication errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum NetworkError {
    /// Failed to establish connection
    ///
    /// This occurs when connecting to a peer fails.
    /// Common causes:
    /// - Peer is offline
    /// - Network unreachable
    /// - Firewall blocking connection
    /// - Invalid address
    ///
    /// This error IS retryable - peer may come online.
    #[error("Connection to {address} failed: {reason}")]
    ConnectionFailed {
        /// Address that connection attempt failed to reach
        address: String,
        /// Reason why connection failed
        reason: String,
    },

    /// Connection was closed
    ///
    /// This occurs when an established connection is closed.
    /// Can be graceful shutdown or abrupt disconnection.
    ///
    /// This error IS retryable - can reconnect to peer.
    #[error("Connection to peer {peer_id} was closed")]
    ConnectionClosed {
        /// ID of peer whose connection closed
        peer_id: String,
    },

    /// Operation timed out
    ///
    /// This occurs when a network operation takes too long.
    /// Common causes:
    /// - Slow network
    /// - Peer not responding
    /// - Network congestion
    ///
    /// This error IS retryable - network conditions may improve.
    #[error("Operation '{operation}' timed out")]
    Timeout {
        /// Description of operation that timed out
        operation: String,
    },

    /// TLS handshake or operation failed
    ///
    /// This occurs when TLS-level error happens.
    /// Can indicate certificate issues, protocol errors, etc.
    ///
    /// This error is NOT retryable - indicates TLS configuration issue.
    #[error("TLS error: {reason}")]
    TlsError {
        /// Reason for TLS failure
        reason: String,
    },

    /// TLS handshake failed
    ///
    /// This occurs during TLS handshake phase.
    /// Can indicate version mismatch, cipher suite issues, etc.
    ///
    /// This error is NOT retryable - indicates TLS configuration issue.
    #[error("TLS handshake failed: {reason}")]
    TlsHandshakeFailed {
        /// Reason why handshake failed
        reason: String,
    },

    /// Certificate error
    ///
    /// This occurs when certificate validation or generation fails.
    /// Can indicate expired certificate, invalid signature, etc.
    ///
    /// This error is NOT retryable - requires certificate fix.
    #[error("Certificate error: {reason}")]
    CertificateError {
        /// Reason for certificate error
        reason: String,
    },

    /// ALPN protocol negotiation failed
    ///
    /// This occurs when TLS ALPN doesn't match expected protocol.
    /// Indicates connection from non-Meshara client or version mismatch.
    ///
    /// This error is NOT retryable - protocol mismatch.
    #[error("Invalid ALPN: expected '{expected}', got '{got}'")]
    InvalidAlpn {
        /// ALPN protocol received
        got: String,
        /// Expected ALPN protocol
        expected: String,
    },

    /// Message size exceeds maximum allowed
    ///
    /// This occurs at network layer before deserialization.
    /// Prevents DoS attacks via oversized messages.
    ///
    /// This error is NOT retryable - message must be rejected.
    #[error("Message too large: {size} bytes exceeds maximum")]
    MessageTooLarge {
        /// Actual message size in bytes
        size: usize,
    },

    /// Connection was reset
    ///
    /// This occurs when connection is abruptly terminated.
    /// Can indicate network issues or peer crash.
    ///
    /// This error IS retryable - can reconnect.
    #[error("Connection reset")]
    ConnectionReset,

    /// Invalid network address provided
    ///
    /// This occurs when an address cannot be parsed or is malformed.
    /// Indicates programming error or invalid user input.
    ///
    /// This error is NOT retryable - address is invalid.
    #[error("Invalid address: {address}")]
    InvalidAddress {
        /// The invalid address string
        address: String,
    },

    /// Peer is unreachable
    ///
    /// This occurs when a known peer cannot be reached.
    /// May indicate peer is offline or network path is broken.
    ///
    /// This error IS retryable - peer may become reachable.
    #[error("Peer {peer_id} is unreachable")]
    PeerUnreachable {
        /// ID of unreachable peer
        peer_id: String,
    },

    /// Failed to send data
    ///
    /// This occurs when sending data over connection fails.
    /// Can indicate connection closed or network error.
    ///
    /// This error MAY be retryable - depends on underlying cause.
    #[error("Send operation failed: {reason}")]
    SendFailed {
        /// Reason why send failed
        reason: String,
    },

    /// Failed to receive data
    ///
    /// This occurs when receiving data fails.
    /// Can indicate connection closed or protocol error.
    ///
    /// This error MAY be retryable - depends on underlying cause.
    #[error("Receive operation failed: {reason}")]
    ReceiveFailed {
        /// Reason why receive failed
        reason: String,
    },
}

impl From<std::io::Error> for StorageError {
    fn from(error: std::io::Error) -> Self {
        Self::IoError {
            message: error.to_string(),
        }
    }
}

impl From<std::io::Error> for MesharaError {
    fn from(error: std::io::Error) -> Self {
        Self::Storage(StorageError::IoError {
            message: error.to_string(),
        })
    }
}

/// Message routing errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RoutingError {
    /// No route found to destination
    ///
    /// This occurs when routing table has no path to destination.
    /// Common in sparse networks or with isolated peers.
    ///
    /// This error IS retryable - route may be discovered.
    #[error("No route to destination: {destination}")]
    NoRouteToDestination {
        /// Destination that could not be routed to
        destination: String,
    },

    /// Message exceeded maximum hop count
    ///
    /// This occurs when message has been forwarded too many times.
    /// Prevents routing loops and limits message propagation.
    ///
    /// This error is NOT retryable - indicates routing loop or excessive distance.
    #[error("Maximum hops exceeded: {hops} hops, maximum is {max}")]
    MaxHopsExceeded {
        /// Number of hops message has taken
        hops: u32,
        /// Maximum allowed hops
        max: u32,
    },

    /// Routing loop detected
    ///
    /// This occurs when message would be routed in a circle.
    /// Indicates routing table inconsistency.
    ///
    /// This error is NOT retryable - routing tables need to converge.
    #[error("Routing loop detected")]
    RoutingLoopDetected,

    /// Invalid routing information
    ///
    /// This occurs when routing data is malformed or inconsistent.
    /// Indicates protocol violation or corrupted routing table.
    ///
    /// This error is NOT retryable - routing info is invalid.
    #[error("Invalid routing information: {reason}")]
    InvalidRoutingInfo {
        /// Reason why routing info is invalid
        reason: String,
    },

    /// Peer not found in routing table
    ///
    /// This occurs when attempting to route to unknown peer.
    /// Peer may not have been discovered yet.
    ///
    /// This error IS retryable - peer may be discovered.
    #[error("Peer not found in routing table: {peer_id}")]
    PeerNotFound {
        /// ID of peer that was not found
        peer_id: String,
    },
}

/// Authority system errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AuthorityError {
    /// Unknown authority encountered
    ///
    /// This occurs when receiving message from unrecognized authority.
    /// Authority is not in trusted authority list.
    ///
    /// This error is NOT retryable - authority must be added to trust list.
    #[error("Unknown authority: {authority_id}")]
    UnknownAuthority {
        /// ID of unknown authority
        authority_id: String,
    },

    /// Authority signature validation failed
    ///
    /// This occurs when authority's signature doesn't verify.
    /// Indicates tampering or invalid authority credentials.
    ///
    /// This error is NOT retryable - signature is invalid.
    #[error("Invalid signature from authority: {authority_id}")]
    InvalidSignature {
        /// ID of authority with invalid signature
        authority_id: String,
    },

    /// Authority is not trusted
    ///
    /// This occurs when authority is known but not trusted.
    /// User has explicitly not trusted this authority.
    ///
    /// This error is NOT retryable - requires user to trust authority.
    #[error("Untrusted authority: {authority_id}")]
    UntrustedAuthority {
        /// ID of untrusted authority
        authority_id: String,
    },

    /// Update version mismatch
    ///
    /// This occurs when update requires different version than current.
    /// May indicate incompatible update or incorrect version detection.
    ///
    /// This error is NOT retryable - version compatibility issue.
    #[error("Version mismatch: required {required}, current {current}")]
    VersionMismatch {
        /// Required version for update
        required: String,
        /// Current version installed
        current: String,
    },

    /// Update package verification failed
    ///
    /// This occurs when validating an update package fails.
    /// Can indicate corruption, tampering, or invalid package.
    ///
    /// This error is NOT retryable - package is invalid.
    #[error("Update verification failed: {reason}")]
    UpdateVerificationFailed {
        /// Reason why verification failed
        reason: String,
    },
}

/// Configuration errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Invalid port number
    ///
    /// This occurs when port number is in invalid range.
    /// Port must be 1-65535 and not system-reserved (< 1024 without privileges).
    ///
    /// This error is NOT retryable - requires valid configuration.
    #[error("Invalid port: {port}")]
    InvalidPort {
        /// The invalid port number
        port: u16,
    },

    /// Invalid bootstrap node address
    ///
    /// This occurs when bootstrap node address is malformed.
    /// Address must be valid host:port format.
    ///
    /// This error is NOT retryable - requires valid configuration.
    #[error("Invalid bootstrap node address: {address}")]
    InvalidBootstrapNode {
        /// The invalid bootstrap address
        address: String,
    },

    /// Invalid network profile name
    ///
    /// This occurs when unknown network profile is specified.
    /// Profile must be one of predefined options.
    ///
    /// This error is NOT retryable - requires valid configuration.
    #[error("Invalid network profile: {profile}")]
    InvalidNetworkProfile {
        /// The invalid profile name
        profile: String,
    },

    /// Invalid privacy level
    ///
    /// This occurs when unknown privacy level is specified.
    /// Privacy level must be one of predefined options.
    ///
    /// This error is NOT retryable - requires valid configuration.
    #[error("Invalid privacy level: {level}")]
    InvalidPrivacyLevel {
        /// The invalid privacy level
        level: String,
    },

    /// Required configuration field is missing
    ///
    /// This occurs when mandatory configuration is not provided.
    /// User must provide required configuration values.
    ///
    /// This error is NOT retryable - requires valid configuration.
    #[error("Missing required configuration field: {field}")]
    MissingRequiredField {
        /// Name of missing required field
        field: String,
    },

    /// Invalid filesystem path
    ///
    /// This occurs when a configured path is invalid.
    /// Path may not exist, be inaccessible, or malformed.
    ///
    /// This error is NOT retryable - requires valid configuration.
    #[error("Invalid path: {path}")]
    InvalidPath {
        /// The invalid path
        path: PathBuf,
    },
}

impl MesharaError {
    /// Determines if this error represents a transient condition worth retrying
    ///
    /// Returns `true` if the operation that caused this error might succeed
    /// if retried after a delay. Returns `false` for permanent errors that
    /// will never succeed without external changes.
    ///
    /// # Examples
    ///
    /// ```
    /// use meshara::error::{MesharaError, NetworkError};
    ///
    /// let timeout_err = MesharaError::Network(NetworkError::Timeout {
    ///     operation: "connect".to_string()
    /// });
    /// assert!(timeout_err.is_retryable());
    ///
    /// let invalid_key = MesharaError::Crypto(
    ///     meshara::error::CryptoError::InvalidKeyLength { expected: 32, got: 16 }
    /// );
    /// assert!(!invalid_key.is_retryable());
    /// ```
    pub fn is_retryable(&self) -> bool {
        match self {
            // Crypto errors are never retryable - they indicate fundamental issues
            MesharaError::Crypto(_) => false,

            // Protocol errors are never retryable - message is fundamentally invalid
            MesharaError::Protocol(_) => false,

            // Storage errors - some I/O errors might be retryable
            MesharaError::Storage(storage_err) => matches!(
                storage_err,
                StorageError::IoError { .. } | StorageError::FileNotFound { .. }
            ),

            // Network errors - most are retryable (transient conditions)
            MesharaError::Network(net_err) => matches!(
                net_err,
                NetworkError::Timeout { .. }
                    | NetworkError::ConnectionFailed { .. }
                    | NetworkError::ConnectionClosed { .. }
                    | NetworkError::ConnectionReset
                    | NetworkError::PeerUnreachable { .. }
            ),

            // Routing errors - some are retryable (route may be discovered)
            MesharaError::Routing(routing_err) => matches!(
                routing_err,
                RoutingError::NoRouteToDestination { .. } | RoutingError::PeerNotFound { .. }
            ),

            // Authority errors are never retryable - require manual intervention
            MesharaError::Authority(_) => false,

            // Config errors are never retryable - require configuration fix
            MesharaError::Config(_) => false,
        }
    }

    /// Returns a stable error code for programmatic handling
    ///
    /// Error codes are stable across versions and can be used for:
    /// - Metrics and monitoring
    /// - Error categorization
    /// - Programmatic error handling
    /// - API error responses
    ///
    /// # Examples
    ///
    /// ```
    /// use meshara::error::{MesharaError, CryptoError};
    ///
    /// let err = MesharaError::Crypto(CryptoError::InvalidSignature {
    ///     context: "message verification".to_string()
    /// });
    /// assert_eq!(err.error_code(), "CRYPTO_INVALID_SIGNATURE");
    /// ```
    pub fn error_code(&self) -> &'static str {
        match self {
            // Crypto error codes
            MesharaError::Crypto(e) => match e {
                CryptoError::InvalidKeyLength { .. } => "CRYPTO_INVALID_KEY_LENGTH",
                CryptoError::InvalidSignature { .. } => "CRYPTO_INVALID_SIGNATURE",
                CryptoError::DecryptionFailed { .. } => "CRYPTO_DECRYPTION_FAILED",
                CryptoError::EncryptionFailed { .. } => "CRYPTO_ENCRYPTION_FAILED",
                CryptoError::InvalidPassphrase => "CRYPTO_INVALID_PASSPHRASE",
                CryptoError::InvalidEncryptedData { .. } => "CRYPTO_INVALID_ENCRYPTED_DATA",
                CryptoError::KeyDerivationFailed { .. } => "CRYPTO_KEY_DERIVATION_FAILED",
                CryptoError::InvalidNonce { .. } => "CRYPTO_INVALID_NONCE",
                CryptoError::SigningFailed { .. } => "CRYPTO_SIGNING_FAILED",
            },

            // Protocol error codes
            MesharaError::Protocol(e) => match e {
                ProtocolError::SerializationFailed { .. } => "PROTOCOL_SERIALIZATION_FAILED",
                ProtocolError::DeserializationFailed { .. } => "PROTOCOL_DESERIALIZATION_FAILED",
                ProtocolError::InvalidMessageType { .. } => "PROTOCOL_INVALID_MESSAGE_TYPE",
                ProtocolError::UnsupportedVersion { .. } => "PROTOCOL_UNSUPPORTED_VERSION",
                ProtocolError::InvalidFieldValue { .. } => "PROTOCOL_INVALID_FIELD_VALUE",
                ProtocolError::MessageTooLarge { .. } => "PROTOCOL_MESSAGE_TOO_LARGE",
                ProtocolError::MissingRequiredField { .. } => "PROTOCOL_MISSING_REQUIRED_FIELD",
                ProtocolError::InvalidSignature => "PROTOCOL_INVALID_SIGNATURE",
            },

            // Storage error codes
            MesharaError::Storage(e) => match e {
                StorageError::FileNotFound { .. } => "STORAGE_FILE_NOT_FOUND",
                StorageError::PermissionDenied { .. } => "STORAGE_PERMISSION_DENIED",
                StorageError::InvalidFormat { .. } => "STORAGE_INVALID_FORMAT",
                StorageError::DecryptionFailed => "STORAGE_DECRYPTION_FAILED",
                StorageError::CorruptedData { .. } => "STORAGE_CORRUPTED_DATA",
                StorageError::IoError { .. } => "STORAGE_IO_ERROR",
                StorageError::SerializationFailed { .. } => "STORAGE_SERIALIZATION_FAILED",
            },

            // Network error codes
            MesharaError::Network(e) => match e {
                NetworkError::ConnectionFailed { .. } => "NETWORK_CONNECTION_FAILED",
                NetworkError::ConnectionClosed { .. } => "NETWORK_CONNECTION_CLOSED",
                NetworkError::Timeout { .. } => "NETWORK_TIMEOUT",
                NetworkError::TlsError { .. } => "NETWORK_TLS_ERROR",
                NetworkError::TlsHandshakeFailed { .. } => "NETWORK_TLS_HANDSHAKE_FAILED",
                NetworkError::CertificateError { .. } => "NETWORK_CERTIFICATE_ERROR",
                NetworkError::InvalidAlpn { .. } => "NETWORK_INVALID_ALPN",
                NetworkError::MessageTooLarge { .. } => "NETWORK_MESSAGE_TOO_LARGE",
                NetworkError::ConnectionReset => "NETWORK_CONNECTION_RESET",
                NetworkError::InvalidAddress { .. } => "NETWORK_INVALID_ADDRESS",
                NetworkError::PeerUnreachable { .. } => "NETWORK_PEER_UNREACHABLE",
                NetworkError::SendFailed { .. } => "NETWORK_SEND_FAILED",
                NetworkError::ReceiveFailed { .. } => "NETWORK_RECEIVE_FAILED",
            },

            // Routing error codes
            MesharaError::Routing(e) => match e {
                RoutingError::NoRouteToDestination { .. } => "ROUTING_NO_ROUTE",
                RoutingError::MaxHopsExceeded { .. } => "ROUTING_MAX_HOPS_EXCEEDED",
                RoutingError::RoutingLoopDetected => "ROUTING_LOOP_DETECTED",
                RoutingError::InvalidRoutingInfo { .. } => "ROUTING_INVALID_INFO",
                RoutingError::PeerNotFound { .. } => "ROUTING_PEER_NOT_FOUND",
            },

            // Authority error codes
            MesharaError::Authority(e) => match e {
                AuthorityError::UnknownAuthority { .. } => "AUTHORITY_UNKNOWN",
                AuthorityError::InvalidSignature { .. } => "AUTHORITY_INVALID_SIGNATURE",
                AuthorityError::UntrustedAuthority { .. } => "AUTHORITY_UNTRUSTED",
                AuthorityError::VersionMismatch { .. } => "AUTHORITY_VERSION_MISMATCH",
                AuthorityError::UpdateVerificationFailed { .. } => {
                    "AUTHORITY_UPDATE_VERIFICATION_FAILED"
                },
            },

            // Config error codes
            MesharaError::Config(e) => match e {
                ConfigError::InvalidPort { .. } => "CONFIG_INVALID_PORT",
                ConfigError::InvalidBootstrapNode { .. } => "CONFIG_INVALID_BOOTSTRAP_NODE",
                ConfigError::InvalidNetworkProfile { .. } => "CONFIG_INVALID_NETWORK_PROFILE",
                ConfigError::InvalidPrivacyLevel { .. } => "CONFIG_INVALID_PRIVACY_LEVEL",
                ConfigError::MissingRequiredField { .. } => "CONFIG_MISSING_REQUIRED_FIELD",
                ConfigError::InvalidPath { .. } => "CONFIG_INVALID_PATH",
            },
        }
    }
}

/// Result type alias for Meshara operations
///
/// This is a convenience alias for `std::result::Result<T, MesharaError>`.
/// Use this for all public API functions that can fail.
///
/// # Examples
///
/// ```
/// use meshara::error::Result;
///
/// fn do_something() -> Result<String> {
///     Ok("success".to_string())
/// }
/// ```
pub type Result<T> = std::result::Result<T, MesharaError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_error_invalid_key_length() {
        let err = CryptoError::InvalidKeyLength {
            expected: 32,
            got: 16,
        };
        assert_eq!(
            err.to_string(),
            "Invalid key length: expected 32 bytes, got 16 bytes"
        );
    }

    #[test]
    fn test_crypto_error_invalid_signature() {
        let err = CryptoError::InvalidSignature {
            context: "message verification".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Signature verification failed: message verification"
        );
    }

    #[test]
    fn test_protocol_error_serialization_failed() {
        let err = ProtocolError::SerializationFailed {
            message_type: "BaseMessage".to_string(),
            reason: "invalid field".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Serialization failed for BaseMessage: invalid field"
        );
    }

    #[test]
    fn test_protocol_error_unsupported_version() {
        let err = ProtocolError::UnsupportedVersion {
            version: 2,
            supported: "1".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Unsupported protocol version 2, supported: 1"
        );
    }

    #[test]
    fn test_storage_error_file_not_found() {
        let err = StorageError::FileNotFound {
            path: PathBuf::from("/tmp/test.key"),
        };
        assert_eq!(err.to_string(), "File not found: /tmp/test.key");
    }

    #[test]
    fn test_network_error_connection_failed() {
        let err = NetworkError::ConnectionFailed {
            address: "127.0.0.1:8080".to_string(),
            reason: "connection refused".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Connection to 127.0.0.1:8080 failed: connection refused"
        );
    }

    #[test]
    fn test_network_error_timeout() {
        let err = NetworkError::Timeout {
            operation: "handshake".to_string(),
        };
        assert_eq!(err.to_string(), "Operation 'handshake' timed out");
    }

    #[test]
    fn test_routing_error_no_route() {
        let err = RoutingError::NoRouteToDestination {
            destination: "peer-123".to_string(),
        };
        assert_eq!(err.to_string(), "No route to destination: peer-123");
    }

    #[test]
    fn test_routing_error_max_hops() {
        let err = RoutingError::MaxHopsExceeded { hops: 10, max: 8 };
        assert_eq!(
            err.to_string(),
            "Maximum hops exceeded: 10 hops, maximum is 8"
        );
    }

    #[test]
    fn test_authority_error_unknown() {
        let err = AuthorityError::UnknownAuthority {
            authority_id: "auth-456".to_string(),
        };
        assert_eq!(err.to_string(), "Unknown authority: auth-456");
    }

    #[test]
    fn test_config_error_invalid_port() {
        let err = ConfigError::InvalidPort { port: 0 };
        assert_eq!(err.to_string(), "Invalid port: 0");
    }

    #[test]
    fn test_meshara_error_from_crypto() {
        let crypto_err = CryptoError::InvalidSignature {
            context: "test".to_string(),
        };
        let meshara_err: MesharaError = crypto_err.into();
        assert!(matches!(meshara_err, MesharaError::Crypto(_)));
    }

    #[test]
    fn test_meshara_error_from_protocol() {
        let protocol_err = ProtocolError::InvalidMessageType { got: 999 };
        let meshara_err: MesharaError = protocol_err.into();
        assert!(matches!(meshara_err, MesharaError::Protocol(_)));
    }

    #[test]
    fn test_meshara_error_from_network() {
        let network_err = NetworkError::Timeout {
            operation: "send".to_string(),
        };
        let meshara_err: MesharaError = network_err.into();
        assert!(matches!(meshara_err, MesharaError::Network(_)));
    }

    #[test]
    fn test_is_retryable_crypto_never() {
        let err = MesharaError::Crypto(CryptoError::InvalidSignature {
            context: "test".to_string(),
        });
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_is_retryable_protocol_never() {
        let err = MesharaError::Protocol(ProtocolError::InvalidMessageType { got: 999 });
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_is_retryable_network_timeout_yes() {
        let err = MesharaError::Network(NetworkError::Timeout {
            operation: "connect".to_string(),
        });
        assert!(err.is_retryable());
    }

    #[test]
    fn test_is_retryable_network_connection_failed_yes() {
        let err = MesharaError::Network(NetworkError::ConnectionFailed {
            address: "localhost".to_string(),
            reason: "refused".to_string(),
        });
        assert!(err.is_retryable());
    }

    #[test]
    fn test_is_retryable_network_tls_error_no() {
        let err = MesharaError::Network(NetworkError::TlsError {
            reason: "bad certificate".to_string(),
        });
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_is_retryable_routing_no_route_yes() {
        let err = MesharaError::Routing(RoutingError::NoRouteToDestination {
            destination: "peer-123".to_string(),
        });
        assert!(err.is_retryable());
    }

    #[test]
    fn test_is_retryable_routing_max_hops_no() {
        let err = MesharaError::Routing(RoutingError::MaxHopsExceeded { hops: 10, max: 8 });
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_is_retryable_storage_io_yes() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        let err = MesharaError::Storage(StorageError::from(io_err));
        assert!(err.is_retryable());
    }

    #[test]
    fn test_is_retryable_storage_corrupted_no() {
        let err = MesharaError::Storage(StorageError::CorruptedData {
            file: "test.db".to_string(),
        });
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_is_retryable_authority_never() {
        let err = MesharaError::Authority(AuthorityError::UnknownAuthority {
            authority_id: "auth-123".to_string(),
        });
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_is_retryable_config_never() {
        let err = MesharaError::Config(ConfigError::InvalidPort { port: 0 });
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_error_code_crypto() {
        let err = MesharaError::Crypto(CryptoError::InvalidSignature {
            context: "test".to_string(),
        });
        assert_eq!(err.error_code(), "CRYPTO_INVALID_SIGNATURE");
    }

    #[test]
    fn test_error_code_protocol() {
        let err = MesharaError::Protocol(ProtocolError::DeserializationFailed {
            reason: "test".to_string(),
        });
        assert_eq!(err.error_code(), "PROTOCOL_DESERIALIZATION_FAILED");
    }

    #[test]
    fn test_error_code_network() {
        let err = MesharaError::Network(NetworkError::Timeout {
            operation: "test".to_string(),
        });
        assert_eq!(err.error_code(), "NETWORK_TIMEOUT");
    }

    #[test]
    fn test_error_code_routing() {
        let err = MesharaError::Routing(RoutingError::RoutingLoopDetected);
        assert_eq!(err.error_code(), "ROUTING_LOOP_DETECTED");
    }

    #[test]
    fn test_error_code_authority() {
        let err = MesharaError::Authority(AuthorityError::InvalidSignature {
            authority_id: "test".to_string(),
        });
        assert_eq!(err.error_code(), "AUTHORITY_INVALID_SIGNATURE");
    }

    #[test]
    fn test_error_code_config() {
        let err = MesharaError::Config(ConfigError::MissingRequiredField {
            field: "listen_port".to_string(),
        });
        assert_eq!(err.error_code(), "CONFIG_MISSING_REQUIRED_FIELD");
    }

    #[test]
    fn test_error_code_storage() {
        let err = MesharaError::Storage(StorageError::FileNotFound {
            path: PathBuf::from("/test"),
        });
        assert_eq!(err.error_code(), "STORAGE_FILE_NOT_FOUND");
    }

    #[test]
    fn test_error_codes_unique() {
        // Verify all error codes are unique by collecting them
        let mut codes = std::collections::HashSet::new();

        // Test a sample of each category
        let test_errors = vec![
            MesharaError::Crypto(CryptoError::InvalidKeyLength {
                expected: 32,
                got: 16,
            }),
            MesharaError::Crypto(CryptoError::InvalidSignature {
                context: "test".to_string(),
            }),
            MesharaError::Protocol(ProtocolError::InvalidMessageType { got: 1 }),
            MesharaError::Network(NetworkError::Timeout {
                operation: "test".to_string(),
            }),
            MesharaError::Routing(RoutingError::NoRouteToDestination {
                destination: "test".to_string(),
            }),
            MesharaError::Authority(AuthorityError::UnknownAuthority {
                authority_id: "test".to_string(),
            }),
            MesharaError::Config(ConfigError::InvalidPort { port: 0 }),
            MesharaError::Storage(StorageError::FileNotFound {
                path: PathBuf::from("/test"),
            }),
        ];

        for err in test_errors {
            let code = err.error_code();
            assert!(codes.insert(code), "Duplicate error code found: {}", code);
        }
    }

    #[test]
    fn test_error_display_includes_context() {
        let err = MesharaError::Crypto(CryptoError::DecryptionFailed {
            reason: "invalid authentication tag".to_string(),
        });
        let display = format!("{}", err);
        assert!(display.contains("Decryption failed"));
        assert!(display.contains("invalid authentication tag"));
    }

    #[test]
    fn test_result_type_alias() {
        fn returns_result() -> Result<i32> {
            Ok(42)
        }

        fn returns_error() -> Result<i32> {
            Err(MesharaError::Crypto(CryptoError::InvalidPassphrase))
        }

        assert_eq!(returns_result().unwrap(), 42);
        assert!(returns_error().is_err());
    }

    #[test]
    fn test_question_mark_operator() {
        fn inner() -> std::result::Result<(), CryptoError> {
            Err(CryptoError::InvalidPassphrase)
        }

        fn outer() -> Result<()> {
            inner()?;
            Ok(())
        }

        let result = outer();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MesharaError::Crypto(_)));
    }
}

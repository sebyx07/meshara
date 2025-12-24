//! Protocol versioning and compatibility handling.
//!
//! This module provides version constants, compatibility checking, and utilities
//! for handling protocol evolution while maintaining backward compatibility.

use crate::protocol::meshara::{BaseMessage, MessageType};
use std::fmt;

/// Current protocol version used by this implementation
pub const PROTOCOL_VERSION: u32 = 1;

/// Minimum supported protocol version for backward compatibility
pub const MIN_SUPPORTED_VERSION: u32 = 1;

/// Maximum supported protocol version (for forward compatibility testing)
pub const MAX_SUPPORTED_VERSION: u32 = 1;

/// Protocol version ranges for each phase
pub mod versions {
    /// Phase 1-3: Core messaging, TLS, peer discovery
    pub const PHASE_1_3: u32 = 1;

    /// Phase 4: Routing, gossip, acknowledgments (future)
    pub const PHASE_4: u32 = 1; // Will be 2 in future

    /// Phase 5: Update distribution, chunking (future)
    pub const PHASE_5: u32 = 1; // Will be 3 in future
}

/// Protocol version compatibility result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionCompatibility {
    /// Fully compatible - same version
    FullyCompatible,

    /// Backward compatible - message from older version
    BackwardCompatible {
        /// The peer's protocol version
        peer_version: u32,
    },

    /// Forward compatible - message from newer version (graceful degradation)
    ForwardCompatible {
        /// The peer's protocol version
        peer_version: u32,
    },

    /// Incompatible - cannot communicate
    Incompatible {
        /// The peer's protocol version
        peer_version: u32,
    },
}

impl fmt::Display for VersionCompatibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FullyCompatible => write!(f, "Fully compatible (same version)"),
            Self::BackwardCompatible { peer_version } => {
                write!(f, "Backward compatible (peer v{})", peer_version)
            },
            Self::ForwardCompatible { peer_version } => {
                write!(
                    f,
                    "Forward compatible (peer v{}, may have unknown features)",
                    peer_version
                )
            },
            Self::Incompatible { peer_version } => {
                write!(f, "Incompatible (peer v{})", peer_version)
            },
        }
    }
}

/// Check if a protocol version is compatible with our implementation
///
/// Note: Currently all versions are 1, so backward/forward compatibility branches
/// are not reachable. This will change when we have version 2+.
#[allow(clippy::impossible_comparisons)]
pub fn check_version_compatibility(peer_version: u32) -> VersionCompatibility {
    if peer_version == PROTOCOL_VERSION {
        VersionCompatibility::FullyCompatible
    } else if peer_version >= MIN_SUPPORTED_VERSION && peer_version < PROTOCOL_VERSION {
        VersionCompatibility::BackwardCompatible { peer_version }
    } else if peer_version > PROTOCOL_VERSION && peer_version <= MAX_SUPPORTED_VERSION {
        VersionCompatibility::ForwardCompatible { peer_version }
    } else {
        VersionCompatibility::Incompatible { peer_version }
    }
}

/// Check if a message type is supported by this implementation
pub fn is_message_type_supported(message_type: MessageType) -> bool {
    matches!(
        message_type,
        MessageType::Broadcast
            | MessageType::PrivateMessage
            | MessageType::UpdatePackage
            | MessageType::Query
            | MessageType::Response
            // Phase 4 types (defined but not yet implemented)
            | MessageType::RouteAdvertisement
            | MessageType::Acknowledgment
            // Phase 5 types (defined but not yet implemented)
            | MessageType::UpdateAnnouncement
            | MessageType::UpdateRequest
            | MessageType::UpdateChunk
    )
}

/// Get the phase when a message type was introduced
pub fn message_type_phase(message_type: MessageType) -> u32 {
    match message_type {
        MessageType::Broadcast
        | MessageType::PrivateMessage
        | MessageType::UpdatePackage
        | MessageType::Query
        | MessageType::Response => 1,
        MessageType::RouteAdvertisement | MessageType::Acknowledgment => 4,
        MessageType::UpdateAnnouncement | MessageType::UpdateRequest | MessageType::UpdateChunk => {
            5
        },
    }
}

/// Result of validating a message
#[derive(Debug)]
pub enum MessageValidationResult {
    /// Message is valid and should be processed
    Valid,

    /// Message has unknown type but should be ignored (not an error)
    UnknownType {
        /// The unknown message type value
        message_type: i32,
    },

    /// Message version is incompatible
    IncompatibleVersion {
        /// The incompatible version number
        version: u32,
    },

    /// Message is from a future phase and cannot be handled yet
    UnsupportedFeature {
        /// The message type that is unsupported
        message_type: MessageType,
        /// The phase where this feature is implemented
        phase: u32,
    },
}

/// Validate a received message for version and type compatibility
pub fn validate_message(message: &BaseMessage) -> MessageValidationResult {
    // Check version compatibility
    let compat = check_version_compatibility(message.version);
    if matches!(compat, VersionCompatibility::Incompatible { .. }) {
        return MessageValidationResult::IncompatibleVersion {
            version: message.version,
        };
    }

    // Check if message type is known
    let message_type = MessageType::try_from(message.message_type).ok();
    let Some(msg_type) = message_type else {
        // Unknown message type - log and ignore (forward compatibility)
        return MessageValidationResult::UnknownType {
            message_type: message.message_type,
        };
    };

    // Check if we support this message type yet
    if !is_message_type_supported(msg_type) {
        let phase = message_type_phase(msg_type);
        return MessageValidationResult::UnsupportedFeature {
            message_type: msg_type,
            phase,
        };
    }

    MessageValidationResult::Valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::meshara::MessageType;

    #[test]
    fn test_current_version_is_compatible() {
        let compat = check_version_compatibility(PROTOCOL_VERSION);
        assert_eq!(compat, VersionCompatibility::FullyCompatible);
    }

    #[test]
    fn test_older_version_is_backward_compatible() {
        // If we're at version 1, we don't have older versions yet
        // This test will be useful when we have version 2+
        if PROTOCOL_VERSION > 1 {
            let compat = check_version_compatibility(PROTOCOL_VERSION - 1);
            assert!(matches!(
                compat,
                VersionCompatibility::BackwardCompatible { .. }
            ));
        }
    }

    #[test]
    fn test_future_version_handling() {
        // Version beyond our max is incompatible
        let compat = check_version_compatibility(MAX_SUPPORTED_VERSION + 1);
        assert!(matches!(compat, VersionCompatibility::Incompatible { .. }));
    }

    #[test]
    fn test_message_type_support() {
        // Phase 1-3 types are supported
        assert!(is_message_type_supported(MessageType::PrivateMessage));
        assert!(is_message_type_supported(MessageType::Broadcast));
        assert!(is_message_type_supported(MessageType::UpdatePackage));
        assert!(is_message_type_supported(MessageType::Query));
        assert!(is_message_type_supported(MessageType::Response));

        // Phase 4-5 types are defined but marked as supported
        // (handlers will be implemented in those phases)
        assert!(is_message_type_supported(MessageType::RouteAdvertisement));
        assert!(is_message_type_supported(MessageType::Acknowledgment));
        assert!(is_message_type_supported(MessageType::UpdateAnnouncement));
        assert!(is_message_type_supported(MessageType::UpdateRequest));
        assert!(is_message_type_supported(MessageType::UpdateChunk));
    }

    #[test]
    fn test_message_type_phases() {
        assert_eq!(message_type_phase(MessageType::PrivateMessage), 1);
        assert_eq!(message_type_phase(MessageType::Broadcast), 1);
        assert_eq!(message_type_phase(MessageType::RouteAdvertisement), 4);
        assert_eq!(message_type_phase(MessageType::Acknowledgment), 4);
        assert_eq!(message_type_phase(MessageType::UpdateAnnouncement), 5);
        assert_eq!(message_type_phase(MessageType::UpdateChunk), 5);
    }

    #[test]
    fn test_validate_message_valid() {
        let msg = BaseMessage {
            version: PROTOCOL_VERSION,
            message_id: vec![0u8; 16],
            message_type: MessageType::PrivateMessage.into(),
            timestamp: 0,
            sender_public_key: vec![0u8; 32],
            payload: vec![],
            signature: vec![0u8; 64],
            routing_info: None,
        };

        let result = validate_message(&msg);
        assert!(matches!(result, MessageValidationResult::Valid));
    }

    #[test]
    fn test_validate_message_unknown_type() {
        let msg = BaseMessage {
            version: PROTOCOL_VERSION,
            message_id: vec![0u8; 16],
            message_type: 999, // Unknown type
            timestamp: 0,
            sender_public_key: vec![0u8; 32],
            payload: vec![],
            signature: vec![0u8; 64],
            routing_info: None,
        };

        let result = validate_message(&msg);
        assert!(matches!(
            result,
            MessageValidationResult::UnknownType { message_type: 999 }
        ));
    }

    #[test]
    fn test_validate_message_incompatible_version() {
        let msg = BaseMessage {
            version: MAX_SUPPORTED_VERSION + 100, // Way too new
            message_id: vec![0u8; 16],
            message_type: MessageType::PrivateMessage.into(),
            timestamp: 0,
            sender_public_key: vec![0u8; 32],
            payload: vec![],
            signature: vec![0u8; 64],
            routing_info: None,
        };

        let result = validate_message(&msg);
        assert!(matches!(
            result,
            MessageValidationResult::IncompatibleVersion { .. }
        ));
    }
}

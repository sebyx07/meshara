# Protocol Versioning and Compatibility

## Overview

Meshara uses a comprehensive protocol versioning strategy to enable protocol evolution while maintaining backward and forward compatibility. This document describes the versioning approach, compatibility rules, and best practices for protocol changes.

## Version Numbering

### Current Protocol Version

The current protocol version is **1.0**, implemented during MVP phases 1-5.

```rust
pub const PROTOCOL_VERSION: u32 = 1;
```

### Version in BaseMessage

Every `BaseMessage` includes a version field that indicates which protocol version was used to create the message:

```protobuf
message BaseMessage {
    uint32 version = 1;  // Protocol version
    // ... other fields
}
```

### Future Version Roadmap

| Version | Phase | Features |
|---------|-------|----------|
| 1.0 | 1-3 | Core messaging, TLS, peer discovery |
| 1.x | 4 | Routing, gossip, acknowledgments (future) |
| 1.x | 5 | Update distribution, chunking (future) |
| 2.0 | - | Reserved for breaking changes (if needed) |

## All Message Types Defined Upfront

**Key Design Decision**: All message types are defined in Phase 1, even if their implementation comes in later phases.

### Advantages

1. **No schema churn** - Avoids rebuilding protobuf code multiple times
2. **Stable field numbers** - Prevents accidental reuse
3. **Better planning** - See full protocol structure upfront
4. **Easier testing** - Can write forward-compatibility tests early
5. **Cleaner git history** - One protobuf schema file, clear evolution

### Message Type Phases

```protobuf
enum MessageType {
    // Phase 1-3: Core message types (implemented)
    BROADCAST = 0;
    PRIVATE_MESSAGE = 1;
    UPDATE_PACKAGE = 2;
    QUERY = 3;
    RESPONSE = 4;

    // Phase 4: Routing extensions (defined, not yet implemented)
    ROUTE_ADVERTISEMENT = 5;
    ACKNOWLEDGMENT = 6;

    // Phase 5: Update distribution (defined, not yet implemented)
    UPDATE_ANNOUNCEMENT = 7;
    UPDATE_REQUEST = 8;
    UPDATE_CHUNK = 9;
}
```

## Reserved Field Ranges

Every message type allocates field number ranges to prevent future conflicts:

### BaseMessage Field Allocation

```protobuf
message BaseMessage {
    // Fields 1-8: Core fields (used)
    uint32 version = 1;
    bytes message_id = 2;
    MessageType message_type = 3;
    int64 timestamp = 4;
    bytes sender_public_key = 5;
    bytes payload = 6;
    bytes signature = 7;
    optional RoutingInfo routing_info = 8;

    // Reserved ranges for future extensions
    reserved 9, 10;          // Additional core fields
    reserved 11 to 20;       // Core extensions
    reserved 21 to 30;       // Metadata
    reserved 31 to 50;       // Future use
}
```

### Standard Allocation Pattern

All message types follow this pattern:

- **Fields 1-5**: Currently used fields
- **Fields 6-10**: Reserved for feature-specific extensions
- **Fields 11-20**: Reserved for general future use

Example:

```protobuf
message PrivateMessagePayload {
    bytes content = 1;
    bytes return_path = 2;
    bytes ephemeral_public_key = 3;
    bytes nonce = 4;

    reserved 5 to 10;   // Encryption enhancements
    reserved 11 to 20;  // Future use
}
```

## Backward Compatibility Rules

### ALLOWED (Backward Compatible)

These changes **DO NOT** break compatibility:

- ✅ Add new optional fields to existing messages
- ✅ Add new enum values (with reserved numbers for removed values)
- ✅ Add new message types
- ✅ Reserve field numbers for removed fields
- ✅ Add comments and documentation

### NOT ALLOWED (Breaking Changes)

These changes **BREAK** compatibility:

- ❌ Remove fields (mark as deprecated instead, use `reserved`)
- ❌ Change field types (`int32` → `int64`, etc.)
- ❌ Change field numbers
- ❌ Make optional fields required
- ❌ Remove enum values (reserve the number instead)
- ❌ Change message semantics without version bump

### Best Practices

1. **Always use `optional`** for new fields
2. **Document deprecation** in comments before removing
3. **Use `reserved` keyword** for removed field numbers
4. **Plan field numbers** carefully (leave gaps for future use)
5. **Test compatibility** before releasing changes

## Forward Compatibility

### Handling Unknown Message Types

When a node receives a message type it doesn't recognize:

```rust
pub enum MessageValidationResult {
    Valid,
    UnknownType { message_type: i32 },
    // ...
}

match validate_message(&msg) {
    MessageValidationResult::UnknownType { message_type } => {
        // Log and ignore (or forward if routing)
        log::warn!("Received unknown message type: {}", message_type);
    }
    // ...
}
```

**Key behavior**: Unknown types are logged and ignored, not treated as errors. This allows older nodes to operate in networks with newer nodes.

### Handling Unknown Fields

Protocol Buffers automatically handles unknown fields:

- When deserializing, unknown fields are silently ignored
- When re-serializing, unknown fields are preserved
- This allows new optional fields to pass through old nodes

## Version Compatibility Checking

### Compatibility Matrix

```rust
pub enum VersionCompatibility {
    FullyCompatible,                         // Same version
    BackwardCompatible { peer_version: u32 }, // Peer is older
    ForwardCompatible { peer_version: u32 },  // Peer is newer
    Incompatible { peer_version: u32 },       // Cannot communicate
}
```

### Compatibility Check

```rust
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
```

### Message Validation

Every received message is validated:

```rust
pub fn validate_message(message: &BaseMessage) -> MessageValidationResult {
    // 1. Check version compatibility
    let compat = check_version_compatibility(message.version);
    if matches!(compat, VersionCompatibility::Incompatible { .. }) {
        return MessageValidationResult::IncompatibleVersion {
            version: message.version,
        };
    }

    // 2. Check if message type is known
    let message_type = MessageType::try_from(message.message_type).ok();
    if message_type.is_none() {
        return MessageValidationResult::UnknownType {
            message_type: message.message_type,
        };
    }

    // 3. Validate type is supported
    // ...

    MessageValidationResult::Valid
}
```

## Field Deprecation Process

When deprecating a field:

### 1. Mark as Deprecated

```protobuf
message ExampleMessage {
    string new_field = 1;

    // Deprecated: Use new_field instead.
    // Will be removed in version 2.0.
    string old_field = 2 [deprecated = true];
}
```

### 2. Update Code

```rust
// Emit warning when deprecated field is used
if !msg.old_field.is_empty() {
    log::warn!("old_field is deprecated, use new_field instead");
}
```

### 3. Document Timeline

- Add deprecation notice to changelog
- Announce deprecation with timeline (e.g., 6 months)
- Remove in next major version only

### 4. Reserve Field Number

When finally removing:

```protobuf
message ExampleMessage {
    string new_field = 1;

    reserved 2;  // Was: old_field (deprecated in v1.2, removed in v2.0)
}
```

## Migration Path for Breaking Changes

If breaking changes are unavoidable (version 2.0):

### 1. Announcement Phase (6+ months)

- Announce breaking changes early
- Provide migration guide
- Offer migration tools if possible

### 2. Dual-Stack Period

```rust
// Support both v1 and v2 protocols
match peer_version {
    1 => handle_v1_message(msg),
    2 => handle_v2_message(msg),
    _ => return Err(UnsupportedVersion),
}
```

### 3. Version Negotiation

During connection handshake:

```rust
pub struct Handshake {
    pub supported_versions: Vec<u32>,  // e.g., [1, 2]
    pub preferred_version: u32,
}

// Select highest mutually supported version
let common_version = find_highest_common_version(
    our_versions,
    peer_versions
);
```

### 4. Gradual Migration

- Ensure v2 has feature parity with v1
- Run v2 in testing for extended period
- Gradually deprecate v1 support
- Eventually sunset v1 (with clear timeline)

## Testing Strategy

### 1. Backward Compatibility Tests

```rust
#[test]
fn test_old_message_to_new_node() {
    // Serialize with old schema
    let old_msg = create_v1_message();
    let bytes = serialize_message(&old_msg).unwrap();

    // Deserialize with new schema
    let new_msg: MessageV2 = deserialize_message(&bytes).unwrap();

    // Verify all old fields present
    assert_eq!(new_msg.old_field, old_msg.old_field);
    // Verify new fields have defaults
    assert_eq!(new_msg.new_field, default_value);
}
```

### 2. Forward Compatibility Tests

```rust
#[test]
fn test_new_message_to_old_node() {
    // Serialize with new schema (all fields)
    let new_msg = create_v2_message_with_all_fields();
    let bytes = serialize_message(&new_msg).unwrap();

    // Deserialize with old schema
    let old_msg: MessageV1 = deserialize_message(&bytes).unwrap();

    // Verify core fields present
    assert_eq!(old_msg.core_field, new_msg.core_field);
    // Unknown fields are ignored automatically
}
```

### 3. Cross-Version Communication Tests

```rust
#[test]
fn test_cross_version_communication() {
    // Spawn nodes with different versions
    let v1_node = spawn_node(version: 1);
    let v2_node = spawn_node(version: 2);

    // Exchange messages
    v1_node.send_to(&v2_node, msg);
    v2_node.send_to(&v1_node, msg);

    // Verify graceful degradation
    assert!(both_nodes_operational());
}
```

### 4. Unknown Type Handling Tests

```rust
#[test]
fn test_unknown_message_type_ignored() {
    let msg = BaseMessage {
        message_type: 999,  // Unknown
        // ...
    };

    let result = validate_message(&msg);
    assert!(matches!(result, MessageValidationResult::UnknownType { .. }));

    // Should not cause error, just logged and ignored
}
```

## Implementation Status

### Phase 1 (Current)

- ✅ All message types defined in protobuf
- ✅ Reserved field ranges allocated
- ✅ Version validation logic implemented
- ✅ Backward compatibility tests
- ✅ Documentation complete

### Phase 2-3

- 📋 Implement core message handlers
- 📋 Test version handling in real network conditions

### Phase 4

- 📋 Implement Phase 4 message types (routing)
- 📋 Test with mixed-version networks
- 📋 Validate graceful degradation

### Phase 5

- 📋 Implement Phase 5 message types (updates)
- 📋 Full cross-version compatibility testing
- 📋 Performance testing with version checks

## Guidelines for Future Development

### When Adding New Features

1. **Add optional fields only** (never required)
2. **Use reserved field numbers** from the allocated ranges
3. **Write compatibility tests** before implementing
4. **Update this documentation** with changes
5. **Announce changes** in changelog

### When Planning Version 2.0

1. **Exhaust all backward-compatible options first**
2. **Provide 6+ months notice** before breaking changes
3. **Implement dual-stack support** for transition period
4. **Create migration tools** for users
5. **Maintain clear upgrade path** with documentation

## References

- Protocol Buffers Language Guide: https://protobuf.dev/programming-guides/proto3/
- Protobuf Best Practices: https://protobuf.dev/programming-guides/api/
- Semantic Versioning: https://semver.org/
- `src/protocol/versioning.rs` - Version handling implementation
- `tests/protocol_versioning_tests.rs` - Compatibility test suite
- `proto/messages.proto` - Complete protocol definition

## Summary

Meshara's protocol versioning strategy prioritizes:

1. **Stability** - No breaking changes without major version bump
2. **Forward compatibility** - Older nodes can operate with newer nodes
3. **Backward compatibility** - Newer nodes support older message formats
4. **Predictability** - Clear rules for what changes are allowed
5. **Future-proofing** - Reserved field ranges prevent conflicts

By following these guidelines, Meshara can evolve its protocol while maintaining a stable, reliable network that gracefully handles version differences.

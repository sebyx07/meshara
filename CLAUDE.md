# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Meshara** is a Rust library for decentralized, privacy-preserving communication. It provides application developers with a simple API to add secure messaging, software distribution, and peer-to-peer communication without requiring cryptography or networking expertise.

**Core Design Principles**:
- Developer-friendly API that hides complexity
- Security by default (automatic encryption, signing, verification)
- Censorship-resistant (TLS-wrapped traffic indistinguishable from HTTPS)
- Protocol Buffers for efficient binary serialization
- Async-first using Rust async/await
- SOLID principles: Each module should have a single responsibility. Interfaces should be small and focused. Dependencies should point inward toward core abstractions. Code should be open for extension but closed for modification through careful use of traits and feature flags
- Concurrency and parallelism: Design for concurrent execution from the ground up. Use async/await for IO-bound operations and parallel processing for CPU-intensive tasks like cryptographic operations. Ensure thread-safety through Rust's ownership model and carefully designed shared state

**Key Technical Components**:
- **Cryptography**: Ed25519 (signing), X25519 (encryption), ChaCha20-Poly1305, Blake3 hashing
- **Networking**: TLS 1.3 with optional HTTP/2 framing for HTTPS mimicry
- **Serialization**: Protocol Buffers for all message types
- **Architecture**: Event-driven async API with automatic peer discovery and routing

## Documentation Resources

**Detailed Documentation** (`docs/`):
- Architecture guides covering cryptography, routing, networking, and message flow
- API references for Node, messaging, events, and authority functionality
- User guides for getting started, configuration, testing, and examples
- Security documentation including threat model, cryptographic design, and best practices

**MVP Development Plan** (`mvp/`):
- Phase-by-phase implementation roadmap with detailed specifications
- Phase 1: Core foundations (cryptography, protocol buffers, storage, error handling, testing)
- Phase 2: API layer (node implementation, message construction)
- Phase 3: Networking (TLS connections, peer discovery)
- Phase 4: Routing (basic routing, DHT integration)
- Phase 5: Authority system (authority nodes, update distribution)

## Development Commands

### Initial Setup
```bash
# Initialize Cargo workspace
cargo init --lib

# Build the library
cargo build

# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Run integration tests only
cargo test --test integration_tests

# Run unit tests only
cargo test --lib
```

### Code Quality
```bash
# Format code
cargo fmt

# Lint code
cargo clippy -- -D warnings

# Check code without building
cargo check

# Generate documentation
cargo doc --open

# Run benchmarks
cargo bench
```

### Development Mode
```bash
# Build with dev-mode feature (verbose logging, testing utilities)
cargo build --features dev-mode

# Run with specific features
cargo build --features "onion-routing,dht"
```

## Development Cycle

### Test-Driven Development (TDD)

Follow TDD workflow for all new features and bug fixes:

1. **Write failing test** - Define expected behavior before implementation
2. **Implement minimal code** - Make the test pass with simplest solution
3. **Refactor** - Improve code quality while keeping tests green
4. **Repeat** - Iterate for each component/function

### Pre-Commit Checklist

Before committing any code, ensure ALL of the following pass:

```bash
# 1. All tests pass
cargo test

# 2. Linter passes with no warnings
cargo clippy -- -D warnings

# 3. No compiler warnings
cargo build --all-features

# 4. Documentation compiles
cargo doc --no-deps --all-features

# 5. Security audit passes
cargo audit

# 6. Code is formatted
cargo fmt -- --check
```

**Never commit code that fails any of these checks.** This maintains code quality and prevents regressions from entering the codebase.

## Architecture Overview

### API Layer Structure

The library follows a **layered architecture** with clear separation of concerns:

1. **Public API Layer** (`src/api/`):
   - `Node`: Main entry point, manages lifecycle
   - `NodeBuilder`: Builder pattern for configuration
   - Event system for async message delivery
   - High-level methods that hide complexity

2. **Protocol Layer** (`src/protocol/`):
   - Protocol Buffer definitions and generated code
   - Message types: BaseMessage, PrivateMessagePayload, BroadcastPayload, UpdatePackage, QueryMessage, ResponseMessage
   - Serialization/deserialization logic
   - Message versioning and compatibility

3. **Cryptography Layer** (`src/crypto/`):
   - Key generation and management
   - Encryption/decryption (X25519 + ChaCha20-Poly1305)
   - Signing/verification (Ed25519)
   - Identity management and export/import

4. **Networking Layer** (`src/network/`):
   - TLS connection management
   - Peer discovery (mDNS, bootstrap nodes, DHT)
   - Connection pooling and lifecycle
   - NAT traversal

5. **Routing Layer** (`src/routing/`):
   - Message routing logic
   - Gossip protocol for broadcasts
   - Onion routing for enhanced privacy
   - Route discovery and maintenance

6. **Storage Layer** (`src/storage/`):
   - Encrypted key storage
   - Message deduplication (Bloom filters)
   - Configuration persistence
   - Update package caching

7. **Authority Layer** (`src/authority/`):
   - Authority key management
   - Update package verification
   - Query/response handling for authority nodes
   - Multi-signature verification

### Critical Design Patterns

**Builder Pattern**: `NodeBuilder` provides progressive disclosure - simple defaults with optional advanced configuration.

**Event-Driven Architecture**: All message delivery is async via callbacks. The node maintains event subscriptions and delivers events without blocking.

**Automatic Resource Management**: Connection pooling, peer discovery, and message routing happen automatically. Developers only call high-level APIs like `send_private_message()`.

**Zero-Copy Optimization**: Message processing uses references where possible to avoid unnecessary copying of encrypted payloads.

### Message Flow

**Sending Private Message**:
1. Developer calls `node.send_private_message(recipient, content)`
2. API layer looks up recipient's public key
3. Crypto layer encrypts content with X25519 key exchange
4. Protocol layer creates PrivateMessagePayload protobuf
5. Signs with Ed25519
6. Wraps in BaseMessage
7. Routing layer finds path to recipient
8. Network layer sends via TLS connection
9. Returns MessageId immediately (async delivery)

**Receiving Message**:
1. Network layer receives bytes on TLS connection
2. Protocol layer deserializes BaseMessage
3. Crypto layer verifies signature
4. If valid, decrypts payload
5. Deserializes inner message type
6. Event system delivers to registered callbacks
7. Developer's callback processes message content

### Traffic Obfuscation Strategy

All network traffic is wrapped in **TLS 1.3** to appear as HTTPS. Optional **HTTP/2 framing** makes messages look like REST API calls. The ALPN identifier "meshara/1.0" allows peers to recognize each other during TLS handshake while appearing as normal HTTPS to observers.

**Domain fronting** support (optional) allows connections through CDNs for censorship circumvention.

### Testing Strategy

**Unit Tests**: Each module has comprehensive unit tests for crypto operations, protocol serialization, routing logic.

**Integration Tests**: Full message flow tests with multiple nodes in simulated network.

**Mock Network**: Testing utility creates in-process node network with controllable latency and packet loss.

**Security Tests**: Fuzzing for protocol parsing, signature verification tests, encryption strength validation.

## Important Implementation Notes

### Protocol Buffers

All `.proto` files are in `proto/` directory. Use `prost` crate for Rust code generation. Build script (`build.rs`) generates Rust structs from protobuf schemas.

Message types are versioned - always include protocol version in BaseMessage. Backward compatibility is maintained by adding only optional fields.

### Cryptography

Never implement crypto primitives - use audited crates:
- `ed25519-dalek` for signing
- `x25519-dalek` for key exchange
- `chacha20poly1305` for encryption
- `blake3` for hashing

Keys are always stored encrypted at rest. Passphrase protection uses Argon2 KDF.

### Core Libraries (Don't Reinvent the Wheel)

**Cryptography (RustCrypto)**:
- `ed25519-dalek` - Ed25519 signatures
- `x25519-dalek` - X25519 key exchange
- `chacha20poly1305` - Authenticated encryption
- `blake3` - Fast hashing
- `argon2` - Password-based key derivation
- `zeroize` - Secure memory clearing
- `rand` / `rand_core` - Cryptographically secure RNG

**Networking**:
- `rustls` / `tokio-rustls` - Modern TLS 1.3 (no OpenSSL)
- `h2` - HTTP/2 framing (optional)
- `mdns-sd` - Local peer discovery via mDNS

**Async Runtime**:
- `tokio` - Default async runtime (feature: `tokio-runtime`)
- `smol` - Alternative lightweight runtime (feature: `smol-runtime`)
- `futures` - Async utilities

**Serialization**:
- `prost` / `prost-types` - Protocol Buffers codegen
- `serde` / `serde_json` - General serialization
- `bincode` - Fast binary encoding

**Data Structures**:
- `dashmap` - Concurrent HashMap
- `parking_lot` - Fast locks (Mutex, RwLock)
- `bytes` - Efficient byte buffers

**Storage**:
- `redb` - Embedded database (optional, feature: `persistent-storage`)

**Error Handling**:
- `thiserror` - Custom error types with `#[derive(Error)]`
- `anyhow` - Context-rich error handling

**Observability**:
- `tracing` / `tracing-subscriber` - Structured logging
- `prometheus` - Metrics (optional, feature: `metrics`)

**Dev/Test**:
- `criterion` - Benchmarking
- `proptest` - Property-based testing
- `tokio-test` - Async test utilities
- `tempfile` - Temporary directories for tests

### Async Runtime

Library should support both `tokio` and `async-std` via feature flags. Default to `tokio`. All public APIs must be async-first.

### Feature Flags

- `default`: Basic features (crypto, protobuf, TLS, mDNS discovery)
- `onion-routing`: Privacy mode with multi-hop routing
- `dht`: Distributed hash table for peer discovery
- `http2-framing`: HTTPS mimicry via HTTP/2 framing
- `domain-fronting`: Censorship circumvention support
- `dev-mode`: Development utilities (never enable in production)

### Error Handling

Use custom `Error` enum with variants for each subsystem. Errors must be:
- Machine-readable (error codes)
- Human-readable (clear messages)
- Contextual (what operation failed)
- Chainable (preserve source errors)

Never panic in library code - always return `Result`.

### Security Considerations

**DO**:
- Always verify signatures before processing messages
- Encrypt private keys at rest
- Use constant-time comparisons for secrets
- Validate all inputs from network
- Rate-limit message processing per peer

**DON'T**:
- Log private keys or plaintext message content
- Skip signature verification (even in tests, unless explicitly dev-mode)
- Trust peer-provided data without validation
- Store passphrases in memory longer than necessary

## Code Organization

```
meshara/
├── src/
│   ├── lib.rs                 # Public API exports
│   ├── api/                   # High-level developer API
│   │   ├── node.rs            # Node and NodeBuilder
│   │   ├── events.rs          # Event system
│   │   └── config.rs          # Configuration types
│   ├── protocol/              # Protocol Buffers
│   │   ├── mod.rs
│   │   └── messages.rs        # Generated protobuf code
│   ├── crypto/                # Cryptographic operations
│   │   ├── mod.rs
│   │   ├── keys.rs            # Key generation and management
│   │   ├── encryption.rs      # Encryption/decryption
│   │   └── signing.rs         # Signature operations
│   ├── network/               # Networking
│   │   ├── mod.rs
│   │   ├── tls.rs             # TLS connection handling
│   │   ├── discovery.rs       # Peer discovery
│   │   └── connection.rs      # Connection management
│   ├── routing/               # Message routing
│   │   ├── mod.rs
│   │   ├── gossip.rs          # Broadcast propagation
│   │   └── onion.rs           # Onion routing (feature-gated)
│   ├── storage/               # Persistent storage
│   │   ├── mod.rs
│   │   └── keystore.rs        # Encrypted key storage
│   ├── authority/             # Authority node functionality
│   │   ├── mod.rs
│   │   └── updates.rs         # Update package handling
│   └── error.rs               # Error types
├── proto/                     # Protocol Buffer definitions
│   └── messages.proto
├── tests/                     # Integration tests
│   └── integration_tests.rs
├── benches/                   # Benchmarks
│   └── crypto_bench.rs
├── examples/                  # Example projects
│   ├── simple_messaging.rs    # Basic messaging example
│   ├── software_updates.rs    # Update distribution example
│   └── chat_app.rs            # Group chat example
├── build.rs                   # Build script (protobuf generation)
└── Cargo.toml
```

## Development Workflow

When implementing new features:

1. **Start with the public API** - design what developers will use
2. **Define protocol messages** - update `.proto` files if needed
3. **Implement crypto layer** - secure operations first
4. **Build networking layer** - TLS and connection management
5. **Add routing logic** - message delivery
6. **Write integration tests** - full message flow
7. **Add examples** - demonstrate usage

Always maintain backward compatibility for protocol messages. Use optional fields for new features.

## Example Projects Directory

The `examples/` directory contains complete, runnable applications demonstrating library usage:

- `simple_messaging.rs`: Basic encrypted messaging between two peers
- `software_updates.rs`: Authority node publishing signed updates
- `chat_app.rs`: Multi-user group chat with broadcast and private messages

These examples serve as both documentation and integration tests. They should compile and run with `cargo run --example <name>`.

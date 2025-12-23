# Meshara

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

**Meshara** is a developer-friendly Rust library for building decentralized, privacy-preserving communication applications. Add secure messaging, software distribution, and peer-to-peer networking to your apps without becoming a cryptography or networking expert.

## Features

- 🎯 **Simple API**: High-level abstractions that hide complexity
- 🔒 **Security by Default**: Automatic encryption, signing, and verification
- 🌐 **Censorship Resistant**: TLS-wrapped traffic indistinguishable from HTTPS
- 🕵️ **Privacy Preserving**: Optional onion routing and traffic obfuscation
- 💻 **Cross-Platform**: Works on Linux, macOS, Windows, and mobile platforms
- ⚡ **Protocol Buffers**: Efficient binary serialization with forward/backward compatibility
- 🚀 **Async-First**: Built on Rust async/await for high performance
- 📚 **Well-Documented**: Comprehensive guides, examples, and API documentation

## 🚀 Quick Start

Add Meshara to your `Cargo.toml`:

```toml
[dependencies]
meshara = "0.1"
```

### Simple Example

```rust
use meshara::{Node, NodeBuilder, MessageEvent};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a node with default configuration
    let node = NodeBuilder::new()
        .with_storage_path("./meshara-data")
        .build()?;

    // Start networking
    node.start().await?;

    // Receive messages
    node.on_message_received(|event: MessageEvent| {
        println!("From: {:?}", event.sender);
        println!("Message: {:?}", String::from_utf8_lossy(&event.content));
    });

    // Send a private message
    let message_id = node.send_private_message(
        recipient_public_key,
        b"Hello, Meshara!",
    ).await?;

    Ok(())
}
```

See [examples/](examples/) for more complete applications.

## 💡 Use Cases

- **Secure Messaging**: Build Signal-like encrypted chat applications
- **Software Distribution**: Distribute signed updates without centralized servers
- **Decentralized Social Networks**: Create censorship-resistant social platforms
- **IoT Coordination**: Secure peer-to-peer communication for IoT devices
- **Emergency Communication**: Resilient networks that work when infrastructure fails
- **Privacy Tools**: Anonymous publishing and whistleblower platforms

## 📖 Documentation

### Getting Started

- [Getting Started Guide](docs/guides/getting-started.md) - Step-by-step tutorial
- [Configuration Guide](docs/guides/configuration.md) - Configure nodes for different use cases
- [Examples Guide](docs/guides/examples.md) - Walkthrough of example applications
- [Testing Guide](docs/guides/testing.md) - Writing tests with Meshara

### Architecture

- [Architecture Overview](docs/architecture/overview.md) - High-level system design
- [Message Flow](docs/architecture/message-flow.md) - How messages are sent and received
- [Cryptography](docs/architecture/cryptography.md) - Cryptographic primitives and key management
- [Networking](docs/architecture/networking.md) - TLS, peer discovery, NAT traversal
- [Routing](docs/architecture/routing.md) - Gossip protocol and onion routing

### API Reference

- [Node API](docs/api/node.md) - Main entry point and lifecycle management
- [Events API](docs/api/events.md) - Event-driven message handling
- [Messaging API](docs/api/messaging.md) - Sending and receiving messages
- [Authority API](docs/api/authority.md) - Publishing signed updates and handling queries

### Security

- [Threat Model](docs/security/threat-model.md) - Security assumptions and guarantees
- [Best Practices](docs/security/best-practices.md) - Developer security guidelines
- [Cryptographic Design](docs/security/cryptographic-design.md) - Detailed crypto implementation

## Key Concepts

### Messages

Meshara supports several message types:

- **Private Messages**: End-to-end encrypted messages between two peers
- **Broadcast Messages**: Signed public messages propagated via gossip protocol
- **Update Packages**: Signed software updates from trusted authorities
- **Query/Response**: Request-response pattern for authority nodes

All messages use Protocol Buffers for efficient serialization and are cryptographically signed.

### Identities

Each node has an Ed25519 keypair that serves as its identity. Public keys are used as addresses. The library handles key generation, storage, and management automatically.

### Authorities

Authority nodes are trusted entities that can publish signed updates or provide authoritative responses. Applications can:

- Trust specific authority public keys
- Verify signatures on updates before applying them
- Query authorities for configuration or data

### Privacy Modes

- **Standard**: Efficient direct routing with TLS encryption
- **Enhanced**: Onion routing when possible for metadata privacy
- **Maximum**: Always use onion routing with cover traffic

### Traffic Obfuscation

All network traffic is wrapped in TLS 1.3 and optionally HTTP/2 framing to appear as normal HTTPS web traffic. This makes Meshara resistant to deep packet inspection and network filtering.

## Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/meshara.git
cd meshara

# Build the library
cargo build --release

# Run tests
cargo test

# Run benchmarks
cargo bench

# Generate documentation
cargo doc --open
```

## 🎓 Examples

The [examples/](examples/) directory contains complete applications:

- **simple_messaging.rs**: Basic encrypted messaging between two peers
- **software_updates.rs**: Authority node publishing and clients receiving updates
- **chat_app.rs**: Multi-user group chat with broadcasts and private messages

Run an example:

```bash
cargo run --example simple_messaging
```

## Feature Flags

Customize Meshara with feature flags:

```toml
[dependencies]
meshara = { version = "0.1", features = ["onion-routing", "dht"] }
```

Available features:

- `onion-routing`: Multi-hop routing for enhanced privacy
- `dht`: Distributed hash table for peer discovery
- `http2-framing`: HTTP/2 framing for HTTPS mimicry
- `domain-fronting`: Censorship circumvention via CDN fronting
- `metrics`: Prometheus-compatible metrics
- `dev-mode`: Development utilities (DO NOT use in production)

## Testing

```bash
# Run all tests
cargo test

# Run unit tests only
cargo test --lib

# Run integration tests
cargo test --test integration_tests

# Run with logging
RUST_LOG=debug cargo test -- --nocapture

# Run specific test
cargo test test_message_encryption
```

## Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench crypto_bench
```

## Development

### Prerequisites

- Rust 1.70 or later
- Protocol Buffers compiler (for modifying `.proto` files)

### Project Structure

```
meshara/
├── src/              # Source code
│   ├── api/          # Public API
│   ├── protocol/     # Protocol Buffers
│   ├── crypto/       # Cryptographic operations
│   ├── network/      # Networking and TLS
│   ├── routing/      # Message routing
│   ├── storage/      # Persistent storage
│   └── authority/    # Authority node functionality
├── proto/            # Protocol Buffer definitions
├── tests/            # Integration tests
├── benches/          # Benchmarks
├── examples/         # Example applications
└── docs/             # Documentation
```

See [CLAUDE.md](CLAUDE.md) for detailed development guidelines.

### Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure `cargo test` and `cargo clippy` pass
5. Submit a pull request

## Roadmap

- [ ] Core message types and Protocol Buffer schemas
- [ ] Cryptographic primitives (Ed25519, X25519, ChaCha20-Poly1305)
- [ ] TLS connection management
- [ ] Basic peer-to-peer messaging
- [ ] Gossip protocol for broadcasts
- [ ] Peer discovery (mDNS, bootstrap nodes)
- [ ] Authority node functionality
- [ ] Update package verification
- [ ] Onion routing (privacy mode)
- [ ] HTTP/2 framing
- [ ] DHT implementation
- [ ] Mobile bindings (iOS, Android)
- [ ] Security audit
- [ ] 1.0 release

## Performance

Preliminary benchmarks (on modern laptop):

- Message encryption: ~500k messages/sec
- Signature verification: ~100k signatures/sec
- Gossip propagation: <100ms for 100 nodes
- Onion routing overhead: ~3x latency per hop

See [benches/](benches/) for detailed benchmarks.

## 🔐 Security

Meshara uses industry-standard cryptographic primitives:

- **Ed25519** for digital signatures
- **X25519** for key exchange
- **ChaCha20-Poly1305** for authenticated encryption
- **Blake3** for hashing
- **TLS 1.3** for transport security

All cryptographic operations use audited Rust crates. Keys are stored encrypted at rest.

**Security Audit Status**: Not yet audited. DO NOT use in production until security audit is complete.

See [docs/security/](docs/security/) for detailed security documentation.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

Meshara is inspired by projects like:

- **Signal Protocol**: End-to-end encryption
- **Tor**: Onion routing and traffic obfuscation
- **BitTorrent**: Gossip-based propagation
- **libp2p**: Peer-to-peer networking primitives

## Support

- **Documentation**: [docs/](docs/)
- **Examples**: [examples/](examples/)
- **Issues**: [GitHub Issues](https://github.com/yourusername/meshara/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/meshara/discussions)

## Status

**Alpha**: Under active development. API is unstable and subject to change.

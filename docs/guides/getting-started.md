# Getting Started

This guide walks you through creating your first Meshara application from scratch.

## Installation

Add Meshara to your `Cargo.toml`:

```toml
[dependencies]
meshara = "1.0"
tokio = { version = "1.0", features = ["full"] }
```

For specific features:

```toml
[dependencies]
meshara = { version = "1.0", features = ["onion-routing", "dht"] }
```

## Your First Meshara Application

### Simple Private Messaging

Create a basic two-node messaging system:

```rust
use meshara::{Node, NodeBuilder, MessageEvent, EventType};

#[tokio::main]
async fn main() -> Result<(), meshara::Error> {
    // Create first node (Alice)
    let alice = NodeBuilder::new()
        .with_storage_path("./alice_data")
        .with_listen_port(8443)
        .build()
        .await?;

    // Create second node (Bob)
    let bob = NodeBuilder::new()
        .with_storage_path("./bob_data")
        .with_listen_port(8444)
        .build()
        .await?;

    // Start both nodes
    alice.start().await?;
    bob.start().await?;

    // Bob subscribes to messages
    bob.on_message_received(|event: MessageEvent| async move {
        println!("Bob received: {}",
                 String::from_utf8_lossy(&event.content));
    }).await?;

    // Connect nodes (for local testing)
    alice.add_peer(
        "127.0.0.1:8444".parse().unwrap(),
        Some(bob.public_key()),
    ).await?;

    // Alice sends message to Bob
    let bob_public_key = bob.public_key();
    let message_id = alice.send_private_message(
        &bob_public_key,
        b"Hello, Bob!",
    ).await?;

    println!("Alice sent message: {}", message_id);

    // Wait for message delivery
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Cleanup
    alice.stop().await?;
    bob.stop().await?;

    Ok(())
}
```

**What's happening**:

1. **Create nodes**: Two separate Meshara instances with different storage and ports
2. **Start networking**: Begin listening for connections and discovering peers
3. **Subscribe to events**: Bob registers callback for incoming messages
4. **Connect peers**: Alice manually connects to Bob (for testing)
5. **Send message**: Alice encrypts and sends private message to Bob
6. **Receive message**: Bob's callback triggered when message arrives
7. **Cleanup**: Graceful shutdown

**Run it**:
```bash
cargo run
```

**Expected output**:
```
Alice sent message: 7f3a2b1c...
Bob received: Hello, Bob!
```

## Understanding Key Concepts

### Node Identity

Each node automatically generates a unique Ed25519 keypair on first run:

```rust
let node = NodeBuilder::new()
    .with_storage_path("./node_data")
    .build()
    .await?;

// Node identity never changes (unless you delete storage)
println!("My public key: {}", node.public_key().to_hex());
println!("My node ID: {}", node.node_id());
```

**Identity persistence**:
- Keys stored encrypted in `./node_data/keystore`
- Same identity across restarts
- Delete storage directory to reset identity

### Message Encryption

All private messages are automatically encrypted:

```rust
// This message is encrypted end-to-end
node.send_private_message(recipient, b"Secret data").await?;
```

**What happens automatically**:
1. Generate ephemeral X25519 key (forward secrecy)
2. Perform key exchange with recipient's public key
3. Encrypt content with ChaCha20-Poly1305
4. Sign encrypted payload with Ed25519
5. Send over TLS connection

**You don't need to**:
- Manage encryption keys
- Choose cipher algorithms
- Handle key exchange
- Implement forward secrecy

### Event-Driven Architecture

All message delivery is asynchronous via callbacks:

```rust
// Register multiple event handlers
node.on_message_received(handle_message).await?;
node.on_peer_connected(handle_peer_connected).await?;
node.on_peer_disconnected(handle_peer_disconnected).await?;
node.on_update_available(handle_update).await?;

async fn handle_message(event: MessageEvent) {
    println!("From: {}", event.sender.to_hex());
    println!("Content: {:?}", event.content);
    println!("Verified: {}", event.verified);
}

async fn handle_peer_connected(event: PeerEvent) {
    println!("Peer connected: {}", event.peer_id);
}

async fn handle_peer_disconnected(event: PeerEvent) {
    println!("Peer disconnected: {}", event.peer_id);
}

async fn handle_update(event: UpdateEvent) {
    if event.verified {
        println!("Update available: {}", event.version);
        println!("Changelog: {}", event.changelog);
    }
}
```

**Callbacks are**:
- Non-blocking (async)
- Concurrent (multiple callbacks execute in parallel)
- Order-preserving (per event type)

## Building a Chat Application

**Complete example** with user input:

```rust
use meshara::{Node, NodeBuilder, MessageEvent};
use std::io::{self, BufRead};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create node
    let node = NodeBuilder::new()
        .with_storage_path("./chat_node")
        .with_listen_port(8443)
        .enable_auto_discovery()
        .build()
        .await?;

    node.start().await?;

    println!("Chat node started");
    println!("Your public key: {}", node.public_key().to_hex());
    println!("Your node ID: {}", node.node_id());

    // Subscribe to messages
    node.on_message_received(|event: MessageEvent| async move {
        let sender_short = &event.sender.to_hex()[..8];
        let message = String::from_utf8_lossy(&event.content);
        println!("\n[{}]: {}", sender_short, message);
        print!("> ");
        io::stdout().flush().unwrap();
    }).await?;

    // Subscribe to peer events
    node.on_peer_connected(|event| async move {
        println!("\n✓ Peer connected: {}", event.peer_id);
        print!("> ");
        io::stdout().flush().unwrap();
    }).await?;

    // Main loop - read user input
    println!("\nCommands:");
    println!("  /connect <addr> - Connect to peer (e.g., /connect 192.168.1.5:8443)");
    println!("  /peers - List connected peers");
    println!("  /send <pubkey> <message> - Send to specific peer");
    println!("  /broadcast <message> - Broadcast to all");
    println!("  /quit - Exit");
    println!();

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        let parts: Vec<&str> = line.splitn(2, ' ').collect();

        match parts[0] {
            "/connect" => {
                if parts.len() < 2 {
                    println!("Usage: /connect <addr:port>");
                    continue;
                }
                let addr = parts[1].parse()?;
                match node.add_peer(addr, None).await {
                    Ok(peer_id) => println!("Connected: {}", peer_id),
                    Err(e) => println!("Connection failed: {}", e),
                }
            }

            "/peers" => {
                let peers = node.list_peers().await?;
                println!("Connected peers: {}", peers.len());
                for peer in peers {
                    println!("  {} - {}", peer.peer_id, peer.address);
                }
            }

            "/send" => {
                let parts: Vec<&str> = parts[1].splitn(2, ' ').collect();
                if parts.len() < 2 {
                    println!("Usage: /send <pubkey> <message>");
                    continue;
                }

                let recipient = parts[0].parse()?;
                let message = parts[1].as_bytes();

                match node.send_private_message(&recipient, message).await {
                    Ok(msg_id) => println!("Sent: {}", msg_id),
                    Err(e) => println!("Send failed: {}", e),
                }
            }

            "/broadcast" => {
                if parts.len() < 2 {
                    println!("Usage: /broadcast <message>");
                    continue;
                }

                let message = parts[1].as_bytes();
                match node.broadcast_message(message).await {
                    Ok(msg_id) => println!("Broadcast: {}", msg_id),
                    Err(e) => println!("Broadcast failed: {}", e),
                }
            }

            "/quit" => {
                println!("Shutting down...");
                node.stop().await?;
                break;
            }

            _ => {
                println!("Unknown command. Type /help for commands.");
            }
        }

        print!("> ");
        io::stdout().flush().unwrap();
    }

    Ok(())
}
```

**Features demonstrated**:
- Automatic peer discovery
- Manual peer connection
- Private messaging
- Broadcasting
- Peer management
- Graceful shutdown

## Peer Discovery

### Automatic Discovery (mDNS)

For local network:

```rust
let node = NodeBuilder::new()
    .with_storage_path("./node_data")
    .enable_auto_discovery()  // Enables mDNS
    .build()
    .await?;

node.start().await?;

// Peers on same subnet discovered automatically
tokio::time::sleep(Duration::from_secs(5)).await;

let peers = node.list_peers().await?;
println!("Discovered {} peers", peers.len());
```

### Bootstrap Nodes

For connecting to wider network:

```rust
let bootstrap_nodes = vec![
    "bootstrap1.meshara.network:443".parse()?,
    "bootstrap2.meshara.network:443".parse()?,
];

let node = NodeBuilder::new()
    .with_storage_path("./node_data")
    .with_bootstrap_nodes(bootstrap_nodes)
    .build()
    .await?;

node.start().await?;
```

### Manual Peer Addition

For specific peers:

```rust
// Add peer without public key pinning
let peer_id = node.add_peer("192.168.1.5:8443".parse()?, None).await?;

// Add peer with public key pinning (more secure)
let peer_public_key = PublicKey::from_hex("7f3a2b...")?;
let peer_id = node.add_peer(
    "192.168.1.5:8443".parse()?,
    Some(peer_public_key),
).await?;
```

## Configuration

### Builder Pattern

Progressive disclosure of configuration options:

```rust
let node = NodeBuilder::new()
    // Storage
    .with_storage_path("./meshara_data")

    // Networking
    .with_listen_port(443)  // Default HTTPS port
    .with_max_peers(200)
    .with_min_peers(20)

    // Discovery
    .enable_auto_discovery()
    .with_bootstrap_nodes(bootstrap_list)

    // Privacy
    .with_privacy_level(PrivacyLevel::Enhanced)  // Uses onion routing

    // Features
    .enable_feature(Feature::Http2Framing)
    .enable_feature(Feature::DomainFronting)

    // Authority
    .with_authority_keys(vec![authority_pubkey])

    .build()
    .await?;
```

### Privacy Levels

**Standard** (default):
- Direct routing when possible
- Bridge routing otherwise
- Good performance, some metadata leakage

**Enhanced**:
- Onion routing when available
- Falls back to bridge routing
- Better privacy, moderate performance impact

**Maximum**:
- Always onion routing (requires `onion-routing` feature)
- Best privacy, highest latency
- Fails if onion routing unavailable

```rust
let node = NodeBuilder::new()
    .with_privacy_level(PrivacyLevel::Maximum)
    .build()
    .await?;
```

## Broadcasting

Send public messages to all peers:

```rust
// Send broadcast
let msg_id = node.broadcast_message(b"Public announcement").await?;

// Receive broadcasts
node.on_message_received(|event: MessageEvent| async move {
    if event.message_type == MessageType::Broadcast {
        println!("Broadcast from {}: {}",
                 event.sender.to_hex(),
                 String::from_utf8_lossy(&event.content));
    }
}).await?;
```

**Characteristics**:
- Not encrypted (signed only)
- Propagates via gossip protocol
- Reaches all reachable nodes
- ~2 seconds for 100 nodes

## Error Handling

Comprehensive error types:

```rust
match node.send_private_message(&recipient, &message).await {
    Ok(msg_id) => println!("Sent: {}", msg_id),

    Err(Error::Network(NetworkError::NoRoute)) => {
        println!("Cannot reach recipient - not connected to network");
    }

    Err(Error::Crypto(CryptoError::InvalidPublicKey)) => {
        println!("Invalid recipient public key");
    }

    Err(Error::MessageTooLarge) => {
        println!("Message exceeds size limit");
    }

    Err(e) => {
        println!("Send failed: {}", e);
    }
}
```

## Logging

Configure logging output:

```rust
use tracing_subscriber;

// Setup logging before creating node
tracing_subscriber::fmt()
    .with_max_level(tracing::Level::DEBUG)
    .init();

let node = NodeBuilder::new()
    .with_storage_path("./node_data")
    .build()
    .await?;

// Logs will show:
// - Connection events
// - Message routing decisions
// - Cryptographic operations
// - Errors and warnings
```

## Next Steps

- **Testing**: See [testing.md](testing.md) for test strategies
- **Configuration**: See [configuration.md](configuration.md) for advanced options
- **Examples**: See [examples.md](examples.md) for more complete applications
- **API Reference**: See [api/](../api/) for detailed API documentation
- **Architecture**: See [architecture/](../architecture/) for system internals

## Common Patterns

### Request/Response

```rust
// Query authority node
let response = node.query_authority(
    authority_id,
    query_bytes,
    Duration::from_secs(30),  // Timeout
).await?;
```

### Identity Export/Import

```rust
// Export identity for backup
let identity_bundle = node.export_identity("passphrase").await?;
std::fs::write("identity_backup.bin", identity_bundle)?;

// Import on another device
let bundle = std::fs::read("identity_backup.bin")?;
let node = NodeBuilder::new()
    .with_imported_identity(&bundle, "passphrase")?
    .build()
    .await?;
```

### Multiple Event Handlers

```rust
// Multiple handlers for same event
node.on_message_received(log_message).await?;
node.on_message_received(process_message).await?;
node.on_message_received(forward_to_ui).await?;

// All execute concurrently
```

### Graceful Shutdown

```rust
// Listen for Ctrl+C
tokio::signal::ctrl_c().await?;

// Graceful shutdown
node.stop().await?;

// All connections closed
// All pending messages flushed
// Storage synced to disk
```

# Simple Messaging Example

This example demonstrates basic encrypted peer-to-peer messaging with Meshara. It consists of two simple programs: Alice and Bob, which can send encrypted messages to each other.

## Features

- **Point-to-Point Encryption**: All messages are encrypted end-to-end using X25519 + ChaCha20-Poly1305
- **Authenticated Communication**: Messages are signed with Ed25519 for authenticity
- **Simple CLI Interface**: Easy command-line interface for both nodes
- **Real-Time Display**: Messages are displayed as they arrive
- **Event-Driven**: Demonstrates Meshara's event system for message handling

## Building

From the `examples/simple_messaging` directory:

```bash
# Build both binaries
cargo build --release

# Or build individually
cargo build --release --bin alice
cargo build --release --bin bob
```

## Usage

### Step 1: Start Bob

Bob will listen for incoming messages and display his public key:

```bash
cargo run --release --bin bob
```

Output:
```
════════════════════════════════════════════════════════════
Bob's Node
════════════════════════════════════════════════════════════
Listening on:  0.0.0.0:9001
Node ID:       a3f2c1...
Public Key:    8f4d2e1a...
════════════════════════════════════════════════════════════

💡 Alice can send messages to Bob using this public key:
   cargo run --bin alice -- --bob-pubkey 8f4d2e1a...

Waiting for messages from Alice... (Press Ctrl+C to exit)
```

### Step 2: Start Alice and Send Message

Copy Bob's public key from the output above and use it to send a message:

```bash
cargo run --release --bin alice -- --bob-pubkey <BOB_PUBLIC_KEY>
```

Alice will:
1. Start her node
2. Display her connection info
3. Send a message to Bob
4. Wait for Bob's response

### Example Session

**Terminal 1 (Bob):**
```
$ cargo run --release --bin bob
Bob's Node
Listening on:  0.0.0.0:9001
Public Key:    8f4d2e1a7c3b9e5f...

Waiting for messages from Alice...

📬 Message: Hello Bob! This is Alice. 👋
```

**Terminal 2 (Alice):**
```
$ cargo run --release --bin alice -- --bob-pubkey 8f4d2e1a7c3b9e5f...
Alice's Node
Listening on:  0.0.0.0:9000
Public Key:    2d4e8f1b3c7a9e5f...

✅ Sent message to Bob
   Message ID: 1f3c5a...
   Content: Hello Bob! This is Alice. 👋

Waiting for messages...
```

## Command-Line Options

### Alice

```
Usage: alice [OPTIONS]

Options:
  -p, --port <PORT>              Port to listen on [default: 9000]
  -b, --bob-pubkey <BOB_PUBKEY>  Bob's public key (hex-encoded)
  -s, --storage <STORAGE>        Storage directory for keys
  -d, --debug                    Enable debug logging
  -h, --help                     Print help
  -V, --version                  Print version
```

### Bob

```
Usage: bob [OPTIONS]

Options:
  -p, --port <PORT>        Port to listen on [default: 9001]
  -s, --storage <STORAGE>  Storage directory for keys
  -d, --debug              Enable debug logging
  -h, --help               Print help
  -V, --version            Print version
```

## How It Works

### Alice (Sender)

1. **Node Creation**: Creates a Meshara node with persistent identity storage
2. **Event Registration**: Registers callback to handle incoming messages
3. **Node Start**: Starts the node and begins listening for connections
4. **Send Message**: Encrypts and sends a message to Bob using his public key
5. **Wait for Response**: Listens for Bob's response

### Bob (Receiver)

1. **Node Creation**: Creates a Meshara node with persistent identity storage
2. **Event Registration**: Registers callback to handle incoming messages
3. **Node Start**: Starts the node and displays public key
4. **Receive Message**: Decrypts and verifies incoming messages
5. **Display**: Shows received messages in real-time

### Security

All messages are:
- **Encrypted** with X25519 (ECDH) + ChaCha20-Poly1305 (AEAD)
- **Signed** with Ed25519 for authenticity verification
- **Transmitted** over TLS 1.3 connections

Keys are stored encrypted on disk using the Meshara keystore.

## Testing

Run the integration tests:

```bash
cargo test --verbose
```

Tests verify:
- Node creation and lifecycle
- Event handler registration
- Public key encoding/decoding
- Node ID generation
- Message exchange between nodes

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Alice's Node                          │
│                                                               │
│  ┌──────────────┐         ┌──────────────┐                  │
│  │   CLI Args   │────────▶│  NodeBuilder │                  │
│  └──────────────┘         └──────┬───────┘                  │
│                                   │                          │
│                                   ▼                          │
│                          ┌─────────────────┐                 │
│                          │  Meshara Node   │                 │
│                          │  - Identity     │                 │
│                          │  - TLS Listener │                 │
│                          │  - Event System │                 │
│                          └────────┬────────┘                 │
│                                   │                          │
│                                   │ Encrypted Message        │
│                                   │ (X25519 + ChaCha20)      │
│                                   │ + Ed25519 Signature      │
└───────────────────────────────────┼──────────────────────────┘
                                    │
                                    │ TLS 1.3
                                    │
┌───────────────────────────────────┼──────────────────────────┐
│                                   │                          │
│                                   ▼                          │
│                          ┌─────────────────┐                 │
│                          │  Meshara Node   │                 │
│                          │  - Identity     │                 │
│                          │  - TLS Listener │                 │
│                          │  - Event System │                 │
│                          └────────┬────────┘                 │
│                                   │                          │
│                                   ▼                          │
│                          ┌─────────────────┐                 │
│                          │ Event Handler   │                 │
│                          │ (Auto-respond)  │                 │
│                          └─────────────────┘                 │
│                                                               │
│                        Bob's Node                            │
└─────────────────────────────────────────────────────────────┘
```

## Key Concepts Demonstrated

1. **Identity Management**: Each node has a persistent Ed25519/X25519 keypair
2. **Event-Driven Architecture**: Message handling via callbacks
3. **Async I/O**: All network operations are async with Tokio
4. **Encryption**: Automatic end-to-end encryption for all messages
5. **Authentication**: Signature verification ensures message authenticity

## Troubleshooting

### "Connection refused" errors

Make sure both nodes are running and can reach each other on the network. By default:
- Alice listens on port 9000
- Bob listens on port 9001

### "Invalid public key" errors

Ensure you've copied Bob's complete public key (128 hex characters) when starting Alice.

### Debug logging

Enable debug logging to see detailed information:

```bash
cargo run --release --bin alice -- --debug --bob-pubkey <KEY>
cargo run --release --bin bob -- --debug
```

## Next Steps

After running this example, check out:

- **Chat App**: Full-featured group chat with terminal UI (`examples/chat_app/`)
- **Software Updates**: Authority node and update distribution (`examples/software_updates/`)
- **Meshara Documentation**: Complete API reference in `docs/`

## License

This example is part of the Meshara project and shares the same license.

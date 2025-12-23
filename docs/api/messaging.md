# Messaging API Reference

The messaging API provides methods for sending and receiving encrypted messages.

## Message Types

### MessageType

```rust
pub enum MessageType {
    PrivateMessage,   // Encrypted point-to-point
    Broadcast,        // Signed public message
    UpdatePackage,    // Authority-signed update
    Query,            // Request to authority
    Response,         // Response to query
}
```

## Sending Messages

### send_private_message

Send encrypted message to specific recipient.

```rust
impl Node {
    pub async fn send_private_message(
        &self,
        recipient: &PublicKey,
        content: &[u8],
    ) -> Result<MessageId, Error>
}
```

**End-to-end encryption**: Content encrypted with recipient's public key. Only sender and recipient can read.

**Forward secrecy**: Each message uses ephemeral key. Compromise of long-term key doesn't reveal past messages.

**Example**:
```rust
let message = b"Secret data";
let recipient_key = PublicKey::from_hex("7f3a...")?;

let msg_id = node.send_private_message(&recipient_key, message).await?;
println!("Sent: {}", msg_id);
```

**Size limits**:
- Maximum: 16 MB per message
- Recommended: < 1 MB for best performance

**Latency**:
- Direct routing: 50-200ms
- Bridge routing: 200-500ms
- Onion routing: 500-1000ms

### send_private_message_with_options

Send with custom options.

```rust
impl Node {
    pub async fn send_private_message_with_options(
        &self,
        recipient: &PublicKey,
        content: &[u8],
        options: SendOptions,
    ) -> Result<MessageId, Error>
}

pub struct SendOptions {
    pub privacy_level: PrivacyLevel,
    pub priority: MessagePriority,
    pub ttl: Duration,
    pub delivery_confirmation: bool,
}
```

**Example**:
```rust
let options = SendOptions {
    privacy_level: PrivacyLevel::Maximum,  // Force onion routing
    priority: MessagePriority::High,
    ttl: Duration::from_secs(300),  // 5 minute expiry
    delivery_confirmation: true,
};

node.send_private_message_with_options(&recipient, message, options).await?;
```

### broadcast_message

Send public message to all reachable peers.

```rust
impl Node {
    pub async fn broadcast_message(
        &self,
        content: &[u8],
    ) -> Result<MessageId, Error>
}
```

**Not encrypted**: Content signed but visible to all peers.

**Propagation**: Gossip protocol distributes to entire network.

**Example**:
```rust
let announcement = b"New version available!";
node.broadcast_message(announcement).await?;
```

**Use cases**:
- Public announcements
- Network-wide notifications
- Software update notifications
- Discovery messages

### broadcast_with_metadata

Broadcast with structured metadata.

```rust
impl Node {
    pub async fn broadcast_with_metadata(
        &self,
        content: &[u8],
        content_type: &str,
        metadata: HashMap<String, String>,
    ) -> Result<MessageId, Error>
}
```

**Example**:
```rust
let mut metadata = HashMap::new();
metadata.insert("version".to_string(), "2.0.0".to_string());
metadata.insert("platform".to_string(), "linux-x86_64".to_string());

node.broadcast_with_metadata(
    update_binary,
    "application/octet-stream",
    metadata,
).await?;
```

## Receiving Messages

Messages delivered via event callbacks. See [events.md](events.md) for details.

### MessageEvent

Structure delivered to message callbacks:

```rust
pub struct MessageEvent {
    pub message_id: MessageId,
    pub sender: PublicKey,
    pub content: Vec<u8>,
    pub timestamp: u64,
    pub verified: bool,
    pub message_type: MessageType,
    pub metadata: Option<HashMap<String, String>>,
}
```

**Fields**:
- `message_id`: Unique identifier (Blake3 hash)
- `sender`: Sender's public key
- `content`: Message payload
- `timestamp`: Unix timestamp (milliseconds)
- `verified`: Signature verification result
- `message_type`: Type of message
- `metadata`: Optional metadata (broadcasts only)

**Example handler**:
```rust
node.on_message_received(|event: MessageEvent| async move {
    // Always check signature verification
    if !event.verified {
        println!("Warning: Invalid signature from {}", event.sender.to_hex());
        return;
    }

    match event.message_type {
        MessageType::PrivateMessage => {
            let text = String::from_utf8_lossy(&event.content);
            println!("Private message from {}: {}", event.sender.to_hex(), text);
        }

        MessageType::Broadcast => {
            println!("Broadcast: {}", String::from_utf8_lossy(&event.content));

            if let Some(metadata) = event.metadata {
                println!("Content-Type: {}", metadata.get("content_type").unwrap_or(&"unknown".to_string()));
            }
        }

        _ => {}
    }
}).await?;
```

## Query/Response Pattern

For request/response communication with authority nodes.

### query_authority

Send query and wait for response.

```rust
impl Node {
    pub async fn query_authority(
        &self,
        authority: &PublicKey,
        query: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, Error>
}
```

**Blocks until**: Response received or timeout

**Example**:
```rust
let query = b"GET /latest_version";

let response = node.query_authority(
    &authority_pubkey,
    query,
    Duration::from_secs(30),
).await?;

let version = String::from_utf8(response)?;
println!("Latest version: {}", version);
```

**Error handling**:
```rust
match node.query_authority(&authority, query, timeout).await {
    Ok(response) => {
        // Process response
    }

    Err(Error::Timeout) => {
        println!("Authority did not respond in time");
    }

    Err(Error::AuthorityUnknown) => {
        println!("Authority not in trusted list");
    }

    Err(e) => {
        println!("Query failed: {}", e);
    }
}
```

### on_query_received

Handle incoming queries (authority nodes only).

```rust
node.on_query_received(|query_event: QueryEvent| async move {
    // Process query
    let response = match query_event.query_type.as_str() {
        "GET_VERSION" => get_current_version(),
        "GET_UPDATE" => get_update_package(),
        _ => b"Unknown query type".to_vec(),
    };

    // Send response
    node.respond_to_query(&query_event.query_id, response).await.unwrap();
}).await?;
```

## Message Priority

Control message delivery priority.

```rust
pub enum MessagePriority {
    Low,       // Background/bulk
    Normal,    // Default
    High,      // Important
    Critical,  // Time-sensitive
}
```

**Example**:
```rust
let options = SendOptions {
    priority: MessagePriority::High,
    ..Default::default()
};

node.send_private_message_with_options(&recipient, urgent_message, options).await?;
```

**Effects**:
- High/Critical messages sent before Low/Normal in queue
- Critical messages may bypass rate limiting
- Low priority may be throttled under load

## Message Batching

Send multiple messages efficiently.

```rust
impl Node {
    pub async fn send_batch(
        &self,
        messages: Vec<(PublicKey, Vec<u8>)>,
    ) -> Result<Vec<MessageId>, Error>
}
```

**Benefits**:
- Single signature for batch
- Reduced overhead
- Better throughput

**Example**:
```rust
let messages = vec![
    (alice_pubkey, b"Message to Alice".to_vec()),
    (bob_pubkey, b"Message to Bob".to_vec()),
    (charlie_pubkey, b"Message to Charlie".to_vec()),
];

let msg_ids = node.send_batch(messages).await?;
```

## Message Deduplication

Automatic deduplication prevents processing same message multiple times.

**How it works**:
1. Compute message ID (Blake3 hash)
2. Check Bloom filter
3. If seen before, discard
4. Otherwise, process and add to filter

**Configuration**:
```rust
let node = NodeBuilder::new()
    .with_bloom_filter_size(100_000)  // Expected messages
    .with_bloom_filter_fp_rate(0.01)  // 1% false positive
    .build()
    .await?;
```

**False positives**: ~1% of messages incorrectly marked as duplicates

**Time-to-live**: Bloom filter entries expire after 5 minutes

## Return Path

Private messages include encrypted return path for responses.

**Automatic**: Return path created automatically

**Usage**:
```rust
// Sender
let msg_id = node.send_private_message(&recipient, b"Question?").await?;

// Recipient receives message and replies
node.on_message_received(|event: MessageEvent| async move {
    if event.message_type == MessageType::PrivateMessage {
        // Reply uses return path automatically
        node.send_private_message(&event.sender, b"Answer!").await.unwrap();
    }
}).await?;
```

## Message Filtering

Filter messages before delivery to application.

```rust
impl Node {
    pub async fn add_message_filter<F>(&self, filter: F)
    where
        F: Fn(&MessageEvent) -> bool + Send + Sync + 'static,
}
```

**Example**:
```rust
// Only accept messages from known contacts
let contacts = vec![alice_pubkey, bob_pubkey];

node.add_message_filter(move |event| {
    contacts.contains(&event.sender)
}).await?;
```

## Rate Limiting

Prevent spam and resource exhaustion.

**Per-peer limits**:
```rust
let node = NodeBuilder::new()
    .enable_rate_limiting()
    .with_rate_limit(100, Duration::from_secs(60))  // 100 msg/min per peer
    .build()
    .await?;
```

**Behavior when exceeded**:
- Additional messages dropped
- Peer reputation decreased
- May lead to disconnection

## Content Types

Recommended MIME types for broadcasts:

```rust
// Text
"text/plain"
"text/markdown"

// Structured data
"application/json"
"application/xml"
"application/protobuf"

// Binary
"application/octet-stream"

// Media
"image/png"
"audio/mp3"
"video/mp4"

// Custom
"application/x-meshara-update"
```

**Example**:
```rust
let json_data = serde_json::to_vec(&my_struct)?;

node.broadcast_with_metadata(
    &json_data,
    "application/json",
    HashMap::new(),
).await?;
```

## Message Acknowledgments

Request delivery confirmation.

```rust
let options = SendOptions {
    delivery_confirmation: true,
    ..Default::default()
};

let msg_id = node.send_private_message_with_options(
    &recipient,
    message,
    options,
).await?;

// Wait for acknowledgment
node.on_message_acknowledged(move |ack: AckEvent| async move {
    if ack.message_id == msg_id {
        println!("Message delivered successfully!");
    }
}).await?;
```

## Compression

Automatic compression for large messages.

```rust
let node = NodeBuilder::new()
    .enable_compression()
    .with_compression_threshold(1024)  // Compress if > 1KB
    .build()
    .await?;
```

**Supported algorithms**:
- LZ4 (fast, low compression)
- Zstd (balanced)
- Brotli (high compression)

## Encryption Details

### Private Messages

**Algorithm**: X25519 + ChaCha20-Poly1305

**Process**:
1. Generate ephemeral X25519 keypair
2. Compute shared secret with recipient's public key
3. Derive encryption key with HKDF-SHA256
4. Encrypt with ChaCha20-Poly1305
5. Include ephemeral public key in message

**Security properties**:
- End-to-end encryption
- Forward secrecy
- Authenticated encryption (AEAD)
- Integrity protection

### Broadcast Messages

**Signed, not encrypted**

**Algorithm**: Ed25519 signature

**Process**:
1. Serialize message content
2. Sign with Ed25519 private key
3. Attach signature to message

**Recipients verify**:
1. Deserialize message
2. Verify Ed25519 signature
3. Check against sender's public key

## Performance Characteristics

| Operation | Latency | Throughput |
|-----------|---------|------------|
| Encrypt message | 0.1ms | 10,000/sec |
| Sign message | 0.05ms | 20,000/sec |
| Send (local network) | 50ms | 1,000/sec |
| Send (internet) | 200ms | 100/sec |
| Broadcast (100 nodes) | 2s | N/A |
| Batch send (10 msg) | 100ms | 100 msg/sec |

## Best Practices

1. **Always check `verified` flag** before trusting message content

2. **Handle errors gracefully** - network failures are common

3. **Use batching** for sending multiple messages

4. **Set appropriate timeouts** for queries

5. **Filter untrusted senders** to prevent spam

6. **Limit message size** - smaller messages route faster

7. **Use metadata** in broadcasts for structured data

8. **Monitor delivery confirmations** for critical messages

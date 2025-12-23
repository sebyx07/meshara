# Events API Reference

Meshara uses an event-driven architecture for asynchronous notification delivery. All message receipts, peer connections, and system events are delivered via callbacks.

## Event System Overview

**Key characteristics**:
- **Non-blocking**: Callbacks execute asynchronously
- **Concurrent**: Multiple callbacks can run in parallel
- **Order-preserving**: Events of same type delivered in order
- **Type-safe**: Strongly typed event structures

## Subscribing to Events

### on_message_received

Subscribe to incoming messages.

```rust
impl Node {
    pub async fn on_message_received<F>(&self, callback: F) -> Result<SubscriptionHandle, Error>
    where
        F: Fn(MessageEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
}
```

**Parameters**:
- `callback`: Async function receiving `MessageEvent`

**Returns**: `SubscriptionHandle` for unsubscribing

**Example**:
```rust
let handle = node.on_message_received(|event: MessageEvent| async move {
    if !event.verified {
        eprintln!("Warning: Unverified message from {}", event.sender.to_hex());
        return;
    }

    match event.message_type {
        MessageType::PrivateMessage => {
            println!("Private: {}", String::from_utf8_lossy(&event.content));
        }
        MessageType::Broadcast => {
            println!("Broadcast: {}", String::from_utf8_lossy(&event.content));
        }
        _ => {}
    }
}).await?;
```

**Multiple subscribers**:
```rust
// Each subscriber receives all messages
node.on_message_received(log_message).await?;
node.on_message_received(process_message).await?;
node.on_message_received(update_ui).await?;
```

### on_peer_connected

Subscribe to peer connection events.

```rust
impl Node {
    pub async fn on_peer_connected<F>(&self, callback: F) -> Result<SubscriptionHandle, Error>
    where
        F: Fn(PeerEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
}
```

**Example**:
```rust
node.on_peer_connected(|event: PeerEvent| async move {
    println!("✓ Peer connected: {} ({})", event.peer_id, event.address);
    println!("  Public key: {}", event.public_key.to_hex());
}).await?;
```

### on_peer_disconnected

Subscribe to peer disconnection events.

```rust
impl Node {
    pub async fn on_peer_disconnected<F>(&self, callback: F) -> Result<SubscriptionHandle, Error>
    where
        F: Fn(PeerEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
}
```

**Example**:
```rust
node.on_peer_disconnected(|event: PeerEvent| async move {
    println!("✗ Peer disconnected: {}", event.peer_id);

    if let Some(reason) = event.disconnect_reason {
        println!("  Reason: {}", reason);
    }
}).await?;
```

### on_update_available

Subscribe to software update notifications.

```rust
impl Node {
    pub async fn on_update_available<F>(&self, callback: F) -> Result<SubscriptionHandle, Error>
    where
        F: Fn(UpdateEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
}
```

**Example**:
```rust
node.on_update_available(|event: UpdateEvent| async move {
    if !event.verified {
        eprintln!("Warning: Update signature invalid!");
        return;
    }

    println!("Update available: v{}", event.version);
    println!("Changelog:\n{}", event.changelog);

    // Verify checksum
    let computed = blake3::hash(&event.package_data);
    if computed.as_bytes() == event.checksum.as_slice() {
        println!("✓ Checksum verified");

        // Optionally auto-apply
        if should_auto_update() {
            apply_update(&event.package_data).await;
        }
    }
}).await?;
```

### on_query_received

Subscribe to incoming queries (authority nodes only).

```rust
impl Node {
    pub async fn on_query_received<F>(&self, callback: F) -> Result<SubscriptionHandle, Error>
    where
        F: Fn(QueryEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
}
```

**Example**:
```rust
node.on_query_received(|event: QueryEvent| async move {
    let query = String::from_utf8_lossy(&event.query_data);

    let response = match query.as_ref() {
        "GET_VERSION" => get_current_version().as_bytes().to_vec(),
        "GET_PEERS" => serialize_peer_list(),
        _ => b"Unknown query".to_vec(),
    };

    node.respond_to_query(&event.query_id, response).await.unwrap();
}).await?;
```

### on_error

Subscribe to error events.

```rust
impl Node {
    pub async fn on_error<F>(&self, callback: F) -> Result<SubscriptionHandle, Error>
    where
        F: Fn(ErrorEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
}
```

**Example**:
```rust
node.on_error(|event: ErrorEvent| async move {
    eprintln!("Error: {} - {}", event.error_type, event.message);

    if event.is_critical {
        eprintln!("Critical error - manual intervention may be required");
    }

    if event.retryable {
        eprintln!("This operation can be retried");
    }
}).await?;
```

### on_network_status_changed

Subscribe to network health changes.

```rust
impl Node {
    pub async fn on_network_status_changed<F>(&self, callback: F) -> Result<SubscriptionHandle, Error>
    where
        F: Fn(NetworkStatusEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
}
```

**Example**:
```rust
node.on_network_status_changed(|event: NetworkStatusEvent| async move {
    match event.status {
        NetworkStatus::Connected => println!("✓ Network healthy"),
        NetworkStatus::Degraded => println!("⚠ Network degraded"),
        NetworkStatus::Disconnected => println!("✗ Network disconnected"),
    }

    println!("Peers: {}/{}", event.current_peers, event.target_peers);
}).await?;
```

## Event Structures

### MessageEvent

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
- `timestamp`: Unix timestamp in milliseconds
- `verified`: True if signature valid
- `message_type`: Type of message
- `metadata`: Optional metadata (broadcasts)

### PeerEvent

```rust
pub struct PeerEvent {
    pub peer_id: PeerId,
    pub public_key: PublicKey,
    pub address: SocketAddr,
    pub event_type: PeerEventType,
    pub disconnect_reason: Option<String>,
}

pub enum PeerEventType {
    Connected,
    Disconnected,
}
```

### UpdateEvent

```rust
pub struct UpdateEvent {
    pub version: String,
    pub package_data: Vec<u8>,
    pub changelog: String,
    pub checksum: Vec<u8>,
    pub required_version: String,
    pub verified: bool,
    pub authority_key: PublicKey,
}
```

**Fields**:
- `version`: Semantic version (e.g., "2.0.1")
- `package_data`: Binary update package
- `changelog`: Human-readable changes
- `checksum`: Blake3 checksum
- `required_version`: Minimum version for this update
- `verified`: True if authority signature valid
- `authority_key`: Authority that signed this update

### QueryEvent

```rust
pub struct QueryEvent {
    pub query_id: QueryId,
    pub query_type: String,
    pub query_data: Vec<u8>,
    pub sender: PublicKey,
    pub response_required: bool,
}
```

### ErrorEvent

```rust
pub struct ErrorEvent {
    pub error_type: ErrorType,
    pub message: String,
    pub context: Option<String>,
    pub is_critical: bool,
    pub retryable: bool,
    pub source_error: Option<Box<dyn std::error::Error + Send + Sync>>,
}

pub enum ErrorType {
    Network,
    Crypto,
    Storage,
    Protocol,
    Config,
    Routing,
    Authority,
}
```

### NetworkStatusEvent

```rust
pub struct NetworkStatusEvent {
    pub status: NetworkStatus,
    pub current_peers: usize,
    pub target_peers: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub latency_ms: Option<u64>,
}

pub enum NetworkStatus {
    Connected,    // Healthy network connectivity
    Degraded,     // Below target peers or high latency
    Disconnected, // No peers connected
}
```

## Unsubscribing

### SubscriptionHandle

Handle returned from subscription methods.

```rust
pub struct SubscriptionHandle { /* private */ }

impl SubscriptionHandle {
    pub async fn unsubscribe(self) -> Result<(), Error>
}
```

**Example**:
```rust
// Subscribe
let handle = node.on_message_received(|event| async move {
    // Handle message
}).await?;

// Later: unsubscribe
handle.unsubscribe().await?;
```

**Automatic unsubscribe**: Dropping handle does NOT unsubscribe. Must call `unsubscribe()` explicitly.

## Event Ordering

**Guarantees**:
- Events of same type delivered in order to same subscriber
- No ordering guarantee between different event types
- No ordering guarantee between different subscribers

**Example**:
```rust
// Messages arrive in order: A, B, C
// Subscriber receives: A, B, C (guaranteed)

// Two subscribers:
// Subscriber 1 might receive: A, B, C
// Subscriber 2 might receive: A, C, B (different order is possible)
```

## Concurrency

**Callbacks execute concurrently**:
```rust
node.on_message_received(|event| async move {
    // This might take 1 second
    process_message(&event.content).await;
}).await?;

// Multiple messages arriving simultaneously execute in parallel
```

**Thread safety**: All callbacks must be `Send + Sync + 'static`

## Error Handling in Callbacks

**Panics in callbacks**: Logged but don't crash the node

**Best practice**: Handle errors within callback

```rust
node.on_message_received(|event| async move {
    match process_message(&event.content).await {
        Ok(result) => {
            println!("Processed: {}", result);
        }
        Err(e) => {
            eprintln!("Failed to process message: {}", e);
            // Log, retry, or ignore
        }
    }
}).await?;
```

## Filtering Events

Filter events before callback execution.

```rust
impl Node {
    pub async fn add_event_filter<F>(&self, filter: F)
    where
        F: Fn(&MessageEvent) -> bool + Send + Sync + 'static,
}
```

**Example**:
```rust
// Only accept messages from known contacts
let contacts = vec![alice_key, bob_key, charlie_key];

node.add_event_filter(move |event| {
    contacts.contains(&event.sender)
}).await?;

// Messages from unknown senders never reach callbacks
```

## Event Statistics

Track event delivery statistics.

```rust
impl Node {
    pub fn get_event_stats(&self) -> EventStats
}

pub struct EventStats {
    pub messages_received: u64,
    pub messages_delivered: u64,
    pub messages_filtered: u64,
    pub callback_errors: u64,
    pub average_callback_duration: Duration,
}
```

**Example**:
```rust
let stats = node.get_event_stats();
println!("Messages delivered: {}", stats.messages_delivered);
println!("Average callback time: {:?}", stats.average_callback_duration);
```

## Advanced: Event Channels

For manual event handling, use channels instead of callbacks.

```rust
impl Node {
    pub async fn subscribe_channel<E>(&self) -> (EventSender<E>, EventReceiver<E>)
    where
        E: Event,
}
```

**Example**:
```rust
let (tx, mut rx) = node.subscribe_channel::<MessageEvent>().await;

tokio::spawn(async move {
    while let Some(event) = rx.recv().await {
        println!("Received: {}", event.message_id);
    }
});
```

**Use cases**:
- Integrating with existing async code
- Custom event buffering
- Rate limiting
- Metrics collection

## Event Batching

Batch events for efficiency.

```rust
impl Node {
    pub async fn subscribe_batched<F>(
        &self,
        batch_size: usize,
        batch_timeout: Duration,
        callback: F,
    ) -> Result<SubscriptionHandle, Error>
    where
        F: Fn(Vec<MessageEvent>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
}
```

**Example**:
```rust
// Process messages in batches of 10 or every 1 second
node.subscribe_batched(
    10,
    Duration::from_secs(1),
    |events: Vec<MessageEvent>| async move {
        process_batch(&events).await;
    }
).await?;
```

## Best Practices

1. **Keep callbacks fast** - Delegate heavy processing to background tasks

2. **Handle all errors** - Don't let panics escape callbacks

3. **Check `verified` flag** - Never trust unverified messages

4. **Use filters** - Reduce callback invocations for unwanted events

5. **Unsubscribe when done** - Prevent memory leaks

6. **Avoid blocking** - Use async operations only

7. **Log errors** - Track callback failures for debugging

**Good example**:
```rust
node.on_message_received(|event| async move {
    if !event.verified {
        return;  // Reject unverified
    }

    // Delegate to background task
    tokio::spawn(async move {
        match heavy_processing(&event.content).await {
            Ok(_) => {},
            Err(e) => eprintln!("Processing failed: {}", e),
        }
    });
}).await?;
```

**Bad example**:
```rust
node.on_message_received(|event| async move {
    // DON'T: Blocking operation
    std::thread::sleep(Duration::from_secs(10));

    // DON'T: Unhandled panic
    let data = serde_json::from_slice(&event.content).unwrap();

    // DON'T: Heavy computation blocking event loop
    for _ in 0..1_000_000 {
        compute_something();
    }
}).await?;
```

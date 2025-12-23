# Node API Reference

The `Node` is the main entry point for the Meshara library. It represents a single node instance in the network.

## Node Creation

### NodeBuilder

Use the builder pattern to create nodes:

```rust
pub struct NodeBuilder { /* private fields */ }

impl NodeBuilder {
    pub fn new() -> Self

    pub fn with_storage_path<P: AsRef<Path>>(self, path: P) -> Self

    pub fn with_listen_port(self, port: u16) -> Self

    pub fn with_bind_address(self, addr: SocketAddr) -> Self

    pub fn with_max_peers(self, max: usize) -> Self

    pub fn with_min_peers(self, min: usize) -> Self

    pub fn with_bootstrap_nodes(self, nodes: Vec<SocketAddr>) -> Self

    pub fn with_authority_keys(self, keys: Vec<PublicKey>) -> Self

    pub fn with_privacy_level(self, level: PrivacyLevel) -> Self

    pub fn with_network_profile(self, profile: NetworkProfile) -> Self

    pub fn enable_auto_discovery(self) -> Self

    pub fn enable_dht(self) -> Self

    pub fn enable_http2_framing(self) -> Self

    pub fn with_passphrase<S: Into<String>>(self, passphrase: S) -> Self

    pub async fn build(self) -> Result<Node, Error>
}
```

**Example**:
```rust
let node = NodeBuilder::new()
    .with_storage_path("./meshara_data")
    .with_listen_port(8443)
    .with_max_peers(100)
    .enable_auto_discovery()
    .build()
    .await?;
```

## Node Lifecycle

### start

Start the node and begin networking.

```rust
pub async fn start(&self) -> Result<(), Error>
```

**Behavior**:
- Begins listening for incoming connections
- Initiates peer discovery (if enabled)
- Connects to bootstrap nodes (if configured)
- Does NOT block

**Example**:
```rust
let node = NodeBuilder::new().build().await?;
node.start().await?;

// Node is now running in background
```

### stop

Gracefully shutdown the node.

```rust
pub async fn stop(&self) -> Result<(), Error>
```

**Behavior**:
- Closes all peer connections gracefully
- Flushes pending messages
- Syncs storage to disk
- Blocks until complete

**Example**:
```rust
// Shutdown on Ctrl+C
tokio::signal::ctrl_c().await?;
node.stop().await?;
```

### restart

Restart the node with updated configuration.

```rust
pub async fn restart(&self) -> Result<(), Error>
```

**Example**:
```rust
node.update_config(|config| {
    config.max_peers = 200;
}).await?;

node.restart().await?;
```

## Identity Methods

### public_key

Get the node's public signing key.

```rust
pub fn public_key(&self) -> &PublicKey
```

**Returns**: Ed25519 public key (32 bytes)

**Example**:
```rust
println!("My public key: {}", node.public_key().to_hex());
```

### node_id

Get the node's unique identifier.

```rust
pub fn node_id(&self) -> NodeId
```

**Returns**: Blake3 hash of public key

**Example**:
```rust
println!("My node ID: {}", node.node_id());
```

### get_fingerprint

Get human-readable fingerprint for verification.

```rust
pub fn get_fingerprint(&self) -> String
```

**Returns**: Formatted fingerprint (e.g., "AB:CD:EF:12:34...")

**Example**:
```rust
println!("Verify this fingerprint: {}", node.get_fingerprint());
```

### export_identity

Export identity for backup or transfer.

```rust
pub async fn export_identity(&self, passphrase: &str) -> Result<Vec<u8>, Error>
```

**Parameters**:
- `passphrase`: Password to encrypt the identity bundle

**Returns**: Encrypted identity bundle

**Security**: Bundle is encrypted with Argon2-derived key

**Example**:
```rust
let bundle = node.export_identity("strong-passphrase").await?;
std::fs::write("identity_backup.bin", bundle)?;
```

### import_identity

Import previously exported identity.

```rust
pub fn with_imported_identity(self, bundle: &[u8], passphrase: &str) -> Result<Self, Error>
```

**Called on NodeBuilder before build()**

**Example**:
```rust
let bundle = std::fs::read("identity_backup.bin")?;

let node = NodeBuilder::new()
    .with_imported_identity(&bundle, "strong-passphrase")?
    .build()
    .await?;
```

## Messaging Methods

### send_private_message

Send encrypted message to specific recipient.

```rust
pub async fn send_private_message(
    &self,
    recipient: &PublicKey,
    content: &[u8],
) -> Result<MessageId, Error>
```

**Parameters**:
- `recipient`: Recipient's public key
- `content`: Message content (max size: 16 MB)

**Returns**: Unique message ID

**Behavior**:
- Encrypts content with X25519 + ChaCha20-Poly1305
- Signs with Ed25519
- Routes to recipient (direct, bridge, or onion)
- Returns immediately (async delivery)

**Errors**:
- `Error::RecipientUnknown`: Cannot route to recipient
- `Error::MessageTooLarge`: Content exceeds size limit
- `Error::Network(...)`: Network failure

**Example**:
```rust
let msg_id = node.send_private_message(
    &bob_pubkey,
    b"Secret message",
).await?;

println!("Message sent: {}", msg_id);
```

### broadcast_message

Send signed public message to all peers.

```rust
pub async fn broadcast_message(
    &self,
    content: &[u8],
) -> Result<MessageId, Error>
```

**Parameters**:
- `content`: Public message content

**Returns**: Message ID

**Behavior**:
- Signs content (NOT encrypted)
- Propagates via gossip protocol
- Reaches all reachable nodes
- Best-effort delivery

**Example**:
```rust
let msg_id = node.broadcast_message(b"Public announcement").await?;
```

### query_authority

Send query to authority node and wait for response.

```rust
pub async fn query_authority(
    &self,
    authority: &PublicKey,
    query: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, Error>
```

**Parameters**:
- `authority`: Authority's public key
- `query`: Query data (encrypted)
- `timeout`: Maximum wait time

**Returns**: Response data

**Errors**:
- `Error::Timeout`: No response within timeout
- `Error::AuthorityUnknown`: Authority not in trusted list
- `Error::Network(...)`: Routing failure

**Example**:
```rust
let response = node.query_authority(
    &authority_key,
    b"GET /latest_version",
    Duration::from_secs(30),
).await?;
```

## Peer Management

### add_peer

Manually add peer connection.

```rust
pub async fn add_peer(
    &self,
    address: SocketAddr,
    public_key: Option<PublicKey>,
) -> Result<PeerId, Error>
```

**Parameters**:
- `address`: Peer's socket address
- `public_key`: Optional public key for pinning (recommended)

**Returns**: Peer ID

**Security**: If `public_key` provided, connection is authenticated. Without it, susceptible to MITM.

**Example**:
```rust
// With public key pinning (secure)
let peer_id = node.add_peer(
    "192.168.1.100:8443".parse()?,
    Some(peer_pubkey),
).await?;

// Without pinning (less secure)
let peer_id = node.add_peer(
    "192.168.1.100:8443".parse()?,
    None,
).await?;
```

### remove_peer

Disconnect from peer.

```rust
pub async fn remove_peer(&self, peer_id: &PeerId) -> Result<(), Error>
```

**Example**:
```rust
node.remove_peer(&peer_id).await?;
```

### list_peers

Get list of connected peers.

```rust
pub async fn list_peers(&self) -> Result<Vec<PeerInfo>, Error>
```

**Returns**: Vector of peer information

**Example**:
```rust
let peers = node.list_peers().await?;
for peer in peers {
    println!("{} - {} - {}", peer.peer_id, peer.address, peer.connected_since);
}
```

### PeerInfo

Information about a connected peer.

```rust
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub public_key: PublicKey,
    pub address: SocketAddr,
    pub connected_since: SystemTime,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub latency_ms: u64,
    pub is_bridge: bool,
    pub reputation_score: f64,
}
```

## Authority Methods

### add_authority

Add trusted authority.

```rust
pub async fn add_authority(
    &self,
    public_key: PublicKey,
    identifier: String,
    trust_level: TrustLevel,
) -> Result<(), Error>
```

**Parameters**:
- `public_key`: Authority's public key
- `identifier`: Human-readable name
- `trust_level`: What this authority can do

**Example**:
```rust
node.add_authority(
    authority_pubkey,
    "Official Developer".to_string(),
    TrustLevel::UpdateAuthority,
).await?;
```

### TrustLevel

```rust
pub enum TrustLevel {
    UpdateAuthority,      // Can publish software updates
    SigningAuthority,     // Can sign messages
    BootstrapAuthority,   // Trusted for peer lists
}
```

### publish_update

Publish signed update package (authority nodes only).

```rust
pub async fn publish_update(
    &self,
    version: &str,
    package_data: Vec<u8>,
    changelog: &str,
) -> Result<MessageId, Error>
```

**Requires**: Node configured as authority

**Example**:
```rust
let update_data = std::fs::read("update_v2.0.0.bin")?;

authority_node.publish_update(
    "2.0.0",
    update_data,
    "Bug fixes and performance improvements",
).await?;
```

### respond_to_query

Respond to query (authority nodes only).

```rust
pub async fn respond_to_query(
    &self,
    query_id: &QueryId,
    response: Vec<u8>,
) -> Result<(), Error>
```

**Called from query event handler**

**Example**:
```rust
node.on_query_received(|query_event| async move {
    let response = process_query(&query_event.query_data);

    node.respond_to_query(&query_event.query_id, response).await?;
});
```

## Configuration Methods

### update_config

Update runtime configuration.

```rust
pub async fn update_config<F>(&self, f: F) -> Result<(), Error>
where
    F: FnOnce(&mut Config),
```

**Example**:
```rust
node.update_config(|config| {
    config.max_peers = 200;
    config.min_peers = 50;
}).await?;
```

### set_privacy_level

Change privacy level at runtime.

```rust
pub async fn set_privacy_level(&self, level: PrivacyLevel) -> Result<(), Error>
```

**Example**:
```rust
node.set_privacy_level(PrivacyLevel::Maximum).await?;
```

## Diagnostics Methods

### get_network_stats

Get network statistics.

```rust
pub fn get_network_stats(&self) -> NetworkStats
```

**Returns**:
```rust
pub struct NetworkStats {
    pub connected_peers: usize,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub average_latency: Duration,
    pub uptime: Duration,
}
```

**Example**:
```rust
let stats = node.get_network_stats();
println!("Connected peers: {}", stats.connected_peers);
println!("Messages sent: {}", stats.messages_sent);
println!("Uptime: {:?}", stats.uptime);
```

### run_diagnostics

Run comprehensive diagnostics.

```rust
pub async fn run_diagnostics(&self) -> Result<DiagnosticReport, Error>
```

**Returns**:
```rust
pub struct DiagnosticReport {
    pub connectivity_ok: bool,
    pub can_reach_bootstrap: bool,
    pub can_reach_authority: bool,
    pub nat_traversal_working: bool,
    pub signature_verification_ok: bool,
    pub storage_ok: bool,
    pub identified_issues: Vec<Issue>,
}
```

**Example**:
```rust
let report = node.run_diagnostics().await?;

if !report.connectivity_ok {
    println!("Warning: Connectivity issues detected");
}

for issue in report.identified_issues {
    println!("Issue: {} - {}", issue.severity, issue.description);
}
```

## Event Subscription

See [events.md](events.md) for detailed event API.

**Quick reference**:
```rust
node.on_message_received(callback).await?;
node.on_peer_connected(callback).await?;
node.on_peer_disconnected(callback).await?;
node.on_update_available(callback).await?;
node.on_query_received(callback).await?;
node.on_error(callback).await?;
```

## Type Aliases

```rust
pub type MessageId = [u8; 32];  // Blake3 hash
pub type NodeId = [u8; 32];     // Blake3 hash of public key
pub type PeerId = NodeId;
```

## Privacy Levels

```rust
pub enum PrivacyLevel {
    /// Direct/bridge routing (fastest, some metadata leakage)
    Standard,

    /// Onion routing when available (better privacy, moderate latency)
    Enhanced,

    /// Always onion routing (best privacy, highest latency)
    Maximum,
}
```

## Network Profiles

```rust
pub enum NetworkProfile {
    /// IoT/embedded (5 peers, minimal features)
    Minimal,

    /// Standard client (50 peers, balanced)
    Standard,

    /// Bridge node (500 peers, high connectivity)
    Bridge,

    /// Authority node (200 peers, stable identity)
    Authority,
}
```

## Thread Safety

All `Node` methods are thread-safe. The `Node` struct implements `Clone` (creates handle to same underlying node).

```rust
let node = NodeBuilder::new().build().await?;

let node_clone = node.clone();

// Use from different tasks
tokio::spawn(async move {
    node_clone.send_private_message(&recipient, b"msg").await.unwrap();
});
```

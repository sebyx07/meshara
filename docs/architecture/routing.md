# Routing Architecture

Meshara's routing layer determines how messages travel through the network from sender to recipient. The design balances efficiency, privacy, and resilience.

## Routing Modes

### Direct Routing

**When**: Sender and recipient are directly connected peers.

**How**:
1. Check connection pool for existing connection to recipient
2. Send message directly over TLS connection
3. Lowest latency, most efficient

**Implementation**:
```rust
pub async fn route_direct(
    &self,
    recipient: &PublicKey,
    message: Vec<u8>,
) -> Result<(), RoutingError> {
    // Check connection pool
    if let Some(conn) = self.connection_pool.get(recipient).await {
        // Send directly
        conn.send(message).await?;
        Ok(())
    } else {
        Err(RoutingError::NoDirectConnection)
    }
}
```

**Characteristics**:
- Single hop
- ~50ms latency (local network)
- Recipient knows sender's IP address
- Most efficient for known peers

### Bridge Routing

**When**: Recipient not directly connected, route through intermediate peers.

**How**:
1. Query DHT for recipient's location
2. Find path through connected peers
3. Forward message hop-by-hop
4. Each hop verifies signature, forwards to next

**Implementation**:
```rust
pub async fn route_via_bridge(
    &self,
    recipient: &PublicKey,
    message: Vec<u8>,
) -> Result<(), RoutingError> {
    // Query DHT for recipient
    let location_info = self.dht.find_node(recipient).await?;

    // Find bridge peer that knows recipient
    let bridge_peer = location_info.closest_known_peer;

    // Forward to bridge
    let forwarding_msg = ForwardingMessage {
        final_recipient: recipient.to_bytes().to_vec(),
        original_message: message,
        hop_count: 1,
        max_hops: MAX_HOPS,
    };

    self.send_to_peer(&bridge_peer, forwarding_msg.encode_to_vec()).await?;

    Ok(())
}

pub async fn handle_forwarding_message(
    &self,
    msg: ForwardingMessage,
) -> Result<(), RoutingError> {
    // Check hop count
    if msg.hop_count >= msg.max_hops {
        return Err(RoutingError::MaxHopsExceeded);
    }

    // Parse final recipient
    let recipient = PublicKey::from_bytes(&msg.final_recipient)?;

    // If we're connected to recipient, deliver directly
    if self.connection_pool.has(&recipient).await {
        self.route_direct(&recipient, msg.original_message).await?;
    } else {
        // Forward to next hop
        let next_hop = self.find_next_hop(&recipient).await?;

        let forwarding_msg = ForwardingMessage {
            hop_count: msg.hop_count + 1,
            ..msg
        };

        self.send_to_peer(&next_hop, forwarding_msg.encode_to_vec()).await?;
    }

    Ok(())
}
```

**Characteristics**:
- Multi-hop (typically 2-4 hops)
- Higher latency (~200ms per hop)
- Intermediate nodes see message is being forwarded
- Used when direct connection unavailable

### Onion Routing (Optional Feature)

**When**: Maximum privacy required. Enabled via `onion-routing` feature flag.

**How**:
1. Select random path through 3+ nodes
2. Encrypt message in layers (onion)
3. Each hop decrypts one layer, forwards to next
4. Final recipient decrypts last layer

**Layered Encryption**:
```rust
pub async fn route_onion(
    &self,
    recipient: &PublicKey,
    plaintext: Vec<u8>,
) -> Result<(), RoutingError> {
    // Select random path: Entry -> Middle -> Exit -> Recipient
    let path = self.select_onion_path(recipient, 3).await?;

    // Build onion layers from inside out
    let mut onion = plaintext;

    // Layer 3: Exit -> Recipient (final delivery)
    let exit_node = &path[2];
    onion = self.create_onion_layer(
        exit_node,
        OnionLayerData {
            next_hop: recipient.clone(),
            payload: onion,
            is_final: true,
        }
    )?;

    // Layer 2: Middle -> Exit
    let middle_node = &path[1];
    onion = self.create_onion_layer(
        middle_node,
        OnionLayerData {
            next_hop: exit_node.public_key.clone(),
            payload: onion,
            is_final: false,
        }
    )?;

    // Layer 1: Entry -> Middle
    let entry_node = &path[0];
    onion = self.create_onion_layer(
        entry_node,
        OnionLayerData {
            next_hop: middle_node.public_key.clone(),
            payload: onion,
            is_final: false,
        }
    )?;

    // Send to entry node
    self.send_to_peer(&entry_node.public_key, onion).await?;

    Ok(())
}

fn create_onion_layer(
    &self,
    hop: &PeerInfo,
    data: OnionLayerData,
) -> Result<Vec<u8>, CryptoError> {
    // Perform key exchange with this hop
    let ephemeral_secret = EphemeralSecret::random();
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared_secret = ephemeral_secret.diffie_hellman(&hop.encryption_key);

    // Derive encryption key
    let encryption_key = derive_key(&shared_secret, b"onion-layer");

    // Serialize layer data
    let serialized = OnionLayer {
        next_hop: data.next_hop.to_bytes().to_vec(),
        payload: data.payload,
        is_final: data.is_final,
    }.encode_to_vec();

    // Encrypt
    let cipher = ChaCha20Poly1305::new(&encryption_key);
    let nonce = generate_nonce();
    let encrypted = cipher.encrypt(&nonce.into(), serialized.as_ref())?;

    // Package with ephemeral public key
    Ok(OnionPacket {
        ephemeral_public_key: ephemeral_public.to_bytes().to_vec(),
        nonce: nonce.to_vec(),
        encrypted_data: encrypted,
    }.encode_to_vec())
}
```

**Processing Onion Layer**:
```rust
pub async fn process_onion_packet(
    &self,
    packet_bytes: &[u8],
) -> Result<(), RoutingError> {
    // Parse onion packet
    let packet = OnionPacket::decode(packet_bytes)?;

    // Extract ephemeral public key
    let ephemeral_public = PublicKey::from_bytes(&packet.ephemeral_public_key)?;

    // Perform key exchange with our static key
    let shared_secret = self.identity.encryption_key.diffie_hellman(&ephemeral_public);

    // Derive decryption key
    let decryption_key = derive_key(&shared_secret, b"onion-layer");

    // Decrypt layer
    let cipher = ChaCha20Poly1305::new(&decryption_key);
    let nonce = <[u8; 12]>::try_from(packet.nonce.as_slice())?;
    let decrypted = cipher.decrypt(&nonce.into(), packet.encrypted_data.as_ref())?;

    // Parse layer
    let layer = OnionLayer::decode(decrypted.as_ref())?;

    if layer.is_final {
        // We are exit node - deliver to final recipient
        let recipient = PublicKey::from_bytes(&layer.next_hop)?;
        self.route_direct(&recipient, layer.payload).await?;
    } else {
        // Forward to next hop
        let next_hop = PublicKey::from_bytes(&layer.next_hop)?;
        self.send_to_peer(&next_hop, layer.payload).await?;
    }

    Ok(())
}
```

**Path Selection**:
```rust
async fn select_onion_path(
    &self,
    recipient: &PublicKey,
    path_length: usize,
) -> Result<Vec<PeerInfo>, RoutingError> {
    let mut path = Vec::with_capacity(path_length);

    // Get list of suitable relay nodes
    let relays = self.get_relay_nodes().await?;

    // Select random nodes for path
    for _ in 0..path_length {
        // Choose node not already in path
        let node = relays.iter()
            .filter(|n| !path.contains(n))
            .choose(&mut rand::thread_rng())
            .ok_or(RoutingError::InsufficientRelays)?;

        path.push(node.clone());
    }

    Ok(path)
}
```

**Characteristics**:
- 3+ hops (configurable)
- High latency (~150ms per hop, 450ms+ total)
- Each hop only knows previous and next hop
- Sender anonymous to recipient
- Recipient anonymous to sender
- Network observers can't trace route
- Higher bandwidth overhead

### Gossip Protocol (Broadcasts)

**When**: Broadcasting to all nodes (updates, announcements).

**How**:
1. Send to all connected peers
2. Each peer deduplicates and rebroadcasts
3. Flood network with exponential propagation
4. Bloom filter prevents infinite loops

**Implementation**:
```rust
pub struct GossipManager {
    seen_messages: BloomFilter,
    fanout: usize,  // How many peers to forward to
}

impl GossipManager {
    pub async fn broadcast_message(
        &mut self,
        message: Vec<u8>,
    ) -> Result<(), RoutingError> {
        // Compute message ID
        let message_id = blake3::hash(&message);

        // Add to seen set
        self.seen_messages.insert(&message_id);

        // Get connected peers
        let peers = self.connection_pool.list_peers().await;

        // Send to all peers (or random subset if many peers)
        let targets = if peers.len() <= self.fanout {
            peers
        } else {
            peers.into_iter()
                .choose_multiple(&mut rand::thread_rng(), self.fanout)
        };

        // Send to each target
        for peer in targets {
            let _ = self.send_to_peer(&peer, message.clone()).await;
            // Ignore errors - best effort delivery
        }

        Ok(())
    }

    pub async fn handle_broadcast_message(
        &mut self,
        message: Vec<u8>,
    ) -> Result<(), RoutingError> {
        // Compute message ID
        let message_id = blake3::hash(&message);

        // Check if already seen
        if self.seen_messages.contains(&message_id) {
            // Already processed, ignore
            return Ok(());
        }

        // Add to seen set
        self.seen_messages.insert(&message_id);

        // Process message locally
        self.deliver_locally(&message).await?;

        // Rebroadcast to peers
        let peers = self.connection_pool.list_peers().await;
        let targets = peers.into_iter()
            .choose_multiple(&mut rand::thread_rng(), self.fanout);

        for peer in targets {
            let _ = self.send_to_peer(&peer, message.clone()).await;
        }

        Ok(())
    }
}
```

**Deduplication with Bloom Filter**:
```rust
use bloom::{BloomFilter, ASMS};

pub struct MessageDeduplication {
    // Bloom filter for fast membership test
    bloom: BloomFilter,

    // Exact set for recent messages (TTL-based)
    recent_messages: HashMap<MessageId, Instant>,

    // Configuration
    expected_messages: usize,
    false_positive_rate: f64,
}

impl MessageDeduplication {
    pub fn new() -> Self {
        Self {
            bloom: BloomFilter::with_rate(0.01, 100_000),
            recent_messages: HashMap::new(),
            expected_messages: 100_000,
            false_positive_rate: 0.01,
        }
    }

    pub fn insert(&mut self, message_id: &MessageId) {
        self.bloom.insert(&message_id.as_bytes());
        self.recent_messages.insert(*message_id, Instant::now());

        // Cleanup old entries
        let cutoff = Instant::now() - Duration::from_secs(300);  // 5 min TTL
        self.recent_messages.retain(|_, timestamp| *timestamp > cutoff);
    }

    pub fn contains(&self, message_id: &MessageId) -> bool {
        // Fast check with Bloom filter
        if !self.bloom.contains(&message_id.as_bytes()) {
            return false;  // Definitely not seen
        }

        // Bloom filter says maybe - check exact set
        self.recent_messages.contains_key(message_id)
    }
}
```

**Characteristics**:
- Exponential propagation (100 nodes in ~2 seconds)
- Eventual consistency (all reachable nodes receive)
- No delivery guarantees (best effort)
- Bloom filter: low memory, ~1% false positive rate
- Suitable for: updates, announcements, discovery

## Routing Tables

### DHT (Distributed Hash Table)

Kademlia-style DHT for peer discovery.

**Structure**:
```rust
pub struct DhtNode {
    // Our node ID (hash of public key)
    node_id: NodeId,

    // K-buckets (160 buckets, k=20 nodes each)
    routing_table: Vec<KBucket>,

    // Pending queries
    pending_queries: HashMap<QueryId, PendingQuery>,
}

pub struct KBucket {
    // Distance from our node ID (XOR metric)
    bucket_index: usize,

    // Up to k nodes in this bucket
    nodes: Vec<PeerInfo>,

    // Least-recently-seen node position
    lru_position: usize,
}

impl DhtNode {
    // Find node closest to target ID
    pub async fn find_node(&self, target: &NodeId) -> Result<Vec<PeerInfo>, DhtError> {
        let mut queried = HashSet::new();
        let mut closest = self.find_closest_local(target, ALPHA);

        loop {
            // Pick ALPHA unqueried nodes
            let to_query: Vec<_> = closest.iter()
                .filter(|n| !queried.contains(&n.node_id))
                .take(ALPHA)
                .cloned()
                .collect();

            if to_query.is_empty() {
                break;  // No more nodes to query
            }

            // Query in parallel
            let mut tasks = vec![];
            for peer in &to_query {
                queried.insert(peer.node_id);
                tasks.push(self.query_peer(peer, target));
            }

            let results = futures::future::join_all(tasks).await;

            // Merge results
            for result in results {
                if let Ok(nodes) = result {
                    closest.extend(nodes);
                }
            }

            // Keep K closest
            closest.sort_by_key(|n| xor_distance(&n.node_id, target));
            closest.truncate(K);
        }

        Ok(closest)
    }

    fn find_closest_local(&self, target: &NodeId, count: usize) -> Vec<PeerInfo> {
        let mut candidates = Vec::new();

        // Collect from all buckets
        for bucket in &self.routing_table {
            candidates.extend(bucket.nodes.iter().cloned());
        }

        // Sort by distance to target
        candidates.sort_by_key(|n| xor_distance(&n.node_id, target));

        // Return closest K
        candidates.into_iter().take(count).collect()
    }
}

fn xor_distance(a: &NodeId, b: &NodeId) -> NodeId {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a.0[i] ^ b.0[i];
    }
    NodeId(result)
}
```

**DHT Operations**:
```rust
// FIND_NODE query
pub async fn query_find_node(
    &self,
    peer: &PeerInfo,
    target: &NodeId,
) -> Result<Vec<PeerInfo>, DhtError> {
    let query = QueryMessage {
        query_id: generate_query_id(),
        query_type: "FIND_NODE".to_string(),
        query_data: target.as_bytes().to_vec(),
        response_required: true,
    };

    let response = self.send_query(peer, query).await?;

    // Parse response
    let nodes: Vec<PeerInfo> = decode_peer_list(&response.response_data)?;

    Ok(nodes)
}

// STORE value in DHT
pub async fn store_value(
    &self,
    key: &NodeId,
    value: Vec<u8>,
) -> Result<(), DhtError> {
    // Find K closest nodes to key
    let closest = self.find_node(key).await?;

    // Store on all K nodes
    for node in closest {
        let store_msg = StoreMessage {
            key: key.as_bytes().to_vec(),
            value: value.clone(),
            ttl: 3600,  // 1 hour
        };

        let _ = self.send_store(&node, store_msg).await;
        // Best effort - ignore errors
    }

    Ok(())
}

// GET value from DHT
pub async fn get_value(&self, key: &NodeId) -> Result<Vec<u8>, DhtError> {
    // Find nodes closest to key
    let closest = self.find_node(key).await?;

    // Query each until we get value
    for node in closest {
        if let Ok(value) = self.query_get(&node, key).await {
            return Ok(value);
        }
    }

    Err(DhtError::ValueNotFound)
}
```

**Characteristics**:
- O(log N) lookup time (N = network size)
- Decentralized (no central authority)
- Self-healing (routes around failures)
- K=20 redundancy per key
- Typical lookup: 3-5 hops

### Route Caching

Cache successful routes to avoid repeated lookups.

```rust
pub struct RouteCache {
    // Maps recipient -> (route, timestamp)
    cache: HashMap<PublicKey, (Route, Instant)>,

    // TTL for cached routes
    ttl: Duration,
}

impl RouteCache {
    pub fn insert(&mut self, recipient: PublicKey, route: Route) {
        self.cache.insert(recipient, (route, Instant::now()));
    }

    pub fn get(&mut self, recipient: &PublicKey) -> Option<Route> {
        if let Some((route, timestamp)) = self.cache.get(recipient) {
            // Check if expired
            if timestamp.elapsed() < self.ttl {
                return Some(route.clone());
            } else {
                // Remove expired entry
                self.cache.remove(recipient);
            }
        }

        None
    }

    // Cleanup expired entries
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.cache.retain(|_, (_, timestamp)| {
            now.duration_since(*timestamp) < self.ttl
        });
    }
}
```

## Routing Strategy Selection

**Decision Logic**:
```rust
pub async fn route_message(
    &self,
    recipient: &PublicKey,
    message: Vec<u8>,
    privacy_level: PrivacyLevel,
) -> Result<(), RoutingError> {
    match privacy_level {
        PrivacyLevel::Standard => {
            // Try direct first
            if self.route_direct(recipient, message.clone()).await.is_ok() {
                return Ok(());
            }

            // Fall back to bridge routing
            self.route_via_bridge(recipient, message).await
        }

        PrivacyLevel::Enhanced => {
            // Try onion routing if available
            #[cfg(feature = "onion-routing")]
            {
                self.route_onion(recipient, message).await
            }

            #[cfg(not(feature = "onion-routing"))]
            {
                // Fall back to bridge routing
                self.route_via_bridge(recipient, message).await
            }
        }

        PrivacyLevel::Maximum => {
            // Always use onion routing
            #[cfg(feature = "onion-routing")]
            {
                self.route_onion(recipient, message).await
            }

            #[cfg(not(feature = "onion-routing"))]
            {
                Err(RoutingError::OnionRoutingNotAvailable)
            }
        }
    }
}
```

## Performance Characteristics

**Direct Routing**:
- Latency: 50-100ms (local) to 200ms (intercontinental)
- Throughput: Limited by TLS connection (~100 MB/sec)
- Reliability: >99% (direct TCP connection)

**Bridge Routing**:
- Latency: 200-500ms (2-3 hops)
- Throughput: Limited by slowest hop
- Reliability: ~95% (depends on intermediate nodes)

**Onion Routing**:
- Latency: 500-1000ms (3+ hops)
- Throughput: ~10 MB/sec (encryption overhead)
- Reliability: ~90% (more hops = more failure points)

**Gossip Broadcast**:
- Propagation: 100 nodes in ~2 seconds
- Reliability: >99% for reachable nodes
- Overhead: O(N) messages for N nodes

**DHT Lookup**:
- Latency: 300-800ms (3-5 hops)
- Success rate: >95%
- Load: O(log N) messages per lookup

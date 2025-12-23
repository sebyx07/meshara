# Testing Guide

Comprehensive testing strategies for applications built with Meshara.

## Unit Testing Basics

### Testing Message Encryption

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use meshara::crypto::{Identity, CryptoHandler};

    #[tokio::test]
    async fn test_message_encryption_decryption() {
        // Generate two identities
        let alice = Identity::generate();
        let bob = Identity::generate();

        let crypto = CryptoHandler::new();

        // Alice encrypts message for Bob
        let plaintext = b"Secret message";
        let encrypted = crypto.encrypt_for_recipient(
            &bob.public_encryption_key(),
            plaintext,
        ).await.unwrap();

        // Bob decrypts message
        let decrypted = crypto.decrypt_with_key(
            &bob.encryption_key,
            &encrypted,
        ).await.unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_signature_verification() {
        let identity = Identity::generate();

        let message = b"Test message";
        let signature = identity.sign(message);

        // Valid signature should verify
        assert!(identity.verify(message, &signature).is_ok());

        // Modified message should fail
        let modified = b"Different message";
        assert!(identity.verify(modified, &signature).is_err());

        // Tampered signature should fail
        let mut bad_signature = signature.clone();
        bad_signature.0[0] ^= 1;  // Flip one bit
        assert!(identity.verify(message, &bad_signature).is_err());
    }
}
```

### Testing Protocol Serialization

```rust
#[test]
fn test_protobuf_roundtrip() {
    use meshara::protocol::{BaseMessage, MessageType};
    use prost::Message;

    let original = BaseMessage {
        version: 1,
        message_id: vec![0x7f; 32],
        message_type: MessageType::PrivateMessage as i32,
        timestamp: 1234567890,
        sender_public_key: vec![0xaa; 32],
        payload: vec![0xbb; 100],
        signature: vec![0xcc; 64],
        routing_info: None,
    };

    // Serialize
    let bytes = original.encode_to_vec();

    // Deserialize
    let decoded = BaseMessage::decode(bytes.as_ref()).unwrap();

    assert_eq!(original.version, decoded.version);
    assert_eq!(original.message_id, decoded.message_id);
    assert_eq!(original.message_type, decoded.message_type);
    assert_eq!(original.payload, decoded.payload);
}
```

## Integration Testing

### Mock Network Setup

Meshara provides utilities for creating in-process test networks:

```rust
use meshara::testing::{MockNetwork, MockNode};

#[tokio::test]
async fn test_message_delivery() {
    // Create mock network with 3 nodes
    let mut network = MockNetwork::new();

    let alice = network.create_node("alice").await.unwrap();
    let bob = network.create_node("bob").await.unwrap();
    let charlie = network.create_node("charlie").await.unwrap();

    // Connect nodes in a line: Alice -> Bob -> Charlie
    network.connect(alice.id(), bob.id()).await.unwrap();
    network.connect(bob.id(), charlie.id()).await.unwrap();

    // Setup message receiver
    let (tx, mut rx) = tokio::sync::mpsc::channel(10);
    charlie.on_message_received(move |event| {
        let tx = tx.clone();
        async move {
            tx.send(event).await.unwrap();
        }
    }).await.unwrap();

    // Alice sends message to Charlie (routed through Bob)
    let message = b"Test message";
    alice.send_private_message(&charlie.public_key(), message)
        .await
        .unwrap();

    // Wait for delivery
    let received = tokio::time::timeout(
        Duration::from_secs(5),
        rx.recv()
    ).await.unwrap().unwrap();

    assert_eq!(received.content, message);
    assert_eq!(received.sender, alice.public_key());
    assert!(received.verified);
}
```

### Network Conditions Simulation

Test behavior under adverse conditions:

```rust
#[tokio::test]
async fn test_message_delivery_with_packet_loss() {
    let mut network = MockNetwork::new();

    // Configure 10% packet loss
    network.set_packet_loss(0.1);

    // Configure 100ms latency
    network.set_latency(Duration::from_millis(100));

    let alice = network.create_node("alice").await.unwrap();
    let bob = network.create_node("bob").await.unwrap();
    network.connect(alice.id(), bob.id()).await.unwrap();

    // Send multiple messages
    let mut sent = Vec::new();
    for i in 0..100 {
        let msg = format!("Message {}", i);
        sent.push(msg.clone());

        alice.send_private_message(&bob.public_key(), msg.as_bytes())
            .await
            .unwrap();
    }

    // Collect received messages
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    bob.on_message_received(move |event| {
        let tx = tx.clone();
        async move {
            tx.send(event).await.unwrap();
        }
    }).await.unwrap();

    // Wait for deliveries
    tokio::time::sleep(Duration::from_secs(5)).await;

    let mut received = Vec::new();
    while let Ok(event) = rx.try_recv() {
        received.push(String::from_utf8(event.content).unwrap());
    }

    // With 10% packet loss, should receive 85-95 out of 100
    assert!(received.len() >= 85);
    assert!(received.len() <= 100);
}
```

### Network Partition Testing

```rust
#[tokio::test]
async fn test_network_partition_recovery() {
    let mut network = MockNetwork::new();

    let alice = network.create_node("alice").await.unwrap();
    let bob = network.create_node("bob").await.unwrap();

    network.connect(alice.id(), bob.id()).await.unwrap();

    // Verify connectivity
    alice.send_private_message(&bob.public_key(), b"ping")
        .await
        .unwrap();

    // Simulate network partition
    network.partition(vec![alice.id()], vec![bob.id()]);

    // Messages should fail to deliver
    let result = alice.send_private_message(&bob.public_key(), b"partitioned")
        .await;

    assert!(matches!(result, Err(Error::Network(_))));

    // Heal partition
    network.heal_partition();
    network.connect(alice.id(), bob.id()).await.unwrap();

    // Messages should deliver again
    alice.send_private_message(&bob.public_key(), b"healed")
        .await
        .unwrap();
}
```

## Testing Gossip Protocol

### Broadcast Propagation

```rust
#[tokio::test]
async fn test_broadcast_propagation() {
    let mut network = MockNetwork::new();

    // Create 10 nodes
    let nodes: Vec<_> = (0..10)
        .map(|i| network.create_node(&format!("node_{}", i)))
        .collect::<futures::stream::FuturesOrdered<_>>()
        .collect::<Result<Vec<_>, _>>()
        .await
        .unwrap();

    // Connect nodes in a mesh
    for i in 0..nodes.len() {
        for j in (i + 1)..nodes.len() {
            network.connect(nodes[i].id(), nodes[j].id()).await.unwrap();
        }
    }

    // Setup receivers on all nodes except sender
    let mut receivers = Vec::new();
    for node in &nodes[1..] {
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        node.on_message_received(move |event| {
            let tx = tx.clone();
            async move {
                if event.message_type == MessageType::Broadcast {
                    tx.send(event).await.unwrap();
                }
            }
        }).await.unwrap();
        receivers.push(rx);
    }

    // Node 0 broadcasts message
    let broadcast_content = b"Broadcast message";
    nodes[0].broadcast_message(broadcast_content)
        .await
        .unwrap();

    // Wait for propagation
    tokio::time::sleep(Duration::from_secs(2)).await;

    // All other nodes should receive broadcast
    for mut rx in receivers {
        let received = rx.try_recv().unwrap();
        assert_eq!(received.content, broadcast_content);
        assert_eq!(received.sender, nodes[0].public_key());
    }
}
```

### Deduplication Testing

```rust
#[tokio::test]
async fn test_broadcast_deduplication() {
    use meshara::routing::MessageDeduplication;

    let mut dedup = MessageDeduplication::new();

    let msg_id = MessageId::generate();

    // First insert should succeed
    assert!(!dedup.contains(&msg_id));
    dedup.insert(&msg_id);
    assert!(dedup.contains(&msg_id));

    // Duplicate should be detected
    assert!(dedup.contains(&msg_id));

    // Different message should not be detected
    let other_msg_id = MessageId::generate();
    assert!(!dedup.contains(&other_msg_id));
}
```

## Testing Routing

### DHT Lookup

```rust
#[tokio::test]
async fn test_dht_node_lookup() {
    let mut network = MockNetwork::new();

    // Create 20 nodes for DHT
    let nodes: Vec<_> = (0..20)
        .map(|i| network.create_node(&format!("dht_node_{}", i)))
        .collect::<futures::stream::FuturesOrdered<_>>()
        .collect::<Result<Vec<_>, _>>()
        .await
        .unwrap();

    // Bootstrap DHT - each node knows a few others
    for i in 0..nodes.len() {
        let next = (i + 1) % nodes.len();
        let skip = (i + nodes.len() / 2) % nodes.len();

        network.connect(nodes[i].id(), nodes[next].id()).await.unwrap();
        network.connect(nodes[i].id(), nodes[skip].id()).await.unwrap();
    }

    // Wait for DHT to stabilize
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Node 0 looks up Node 15 (not directly connected)
    let target = nodes[15].public_key();
    let lookup_result = nodes[0].find_node(&target).await.unwrap();

    // Should find the node
    assert!(lookup_result.iter().any(|p| p.public_key == target));
}
```

### Onion Routing

```rust
#[cfg(feature = "onion-routing")]
#[tokio::test]
async fn test_onion_routing() {
    let mut network = MockNetwork::new();

    // Create 5 nodes for onion path
    let nodes: Vec<_> = (0..5)
        .map(|i| network.create_node(&format!("onion_node_{}", i)))
        .collect::<futures::stream::FuturesOrdered<_>>()
        .collect::<Result<Vec<_>, _>>()
        .await
        .unwrap();

    // Connect in a line
    for i in 0..(nodes.len() - 1) {
        network.connect(nodes[i].id(), nodes[i + 1].id()).await.unwrap();
    }

    // Setup receiver
    let (tx, mut rx) = tokio::sync::mpsc::channel(10);
    nodes[4].on_message_received(move |event| {
        let tx = tx.clone();
        async move {
            tx.send(event).await.unwrap();
        }
    }).await.unwrap();

    // Node 0 sends to Node 4 via onion routing
    let message = b"Onion routed message";
    nodes[0].send_private_message_with_options(
        &nodes[4].public_key(),
        message,
        SendOptions {
            privacy_level: PrivacyLevel::Maximum,
            ..Default::default()
        }
    ).await.unwrap();

    // Message should arrive
    let received = tokio::time::timeout(
        Duration::from_secs(10),
        rx.recv()
    ).await.unwrap().unwrap();

    assert_eq!(received.content, message);

    // Intermediate nodes should not know content
    // (This is verified by the fact that decryption works only at final node)
}
```

## Testing Authority System

### Update Distribution

```rust
#[tokio::test]
async fn test_update_distribution() {
    let mut network = MockNetwork::new();

    // Create authority node
    let authority = network.create_authority_node("authority").await.unwrap();

    // Create client nodes
    let clients: Vec<_> = (0..5)
        .map(|i| {
            let mut builder = network.node_builder(&format!("client_{}", i));
            builder.with_authority_keys(vec![authority.public_key()]);
            builder.build()
        })
        .collect::<futures::stream::FuturesOrdered<_>>()
        .collect::<Result<Vec<_>, _>>()
        .await
        .unwrap();

    // Connect clients to authority
    for client in &clients {
        network.connect(client.id(), authority.id()).await.unwrap();
    }

    // Setup update receivers
    let mut receivers = Vec::new();
    for client in &clients {
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        client.on_update_available(move |event| {
            let tx = tx.clone();
            async move {
                tx.send(event).await.unwrap();
            }
        }).await.unwrap();
        receivers.push(rx);
    }

    // Authority publishes update
    let update_data = b"Update package v2.0.0";
    authority.publish_update(
        "2.0.0",
        update_data.to_vec(),
        "New features: bug fixes",
    ).await.unwrap();

    // Wait for propagation
    tokio::time::sleep(Duration::from_secs(3)).await;

    // All clients should receive update
    for mut rx in receivers {
        let update_event = rx.try_recv().unwrap();

        assert_eq!(update_event.version, "2.0.0");
        assert_eq!(update_event.package_data, update_data);
        assert!(update_event.verified);  // Signature verified
    }
}
```

### Signature Verification

```rust
#[tokio::test]
async fn test_authority_signature_verification() {
    let authority = Identity::generate();
    let impostor = Identity::generate();

    // Create update signed by authority
    let update = UpdatePackage {
        version: "1.0.0".to_string(),
        package_data: b"legitimate update".to_vec(),
        changelog: "Bug fixes".to_string(),
        checksum: blake3::hash(b"legitimate update").as_bytes().to_vec(),
        required_version: "0.9.0".to_string(),
        signatures: vec![authority.sign(&b"update").to_bytes().to_vec()],
    };

    // Verification should succeed with authority key
    assert!(verify_update_signature(&update, &authority.public_signing_key()).is_ok());

    // Verification should fail with impostor key
    assert!(verify_update_signature(&update, &impostor.public_signing_key()).is_err());
}
```

## Performance Testing

### Throughput Benchmarks

```rust
#[tokio::test]
async fn benchmark_message_throughput() {
    let mut network = MockNetwork::new();

    let alice = network.create_node("alice").await.unwrap();
    let bob = network.create_node("bob").await.unwrap();

    network.connect(alice.id(), bob.id()).await.unwrap();

    // Send 1000 messages
    let start = std::time::Instant::now();
    let mut tasks = vec![];

    for i in 0..1000 {
        let msg = format!("Message {}", i);
        let task = alice.send_private_message(&bob.public_key(), msg.as_bytes());
        tasks.push(task);
    }

    futures::future::join_all(tasks).await;

    let elapsed = start.elapsed();

    println!("Sent 1000 messages in {:?}", elapsed);
    println!("Throughput: {} msg/sec", 1000.0 / elapsed.as_secs_f64());

    // Typical: 500-2000 msg/sec depending on hardware
}
```

### Latency Measurements

```rust
#[tokio::test]
async fn measure_message_latency() {
    let mut network = MockNetwork::new();
    network.set_latency(Duration::from_millis(50));

    let alice = network.create_node("alice").await.unwrap();
    let bob = network.create_node("bob").await.unwrap();
    network.connect(alice.id(), bob.id()).await.unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::channel(10);
    bob.on_message_received(move |event| {
        let tx = tx.clone();
        async move {
            tx.send(std::time::Instant::now()).await.unwrap();
        }
    }).await.unwrap();

    // Measure round-trip time
    let send_time = std::time::Instant::now();
    alice.send_private_message(&bob.public_key(), b"ping").await.unwrap();

    let receive_time = rx.recv().await.unwrap();
    let latency = receive_time.duration_since(send_time);

    println!("Message latency: {:?}", latency);

    // Should be approximately network latency + processing time
    assert!(latency >= Duration::from_millis(50));
    assert!(latency < Duration::from_millis(200));
}
```

## Property-Based Testing

Using `proptest` for randomized testing:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_encryption_always_decrypts(
        plaintext in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        let runtime = tokio::runtime::Runtime::new().unwrap();

        runtime.block_on(async {
            let alice = Identity::generate();
            let bob = Identity::generate();
            let crypto = CryptoHandler::new();

            let encrypted = crypto.encrypt_for_recipient(
                &bob.public_encryption_key(),
                &plaintext,
            ).await.unwrap();

            let decrypted = crypto.decrypt_with_key(
                &bob.encryption_key,
                &encrypted,
            ).await.unwrap();

            assert_eq!(plaintext, decrypted);
        });
    }

    #[test]
    fn test_signature_always_verifies(
        message in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        let identity = Identity::generate();
        let signature = identity.sign(&message);

        assert!(identity.verify(&message, &signature).is_ok());
    }
}
```

## Test Utilities

### Deterministic Key Generation

For reproducible tests:

```rust
#[cfg(feature = "dev-mode")]
#[test]
fn test_with_deterministic_keys() {
    use meshara::testing::DeterministicRng;

    // Same seed produces same keys
    let mut rng1 = DeterministicRng::from_seed(42);
    let identity1 = Identity::generate_with_rng(&mut rng1);

    let mut rng2 = DeterministicRng::from_seed(42);
    let identity2 = Identity::generate_with_rng(&mut rng2);

    assert_eq!(
        identity1.public_signing_key().to_bytes(),
        identity2.public_signing_key().to_bytes()
    );
}
```

### Mock Time

Control time for testing timeouts:

```rust
#[tokio::test]
async fn test_query_timeout() {
    let mut network = MockNetwork::new();
    let mut time = MockTime::new();

    let alice = network.create_node("alice").await.unwrap();
    let bob = network.create_node("bob").await.unwrap();

    // Bob doesn't respond to queries

    // Query with 5-second timeout
    let query_future = alice.query_peer(
        &bob.public_key(),
        b"query",
        Duration::from_secs(5),
    );

    // Advance time by 6 seconds
    time.advance(Duration::from_secs(6)).await;

    // Query should timeout
    let result = query_future.await;
    assert!(matches!(result, Err(Error::Timeout)));
}
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      - name: Run tests
        run: cargo test --all-features

      - name: Run integration tests
        run: cargo test --test integration_tests

      - name: Run benchmarks
        run: cargo bench --no-run

      - name: Check formatting
        run: cargo fmt -- --check

      - name: Run clippy
        run: cargo clippy -- -D warnings
```

## Best Practices

1. **Use MockNetwork for integration tests** - Faster and more reliable than real networking

2. **Test error paths** - Verify behavior under network failures, invalid inputs, etc.

3. **Property-based testing** - Use proptest for cryptographic functions

4. **Deterministic tests** - Use fixed seeds for reproducibility

5. **Measure performance** - Set benchmarks to detect regressions

6. **Test security properties** - Verify signatures, encryption, authentication

7. **Test edge cases** - Empty messages, maximum size, malformed data

8. **Concurrent testing** - Test with multiple nodes and concurrent operations

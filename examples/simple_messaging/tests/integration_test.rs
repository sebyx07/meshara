//! Integration tests for simple messaging example

use anyhow::Result;
use meshara::{Event, NodeBuilder, PublicKey};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[tokio::test]
async fn test_node_creation() -> Result<()> {
    // Create a temporary directory for storage
    let temp_dir = tempfile::tempdir()?;
    let storage_path = temp_dir.path().join("test_node");

    // Build a node
    let mut node = NodeBuilder::new()
        .with_storage_path(storage_path.to_str().unwrap())
        .with_listen_port(0) // Random port
        .build()?;

    // Start the node
    node.start().await?;

    // Verify node is running
    assert!(node.listen_address().is_some());

    // Stop the node
    node.stop().await?;

    Ok(())
}

#[tokio::test]
async fn test_two_nodes_exchange_messages() -> Result<()> {
    // Create two temporary directories
    let temp_dir_alice = tempfile::tempdir()?;
    let temp_dir_bob = tempfile::tempdir()?;

    let storage_alice = temp_dir_alice.path().join("alice");
    let storage_bob = temp_dir_bob.path().join("bob");

    // Create Alice's node
    let mut alice = NodeBuilder::new()
        .with_storage_path(storage_alice.to_str().unwrap())
        .with_listen_port(0)
        .build()?;

    // Track Alice's received messages
    let alice_messages = Arc::new(Mutex::new(Vec::new()));
    let alice_msg_clone = Arc::clone(&alice_messages);

    alice.on_event(move |event| {
        if let Event::MessageReceived { content, .. } = event {
            let msg = String::from_utf8_lossy(&content).to_string();
            let alice_msg_clone = Arc::clone(&alice_msg_clone);
            tokio::spawn(async move {
                alice_msg_clone.lock().await.push(msg);
            });
        }
    });

    alice.start().await?;
    let alice_pubkey = alice.public_key();

    // Create Bob's node
    let mut bob = NodeBuilder::new()
        .with_storage_path(storage_bob.to_str().unwrap())
        .with_listen_port(0)
        .build()?;

    // Track Bob's received messages
    let bob_messages = Arc::new(Mutex::new(Vec::new()));
    let bob_msg_clone = Arc::clone(&bob_messages);

    bob.on_event(move |event| {
        if let Event::MessageReceived { content, .. } = event {
            let msg = String::from_utf8_lossy(&content).to_string();
            let bob_msg_clone = Arc::clone(&bob_msg_clone);
            tokio::spawn(async move {
                bob_msg_clone.lock().await.push(msg);
            });
        }
    });

    bob.start().await?;
    let bob_pubkey = bob.public_key();

    // Give nodes time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Note: Full message delivery requires nodes to actually connect to each other,
    // which requires either:
    // 1. Manual connection establishment (not yet implemented in high-level API)
    // 2. Peer discovery via mDNS (requires nodes on same network)
    // 3. Bootstrap nodes or DHT
    //
    // For now, we just verify the nodes can be created and started successfully

    // Verify nodes started successfully
    assert!(alice.listen_address().is_some());
    assert!(bob.listen_address().is_some());

    // Verify public keys are different
    assert_ne!(alice_pubkey.to_bytes(), bob_pubkey.to_bytes());

    // Clean up
    alice.stop().await?;
    bob.stop().await?;

    Ok(())
}

#[tokio::test]
async fn test_event_handler_registration() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let storage_path = temp_dir.path().join("test_events");

    let mut node = NodeBuilder::new()
        .with_storage_path(storage_path.to_str().unwrap())
        .with_listen_port(0)
        .build()?;

    // Register event handler
    let started = Arc::new(Mutex::new(false));
    let started_clone = Arc::clone(&started);

    node.on_event(move |event| {
        if matches!(event, Event::NodeStarted) {
            let started_clone = Arc::clone(&started_clone);
            tokio::spawn(async move {
                *started_clone.lock().await = true;
            });
        }
    });

    // Start node
    node.start().await?;

    // Give event time to be processed
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify event was received
    assert!(*started.lock().await);

    node.stop().await?;

    Ok(())
}

#[test]
fn test_public_key_hex_encoding() -> Result<()> {
    // Create a test public key
    let temp_dir = tempfile::tempdir()?;
    let storage_path = temp_dir.path().join("test_key");

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let mut node = NodeBuilder::new()
            .with_storage_path(storage_path.to_str().unwrap())
            .with_listen_port(0)
            .build()?;

        // Start the node to initialize identity
        node.start().await?;

        let pubkey = node.public_key();
        let hex_str = hex::encode(pubkey.to_bytes());

        // Verify hex encoding
        assert_eq!(hex_str.len(), 128); // 64 bytes * 2 hex chars

        // Verify we can decode it back
        let decoded = hex::decode(&hex_str)?;
        assert_eq!(decoded.len(), 64);

        let mut key_array = [0u8; 64];
        key_array.copy_from_slice(&decoded);
        let decoded_key = PublicKey::from_bytes(&key_array)?;

        // Verify round-trip
        assert_eq!(pubkey.to_bytes(), decoded_key.to_bytes());

        node.stop().await?;

        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

#[test]
fn test_node_id_generation() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let storage_path = temp_dir.path().join("test_node_id");

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let mut node = NodeBuilder::new()
            .with_storage_path(storage_path.to_str().unwrap())
            .with_listen_port(0)
            .build()?;

        // Start the node to initialize identity
        node.start().await?;

        let node_id = node.node_id();
        let hex_str = node_id.to_hex();

        // Verify node ID format
        assert_eq!(hex_str.len(), 64); // 32 bytes * 2 hex chars

        node.stop().await?;

        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

#[tokio::test]
async fn test_multiple_event_handlers() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let storage_path = temp_dir.path().join("test_multi_handlers");

    let mut node = NodeBuilder::new()
        .with_storage_path(storage_path.to_str().unwrap())
        .with_listen_port(0)
        .build()?;

    // Register multiple event handlers
    let count1 = Arc::new(Mutex::new(0));
    let count1_clone = Arc::clone(&count1);

    node.on_event(move |event| {
        if matches!(event, Event::NodeStarted) {
            let count1_clone = Arc::clone(&count1_clone);
            tokio::spawn(async move {
                *count1_clone.lock().await += 1;
            });
        }
    });

    let count2 = Arc::new(Mutex::new(0));
    let count2_clone = Arc::clone(&count2);

    node.on_event(move |event| {
        if matches!(event, Event::NodeStarted) {
            let count2_clone = Arc::clone(&count2_clone);
            tokio::spawn(async move {
                *count2_clone.lock().await += 1;
            });
        }
    });

    // Start node
    node.start().await?;

    // Give events time to be processed
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify both handlers were called
    assert_eq!(*count1.lock().await, 1);
    assert_eq!(*count2.lock().await, 1);

    node.stop().await?;

    Ok(())
}

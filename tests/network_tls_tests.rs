//! Integration tests for TLS networking
//!
//! These tests verify that TLS connections, message framing, and
//! connection pooling work correctly in realistic scenarios.

use meshara::crypto::{hash_message, Identity, NodeId};
use meshara::network::{Connection, ConnectionPool, TlsConfig, TlsListener};
use meshara::protocol::{BaseMessage, MessageType};
use std::net::SocketAddr;
use tokio::time::{timeout, Duration};

/// Helper function to create a test message
fn create_test_message(content: &[u8]) -> BaseMessage {
    let identity = Identity::generate();
    let public_key = identity.public_key();

    // Create message content
    let message_id = hash_message(content);

    BaseMessage {
        version: 1,
        message_id: message_id.as_bytes().to_vec(),
        message_type: MessageType::PrivateMessage as i32,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        sender_public_key: public_key.to_bytes(),
        payload: content.to_vec(),
        signature: vec![0u8; 64], // Dummy signature for testing
        routing_info: None,
    }
}

#[tokio::test]
async fn test_tls_connection_establishment() {
    // Create identities for server and client
    let server_identity = Identity::generate();
    let client_identity = Identity::generate();

    // Create TLS configs
    let server_tls = TlsConfig::from_identity(&server_identity).unwrap();
    let client_tls = TlsConfig::from_identity(&client_identity).unwrap();

    // Start server
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TlsListener::bind(server_addr, server_tls.server_config())
        .await
        .unwrap();
    let bound_addr = listener.local_addr().unwrap();

    // Spawn server task
    let server_task = tokio::spawn(async move {
        // Accept one connection
        let (tls_stream, peer_addr) = listener.accept().await.unwrap();
        Connection::accept(tls_stream, peer_addr)
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Connect client
    let client_conn = Connection::connect(bound_addr, client_tls.client_config())
        .await
        .unwrap();

    // Wait for server to accept
    let server_conn = server_task.await.unwrap();

    // Verify connections are established
    assert_eq!(
        client_conn.state().await,
        meshara::network::ConnectionState::Connected
    );
    assert_eq!(
        server_conn.state().await,
        meshara::network::ConnectionState::Connected
    );

    // Close connections
    client_conn.close().await.unwrap();
    server_conn.close().await.unwrap();
}

#[tokio::test]
async fn test_send_receive_message() {
    // Create identities
    let server_identity = Identity::generate();
    let client_identity = Identity::generate();

    // Create TLS configs
    let server_tls = TlsConfig::from_identity(&server_identity).unwrap();
    let client_tls = TlsConfig::from_identity(&client_identity).unwrap();

    // Start server
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TlsListener::bind(server_addr, server_tls.server_config())
        .await
        .unwrap();
    let bound_addr = listener.local_addr().unwrap();

    // Create test message
    let test_message = create_test_message(b"Hello, TLS!");

    // Clone for verification
    let expected_message_id = test_message.message_id.clone();

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let (tls_stream, peer_addr) = listener.accept().await.unwrap();
        let server_conn = Connection::accept(tls_stream, peer_addr);

        // Receive message
        let received = server_conn.receive_message().await.unwrap();
        server_conn.close().await.unwrap();
        received
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Connect client and send message
    let client_conn = Connection::connect(bound_addr, client_tls.client_config())
        .await
        .unwrap();

    client_conn.send_message(&test_message).await.unwrap();

    // Wait for server to receive
    let received_message = timeout(Duration::from_secs(5), server_task)
        .await
        .expect("Server task timed out")
        .unwrap();

    // Verify message was received correctly
    assert_eq!(received_message.message_id, expected_message_id);
    assert_eq!(received_message.payload, b"Hello, TLS!");

    // Close client connection
    client_conn.close().await.unwrap();
}

#[tokio::test]
async fn test_bidirectional_communication() {
    // Create identities
    let server_identity = Identity::generate();
    let client_identity = Identity::generate();

    // Create TLS configs
    let server_tls = TlsConfig::from_identity(&server_identity).unwrap();
    let client_tls = TlsConfig::from_identity(&client_identity).unwrap();

    // Start server
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TlsListener::bind(server_addr, server_tls.server_config())
        .await
        .unwrap();
    let bound_addr = listener.local_addr().unwrap();

    // Create test messages
    let client_message = create_test_message(b"Client -> Server");
    let server_message = create_test_message(b"Server -> Client");

    let expected_client_payload = client_message.payload.clone();
    let expected_server_payload = server_message.payload.clone();

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let (tls_stream, peer_addr) = listener.accept().await.unwrap();
        let server_conn = Connection::accept(tls_stream, peer_addr);

        // Receive from client
        let received_from_client = server_conn.receive_message().await.unwrap();

        // Send to client
        server_conn.send_message(&server_message).await.unwrap();

        server_conn.close().await.unwrap();
        received_from_client
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Connect client
    let client_conn = Connection::connect(bound_addr, client_tls.client_config())
        .await
        .unwrap();

    // Send to server
    client_conn.send_message(&client_message).await.unwrap();

    // Receive from server
    let received_from_server = client_conn.receive_message().await.unwrap();

    // Wait for server task
    let received_from_client = timeout(Duration::from_secs(5), server_task)
        .await
        .expect("Server task timed out")
        .unwrap();

    // Verify bidirectional communication
    assert_eq!(received_from_client.payload, expected_client_payload);
    assert_eq!(received_from_server.payload, expected_server_payload);

    // Close client connection
    client_conn.close().await.unwrap();
}

#[tokio::test]
async fn test_connection_pool() {
    // Create client identity and config
    let client_identity = Identity::generate();
    let client_tls = TlsConfig::from_identity(&client_identity).unwrap();

    // Create connection pool
    let pool = ConnectionPool::new(10);

    // Create multiple server endpoints
    let mut server_tasks = Vec::new();
    let mut bound_addrs = Vec::new();

    for _ in 0..3 {
        let server_identity = Identity::generate();
        let server_tls = TlsConfig::from_identity(&server_identity).unwrap();

        let listener =
            TlsListener::bind("127.0.0.1:0".parse().unwrap(), server_tls.server_config())
                .await
                .unwrap();
        let bound_addr = listener.local_addr().unwrap();
        bound_addrs.push(bound_addr);

        let task = tokio::spawn(async move {
            let (tls_stream, peer_addr) = listener.accept().await.unwrap();
            Connection::accept(tls_stream, peer_addr)
        });
        server_tasks.push(task);
    }

    // Give servers time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect to all servers using pool
    let mut peer_ids = Vec::new();
    for addr in &bound_addrs {
        // Create a unique peer ID for each connection
        let peer_id = NodeId::from_bytes([peer_ids.len() as u8; 32]);
        peer_ids.push(peer_id);

        let conn = pool
            .get_or_connect(&peer_id, *addr, client_tls.client_config())
            .await
            .unwrap();

        assert_eq!(
            conn.state().await,
            meshara::network::ConnectionState::Connected
        );
    }

    // Verify pool size
    assert_eq!(pool.len(), 3);

    // Test getting existing connection
    let first_peer_id = &peer_ids[0];
    let existing_conn = pool.get(first_peer_id).unwrap();
    assert_eq!(
        existing_conn.state().await,
        meshara::network::ConnectionState::Connected
    );

    // Get peer IDs from pool
    let pool_peer_ids = pool.peer_ids();
    assert_eq!(pool_peer_ids.len(), 3);

    // Close all connections
    pool.close_all().await;
    assert_eq!(pool.len(), 0);

    // Wait for server tasks to complete
    for task in server_tasks {
        let _ = timeout(Duration::from_secs(5), task).await;
    }
}

#[tokio::test]
async fn test_multiple_messages() {
    // Create identities
    let server_identity = Identity::generate();
    let client_identity = Identity::generate();

    // Create TLS configs
    let server_tls = TlsConfig::from_identity(&server_identity).unwrap();
    let client_tls = TlsConfig::from_identity(&client_identity).unwrap();

    // Start server
    let listener = TlsListener::bind("127.0.0.1:0".parse().unwrap(), server_tls.server_config())
        .await
        .unwrap();
    let bound_addr = listener.local_addr().unwrap();

    const MESSAGE_COUNT: usize = 10;

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let (tls_stream, peer_addr) = listener.accept().await.unwrap();
        let server_conn = Connection::accept(tls_stream, peer_addr);

        let mut received_count = 0;
        for _ in 0..MESSAGE_COUNT {
            let _ = server_conn.receive_message().await.unwrap();
            received_count += 1;
        }

        server_conn.close().await.unwrap();
        received_count
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Connect client
    let client_conn = Connection::connect(bound_addr, client_tls.client_config())
        .await
        .unwrap();

    // Send multiple messages
    for i in 0..MESSAGE_COUNT {
        let content = format!("Message {}", i);
        let message = create_test_message(content.as_bytes());
        client_conn.send_message(&message).await.unwrap();
    }

    // Wait for server
    let received_count = timeout(Duration::from_secs(5), server_task)
        .await
        .expect("Server task timed out")
        .unwrap();

    assert_eq!(received_count, MESSAGE_COUNT);

    // Close client connection
    client_conn.close().await.unwrap();
}

#[tokio::test]
async fn test_large_message() {
    // Create identities
    let server_identity = Identity::generate();
    let client_identity = Identity::generate();

    // Create TLS configs
    let server_tls = TlsConfig::from_identity(&server_identity).unwrap();
    let client_tls = TlsConfig::from_identity(&client_identity).unwrap();

    // Start server
    let listener = TlsListener::bind("127.0.0.1:0".parse().unwrap(), server_tls.server_config())
        .await
        .unwrap();
    let bound_addr = listener.local_addr().unwrap();

    // Create a large message (1 MB)
    let large_content = vec![42u8; 1024 * 1024];
    let large_message = create_test_message(&large_content);

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let (tls_stream, peer_addr) = listener.accept().await.unwrap();
        let server_conn = Connection::accept(tls_stream, peer_addr);

        let received = server_conn.receive_message().await.unwrap();
        server_conn.close().await.unwrap();
        received.payload.len()
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Connect and send
    let client_conn = Connection::connect(bound_addr, client_tls.client_config())
        .await
        .unwrap();

    client_conn.send_message(&large_message).await.unwrap();

    // Verify size
    let received_size = timeout(Duration::from_secs(10), server_task)
        .await
        .expect("Server task timed out")
        .unwrap();

    assert_eq!(received_size, 1024 * 1024);

    // Close
    client_conn.close().await.unwrap();
}

//! Connection management and message framing
//!
//! This module provides TCP connections with TLS 1.3 encryption,
//! length-prefixed message framing, and connection pooling.

use crate::crypto::{NodeId, PublicKey};
use crate::error::{NetworkError, Result};
use crate::network::MAX_MESSAGE_SIZE;
use crate::protocol::{deserialize_message, serialize_message, BaseMessage};
use dashmap::DashMap;
use rustls::ClientConfig;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::TlsConnector;

/// State of a connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection is being established
    Connecting,
    /// Connection is active and can send/receive
    Connected,
    /// Connection is in the process of closing
    Closing,
    /// Connection is closed
    Closed,
}

/// A TLS connection to a peer
pub struct Connection {
    /// ID of the connected peer
    peer_id: NodeId,
    /// Public key of the peer (for verification)
    peer_public_key: Option<PublicKey>,
    /// TLS stream (either client or server)
    stream: ConnectionStream,
    /// Current connection state
    state: Mutex<ConnectionState>,
    /// When this connection was created
    created_at: Instant,
    /// Total bytes sent over this connection
    bytes_sent: AtomicU64,
    /// Total bytes received over this connection
    bytes_received: AtomicU64,
    /// Remote peer address
    peer_addr: SocketAddr,
}

/// Wrapper for TLS stream (client or server)
enum ConnectionStream {
    Client(Mutex<ClientTlsStream<TcpStream>>),
    Server(Mutex<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl Connection {
    /// Connect to a peer as a client
    ///
    /// Establishes TCP connection and performs TLS handshake.
    ///
    /// # Arguments
    ///
    /// * `address` - Socket address of the peer
    /// * `tls_config` - Client TLS configuration
    ///
    /// # Example
    ///
    /// ```no_run
    /// use meshara::crypto::Identity;
    /// use meshara::network::{TlsConfig, Connection};
    /// use std::net::SocketAddr;
    ///
    /// # async fn example() -> meshara::error::Result<()> {
    /// let identity = Identity::generate();
    /// let tls_config = TlsConfig::from_identity(&identity)?;
    /// let addr: SocketAddr = "127.0.0.1:8443".parse().unwrap();
    ///
    /// let conn = Connection::connect(addr, tls_config.client_config()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(address: SocketAddr, tls_config: Arc<ClientConfig>) -> Result<Self> {
        // Connect TCP
        let tcp_stream =
            TcpStream::connect(address)
                .await
                .map_err(|e| NetworkError::ConnectionFailed {
                    address: address.to_string(),
                    reason: format!("TCP connection failed: {}", e),
                })?;

        let peer_addr = tcp_stream
            .peer_addr()
            .map_err(|e| NetworkError::ConnectionFailed {
                address: address.to_string(),
                reason: format!("Failed to get peer address: {}", e),
            })?;

        // Perform TLS handshake
        let connector = TlsConnector::from(tls_config);
        let domain = rustls::pki_types::ServerName::try_from("meshara-node").map_err(|e| {
            NetworkError::TlsHandshakeFailed {
                reason: format!("Invalid server name: {}", e),
            }
        })?;

        let tls_stream = connector.connect(domain, tcp_stream).await.map_err(|e| {
            NetworkError::TlsHandshakeFailed {
                reason: format!("TLS handshake failed: {}", e),
            }
        })?;

        // TODO: Extract peer's public key from certificate and verify
        // For now, we'll set it to None and verify later via message signatures

        // Create temporary node ID (will be replaced with actual ID from certificate)
        let peer_id = NodeId::from_bytes([0u8; 32]);

        Ok(Self {
            peer_id,
            peer_public_key: None,
            stream: ConnectionStream::Client(Mutex::new(tls_stream)),
            state: Mutex::new(ConnectionState::Connected),
            created_at: Instant::now(),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            peer_addr,
        })
    }

    /// Accept an incoming connection from a peer
    ///
    /// Called by TlsListener after TLS handshake is complete.
    ///
    /// # Arguments
    ///
    /// * `tls_stream` - TLS stream from accepted connection
    /// * `peer_addr` - Remote peer address
    pub fn accept(
        tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
        peer_addr: SocketAddr,
    ) -> Self {
        // TODO: Extract peer's public key from certificate and verify
        // For now, we'll set it to None and verify later via message signatures

        // Create temporary node ID (will be replaced with actual ID from certificate)
        let peer_id = NodeId::from_bytes([0u8; 32]);

        Self {
            peer_id,
            peer_public_key: None,
            stream: ConnectionStream::Server(Mutex::new(tls_stream)),
            state: Mutex::new(ConnectionState::Connected),
            created_at: Instant::now(),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            peer_addr,
        }
    }

    /// Send a message to the peer
    ///
    /// Messages are framed with a 4-byte length prefix (big-endian).
    ///
    /// # Arguments
    ///
    /// * `message` - The message to send
    ///
    /// # Example
    ///
    /// ```no_run
    /// use meshara::protocol::BaseMessage;
    /// # use meshara::network::Connection;
    ///
    /// # async fn example(mut conn: Connection, msg: BaseMessage) -> meshara::error::Result<()> {
    /// conn.send_message(&msg).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_message(&self, message: &BaseMessage) -> Result<()> {
        // Check connection state
        {
            let state = self.state.lock().await;
            if *state != ConnectionState::Connected {
                return Err(NetworkError::ConnectionClosed {
                    peer_id: format!("{:?}", self.peer_id),
                }
                .into());
            }
        }

        // Serialize message
        let bytes = serialize_message(message).map_err(|e| NetworkError::SendFailed {
            reason: format!("Serialization failed: {}", e),
        })?;

        // Check size limit
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(NetworkError::MessageTooLarge { size: bytes.len() }.into());
        }

        // Send with framing
        match &self.stream {
            ConnectionStream::Client(stream) => {
                let mut stream = stream.lock().await;
                send_framed_message(&mut *stream, &bytes).await?;
            },
            ConnectionStream::Server(stream) => {
                let mut stream = stream.lock().await;
                send_framed_message(&mut *stream, &bytes).await?;
            },
        }

        // Update stats
        self.bytes_sent
            .fetch_add((bytes.len() + 4) as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Receive a message from the peer
    ///
    /// Reads a length-prefixed message from the stream.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use meshara::network::Connection;
    ///
    /// # async fn example(mut conn: Connection) -> meshara::error::Result<()> {
    /// let message = conn.receive_message().await?;
    /// println!("Received message: {:?}", message);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn receive_message(&self) -> Result<BaseMessage> {
        // Check connection state
        {
            let state = self.state.lock().await;
            if *state != ConnectionState::Connected {
                return Err(NetworkError::ConnectionClosed {
                    peer_id: format!("{:?}", self.peer_id),
                }
                .into());
            }
        }

        // Receive with framing
        let bytes = match &self.stream {
            ConnectionStream::Client(stream) => {
                let mut guard = stream.lock().await;
                receive_framed_message(&mut *guard).await?
            },
            ConnectionStream::Server(stream) => {
                let mut guard = stream.lock().await;
                receive_framed_message(&mut *guard).await?
            },
        };

        // Update stats
        self.bytes_received
            .fetch_add((bytes.len() + 4) as u64, Ordering::Relaxed);

        // Deserialize message
        deserialize_message(&bytes).map_err(|e| {
            NetworkError::ReceiveFailed {
                reason: format!("Deserialization failed: {}", e),
            }
            .into()
        })
    }

    /// Close the connection gracefully
    pub async fn close(&self) -> Result<()> {
        // Update state
        {
            let mut state = self.state.lock().await;
            *state = ConnectionState::Closing;
        }

        // Shutdown TLS stream
        match &self.stream {
            ConnectionStream::Client(stream) => {
                let mut stream = stream.lock().await;
                let _ = stream.shutdown().await; // Ignore errors during shutdown
            },
            ConnectionStream::Server(stream) => {
                let mut stream = stream.lock().await;
                let _ = stream.shutdown().await; // Ignore errors during shutdown
            },
        }

        // Update state
        {
            let mut state = self.state.lock().await;
            *state = ConnectionState::Closed;
        }

        Ok(())
    }

    /// Get the peer's node ID
    pub fn peer_id(&self) -> &NodeId {
        &self.peer_id
    }

    /// Get the peer's public key (if known)
    pub fn peer_public_key(&self) -> Option<&PublicKey> {
        self.peer_public_key.as_ref()
    }

    /// Get the connection state
    pub async fn state(&self) -> ConnectionState {
        *self.state.lock().await
    }

    /// Get the peer address
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Get total bytes sent
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get total bytes received
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Get connection age
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }
}

/// Send a framed message (length prefix + data)
async fn send_framed_message<S>(stream: &mut S, message: &[u8]) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    // Write length prefix (4 bytes, big-endian)
    let len = message.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| NetworkError::SendFailed {
            reason: format!("Failed to write length prefix: {}", e),
        })?;

    // Write message data
    stream
        .write_all(message)
        .await
        .map_err(|e| NetworkError::SendFailed {
            reason: format!("Failed to write message: {}", e),
        })?;

    // Flush to ensure data is sent
    stream.flush().await.map_err(|e| NetworkError::SendFailed {
        reason: format!("Failed to flush: {}", e),
    })?;

    Ok(())
}

/// Receive a framed message (length prefix + data)
async fn receive_framed_message<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncReadExt + Unpin,
{
    // Read length prefix (4 bytes, big-endian)
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            NetworkError::ConnectionReset
        } else {
            NetworkError::ReceiveFailed {
                reason: format!("Failed to read length prefix: {}", e),
            }
        }
    })?;

    let len = u32::from_be_bytes(len_bytes) as usize;

    // Validate length to prevent DoS
    if len > MAX_MESSAGE_SIZE {
        return Err(NetworkError::MessageTooLarge { size: len }.into());
    }

    // Read message data
    let mut message = vec![0u8; len];
    stream.read_exact(&mut message).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            NetworkError::ConnectionReset
        } else {
            NetworkError::ReceiveFailed {
                reason: format!("Failed to read message data: {}", e),
            }
        }
    })?;

    Ok(message)
}

/// Connection pool for managing multiple peer connections
pub struct ConnectionPool {
    /// Active connections indexed by peer ID
    connections: DashMap<NodeId, Arc<Connection>>,
    /// Maximum number of concurrent connections
    max_connections: usize,
}

impl ConnectionPool {
    /// Create a new connection pool
    ///
    /// # Arguments
    ///
    /// * `max_connections` - Maximum number of concurrent connections allowed
    ///
    /// # Example
    ///
    /// ```
    /// use meshara::network::ConnectionPool;
    ///
    /// let pool = ConnectionPool::new(100);
    /// ```
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: DashMap::new(),
            max_connections,
        }
    }

    /// Get an existing connection or create a new one
    ///
    /// # Arguments
    ///
    /// * `peer_id` - ID of the peer to connect to
    /// * `address` - Socket address of the peer
    /// * `tls_config` - Client TLS configuration
    ///
    /// # Example
    ///
    /// ```no_run
    /// use meshara::crypto::{Identity, NodeId};
    /// use meshara::network::{TlsConfig, ConnectionPool};
    /// use std::net::SocketAddr;
    ///
    /// # async fn example() -> meshara::error::Result<()> {
    /// let pool = ConnectionPool::new(100);
    /// let identity = Identity::generate();
    /// let tls_config = TlsConfig::from_identity(&identity)?;
    /// let peer_id = NodeId::from_bytes([1u8; 32]);
    /// let addr: SocketAddr = "127.0.0.1:8443".parse().unwrap();
    ///
    /// let conn = pool.get_or_connect(&peer_id, addr, tls_config.client_config()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_or_connect(
        &self,
        peer_id: &NodeId,
        address: SocketAddr,
        tls_config: Arc<ClientConfig>,
    ) -> Result<Arc<Connection>> {
        // Check if connection already exists
        if let Some(conn) = self.connections.get(peer_id) {
            // Verify connection is still active
            if conn.state().await == ConnectionState::Connected {
                return Ok(conn.clone());
            } else {
                // Remove stale connection
                self.connections.remove(peer_id);
            }
        }

        // Check connection limit
        if self.connections.len() >= self.max_connections {
            return Err(NetworkError::ConnectionFailed {
                address: address.to_string(),
                reason: "Connection pool is full".to_string(),
            }
            .into());
        }

        // Create new connection
        let conn = Connection::connect(address, tls_config).await?;
        let conn_arc = Arc::new(conn);

        // Store in pool
        self.connections.insert(*peer_id, conn_arc.clone());

        Ok(conn_arc)
    }

    /// Add an accepted connection to the pool
    ///
    /// # Arguments
    ///
    /// * `connection` - The accepted connection to add
    pub fn add_connection(&self, connection: Connection) -> Result<()> {
        let peer_id = *connection.peer_id();

        // Check connection limit
        if self.connections.len() >= self.max_connections {
            return Err(NetworkError::ConnectionFailed {
                address: connection.peer_addr().to_string(),
                reason: "Connection pool is full".to_string(),
            }
            .into());
        }

        self.connections.insert(peer_id, Arc::new(connection));
        Ok(())
    }

    /// Get a connection by peer ID
    pub fn get(&self, peer_id: &NodeId) -> Option<Arc<Connection>> {
        self.connections.get(peer_id).map(|entry| entry.clone())
    }

    /// Remove a connection from the pool
    pub fn remove(&self, peer_id: &NodeId) -> Option<Arc<Connection>> {
        self.connections.remove(peer_id).map(|(_, conn)| conn)
    }

    /// Get the number of active connections
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Check if the pool is empty
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Close all connections gracefully
    pub async fn close_all(&self) {
        for entry in self.connections.iter() {
            let conn = entry.value();
            let _ = conn.close().await; // Ignore errors
        }
        self.connections.clear();
    }

    /// Get all peer IDs
    pub fn peer_ids(&self) -> Vec<NodeId> {
        self.connections.iter().map(|entry| *entry.key()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state_transitions() {
        assert_eq!(ConnectionState::Connecting, ConnectionState::Connecting);
        assert_ne!(ConnectionState::Connected, ConnectionState::Closed);
    }

    #[test]
    fn test_connection_pool_creation() {
        let pool = ConnectionPool::new(100);
        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_connection_pool_peer_ids() {
        let pool = ConnectionPool::new(100);
        let peer_ids = pool.peer_ids();
        assert_eq!(peer_ids.len(), 0);
    }

    #[tokio::test]
    async fn test_message_framing() {
        // Create a mock message
        let message_bytes = b"Hello, Meshara!";

        // Create an in-memory buffer to simulate a stream
        let mut buffer = Vec::new();

        // Send framed message
        send_framed_message(&mut buffer, message_bytes)
            .await
            .unwrap();

        // Verify format: [4 byte length][data]
        assert_eq!(buffer.len(), 4 + message_bytes.len());
        assert_eq!(&buffer[0..4], &(message_bytes.len() as u32).to_be_bytes());
        assert_eq!(&buffer[4..], message_bytes);

        // Receive framed message
        let mut cursor = &buffer[..];
        let received = receive_framed_message(&mut cursor).await.unwrap();
        assert_eq!(received, message_bytes);
    }

    #[tokio::test]
    async fn test_message_framing_large_message() {
        // Create a large message (but under limit)
        let message_bytes = vec![42u8; 1024 * 1024]; // 1 MB

        let mut buffer = Vec::new();
        send_framed_message(&mut buffer, &message_bytes)
            .await
            .unwrap();

        let mut cursor = &buffer[..];
        let received = receive_framed_message(&mut cursor).await.unwrap();
        assert_eq!(received.len(), message_bytes.len());
        assert_eq!(received, message_bytes);
    }

    #[tokio::test]
    async fn test_message_framing_oversized() {
        // Create an oversized length prefix
        let oversized_len = (MAX_MESSAGE_SIZE + 1) as u32;
        let mut buffer = oversized_len.to_be_bytes().to_vec();
        buffer.extend_from_slice(&[0u8; 100]); // Some dummy data

        let mut cursor = &buffer[..];
        let result = receive_framed_message(&mut cursor).await;
        assert!(result.is_err());

        // Check that it's a NetworkError::MessageTooLarge
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            crate::error::MesharaError::Network(crate::error::NetworkError::MessageTooLarge { .. })
        ));
    }
}

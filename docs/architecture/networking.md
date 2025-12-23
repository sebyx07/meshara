# Networking Architecture

Meshara's networking layer handles all network communication using TLS 1.3 for transport security and traffic obfuscation. The design prioritizes censorship resistance by making traffic indistinguishable from HTTPS.

## TLS 1.3 Layer

### Why TLS

**Traffic Obfuscation**: All Meshara traffic wrapped in TLS 1.3 appears identical to HTTPS web traffic. Network observers cannot distinguish it from regular web browsing or API calls.

**Transport Security**: TLS provides additional encryption layer beyond application-level encryption. Defense in depth.

**Standardization**: TLS is ubiquitous. Firewalls and DPI systems expect TLS traffic. Less likely to be flagged or throttled.

### TLS Configuration

**Using rustls** (pure Rust, no OpenSSL dependency):

```rust
use rustls::{ServerConfig, ClientConfig, Certificate, PrivateKey};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub struct MesharaTlsConfig {
    // Server configuration (for accepting connections)
    server_config: Arc<ServerConfig>,

    // Client configuration (for initiating connections)
    client_config: Arc<ClientConfig>,
}

impl MesharaTlsConfig {
    pub fn new(identity: &Identity) -> Result<Self, TlsError> {
        // Generate self-signed certificate from node's public key
        let cert = Self::generate_certificate(identity)?;
        let private_key = Self::export_private_key(identity)?;

        // Server config
        let mut server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()  // We verify peers using Ed25519, not TLS certs
            .with_single_cert(vec![cert.clone()], private_key.clone())?;

        // Set ALPN protocol
        server_config.alpn_protocols = vec![b"meshara/1.0".to_vec()];

        // Client config
        let mut client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(
                Arc::new(MesharaVerifier::new())  // Custom verifier
            )
            .with_single_cert(vec![cert], private_key)?;

        client_config.alpn_protocols = vec![b"meshara/1.0".to_vec()];

        Ok(Self {
            server_config: Arc::new(server_config),
            client_config: Arc::new(client_config),
        })
    }

    fn generate_certificate(identity: &Identity) -> Result<Certificate, TlsError> {
        use rcgen::{Certificate as RcgenCert, CertificateParams};

        let mut params = CertificateParams::new(vec!["meshara.node".to_string()]);

        // Use node's public key in certificate
        params.key_pair = Some(Self::convert_ed25519_to_cert_key(identity)?);

        let cert = RcgenCert::from_params(params)?;

        Ok(Certificate(cert.serialize_der()?))
    }
}
```

### Custom Certificate Verification

Meshara doesn't use CA-based certificate verification. Instead, verify peer identity using Ed25519 public keys:

```rust
use rustls::client::ServerCertVerifier;
use rustls::ServerName;

pub struct MesharaVerifier {
    // Map of expected peer public keys (optional)
    pinned_peers: Arc<RwLock<HashMap<SocketAddr, PublicKey>>>,
}

impl ServerCertVerifier for MesharaVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Accept any certificate during TLS handshake
        // Actual peer verification happens via Ed25519 signature
        // after TLS connection established

        Ok(ServerCertVerified::assertion())
    }
}
```

### ALPN Protocol Negotiation

**Application-Layer Protocol Negotiation** allows peers to identify each other while appearing as normal HTTPS:

```rust
pub async fn establish_connection(
    &self,
    addr: SocketAddr,
) -> Result<MesharaConnection, NetworkError> {
    // Connect TCP socket
    let tcp_stream = TcpStream::connect(addr).await?;

    // Wrap in TLS
    let tls_connector = TlsConnector::from(self.tls_config.client_config.clone());
    let domain = ServerName::try_from("meshara.node")?;

    let tls_stream = tls_connector.connect(domain, tcp_stream).await?;

    // Verify ALPN protocol was negotiated
    let (_, server_connection) = tls_stream.get_ref();
    let alpn_protocol = server_connection.alpn_protocol();

    if alpn_protocol != Some(b"meshara/1.0") {
        return Err(NetworkError::AlpnMismatch);
    }

    // Perform Meshara handshake over TLS connection
    let connection = self.perform_handshake(tls_stream).await?;

    Ok(connection)
}
```

To network observers:
- Sees TLS handshake (normal for HTTPS)
- Sees ALPN negotiation (normal for HTTP/2, gRPC, etc.)
- Cannot read ALPN protocol value (encrypted in TLS 1.3)
- Cannot distinguish from any other HTTPS connection

## HTTP/2 Framing (Optional)

For enhanced obfuscation, embed Meshara messages in HTTP/2 frames:

```rust
#[cfg(feature = "http2-framing")]
pub struct Http2Transport {
    // HTTP/2 connection
    h2_connection: h2::client::SendRequest<Bytes>,
}

#[cfg(feature = "http2-framing")]
impl Http2Transport {
    pub async fn send_message(&mut self, message: Vec<u8>) -> Result<(), NetworkError> {
        // Create HTTP/2 request
        let request = http::Request::builder()
            .method("POST")
            .uri("/api/v1/message")
            .header("content-type", "application/octet-stream")
            .header("user-agent", "meshara-client/1.0")
            .body(())
            .unwrap();

        // Send request
        let (response, mut stream) = self.h2_connection.send_request(request, false)?;

        // Send message as request body
        stream.send_data(Bytes::from(message), true).await?;

        // Await response
        let response = response.await?;

        if response.status() != http::StatusCode::OK {
            return Err(NetworkError::Http2Error);
        }

        Ok(())
    }

    pub async fn receive_message(&mut self) -> Result<Vec<u8>, NetworkError> {
        // Receive HTTP/2 request from peer
        let (request, mut stream) = self.h2_server.accept().await?
            .ok_or(NetworkError::ConnectionClosed)?;

        // Validate request
        if request.method() != http::Method::POST {
            stream.send_response(
                http::Response::builder()
                    .status(405)
                    .body(())
                    .unwrap(),
                true
            ).await?;
            return Err(NetworkError::InvalidRequest);
        }

        // Read body
        let mut body = Vec::new();
        while let Some(chunk) = stream.data().await {
            let chunk = chunk?;
            body.extend_from_slice(&chunk);
            stream.flow_control().release_capacity(chunk.len())?;
        }

        // Send success response
        stream.send_response(
            http::Response::builder()
                .status(200)
                .body(())
                .unwrap(),
            true
        ).await?;

        Ok(body)
    }
}
```

**To Network Observer**:
- Sees HTTP/2 over TLS (HTTPS)
- Sees POST requests to `/api/v1/message`
- Binary body (normal for modern REST APIs, protobuf, etc.)
- Indistinguishable from mobile app API traffic

## Peer Discovery

### mDNS (Local Network Discovery)

Discover peers on local network using multicast DNS:

```rust
use mdns_sd::{ServiceDaemon, ServiceInfo, ServiceEvent};

pub struct MdnsDiscovery {
    service_daemon: ServiceDaemon,
    service_name: String,
}

impl MdnsDiscovery {
    pub fn new(port: u16, node_id: &NodeId) -> Result<Self, DiscoveryError> {
        let service_daemon = ServiceDaemon::new()?;

        // Register our service
        let service_name = format!("meshara-{}", node_id.to_hex());
        let service_type = "_meshara._tcp.local.";

        let service_info = ServiceInfo::new(
            service_type,
            &service_name,
            &format!("{}.local.", hostname()),
            "",  // No address - will use host's address
            port,
            None,  // No TXT records
        )?;

        service_daemon.register(service_info)?;

        Ok(Self { service_daemon, service_name })
    }

    pub async fn discover_peers(&self) -> Result<Vec<PeerInfo>, DiscoveryError> {
        let browse = self.service_daemon.browse("_meshara._tcp.local.")?;

        let mut peers = Vec::new();

        // Listen for discoveries for 5 seconds
        let timeout = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                event = browse.recv_async() => {
                    if let Ok(ServiceEvent::ServiceResolved(info)) = event {
                        // Extract peer information
                        let peer = PeerInfo {
                            address: info.get_addresses().iter().next().copied()
                                .ok_or(DiscoveryError::NoAddress)?,
                            port: info.get_port(),
                            node_id: NodeId::from_service_name(info.get_fullname())?,
                        };

                        peers.push(peer);
                    }
                }
                _ = &mut timeout => break,
            }
        }

        Ok(peers)
    }
}
```

**Characteristics**:
- Local network only (same subnet)
- Fast discovery (< 1 second)
- Zero configuration
- Automatic (no user intervention)

### Bootstrap Nodes

Hard-coded entry points for joining the network:

```rust
pub struct BootstrapManager {
    bootstrap_nodes: Vec<BootstrapNode>,
}

pub struct BootstrapNode {
    address: SocketAddr,
    public_key: PublicKey,  // Pinned for security
    reliability_score: f64,
}

impl BootstrapManager {
    pub async fn connect_to_network(&self) -> Result<Vec<PeerInfo>, NetworkError> {
        // Try connecting to bootstrap nodes in parallel
        let mut tasks = vec![];

        for node in &self.bootstrap_nodes {
            tasks.push(self.connect_to_bootstrap(node));
        }

        let results = futures::future::join_all(tasks).await;

        // Collect successful connections
        let mut peers = Vec::new();
        for result in results {
            if let Ok(peer_list) = result {
                peers.extend(peer_list);
            }
        }

        if peers.is_empty() {
            return Err(NetworkError::NoBootstrapConnection);
        }

        Ok(peers)
    }

    async fn connect_to_bootstrap(
        &self,
        node: &BootstrapNode,
    ) -> Result<Vec<PeerInfo>, NetworkError> {
        // Connect to bootstrap node
        let conn = self.establish_connection(node.address).await?;

        // Verify it's the expected node (pinned public key)
        if conn.peer_public_key() != &node.public_key {
            return Err(NetworkError::PublicKeyMismatch);
        }

        // Request peer list
        let query = QueryMessage {
            query_id: generate_query_id(),
            query_type: "GET_PEERS".to_string(),
            query_data: vec![],
            response_required: true,
        };

        let response = conn.send_query(query).await?;

        // Parse peer list
        let peers: Vec<PeerInfo> = decode_peer_list(&response.response_data)?;

        Ok(peers)
    }
}
```

**Bootstrap Node Selection**:
- Hard-coded in library (updateable via authority updates)
- Geographically distributed
- High uptime (>99%)
- Public keys pinned (prevents MITM)
- Fallback if all fail: manual peer addition

### DHT-Based Discovery

See routing.md for DHT implementation details. DHT provides decentralized peer discovery without relying on bootstrap nodes.

## Connection Management

### Connection Pool

Maintain pool of connections to peers:

```rust
pub struct ConnectionPool {
    // Active connections
    connections: Arc<RwLock<HashMap<PublicKey, Arc<Connection>>>>,

    // Configuration
    max_connections: usize,
    min_connections: usize,

    // Metrics
    connection_stats: Arc<RwLock<HashMap<PublicKey, ConnectionStats>>>,
}

impl ConnectionPool {
    pub async fn get_connection(
        &self,
        peer: &PublicKey,
    ) -> Result<Arc<Connection>, NetworkError> {
        // Check if already connected
        {
            let conns = self.connections.read().await;
            if let Some(conn) = conns.get(peer) {
                if conn.is_alive() {
                    return Ok(conn.clone());
                }
            }
        }

        // Not connected - establish new connection
        let conn = self.establish_new_connection(peer).await?;

        // Add to pool
        {
            let mut conns = self.connections.write().await;

            // Check connection limit
            if conns.len() >= self.max_connections {
                // Evict least recently used connection
                self.evict_lru_connection(&mut conns).await;
            }

            conns.insert(peer.clone(), Arc::new(conn.clone()));
        }

        Ok(Arc::new(conn))
    }

    async fn evict_lru_connection(
        &self,
        conns: &mut HashMap<PublicKey, Arc<Connection>>,
    ) {
        let stats = self.connection_stats.read().await;

        // Find LRU connection (exclude pinned connections)
        let lru_peer = stats.iter()
            .filter(|(_, s)| !s.pinned)
            .min_by_key(|(_, s)| s.last_used)
            .map(|(k, _)| k.clone());

        if let Some(peer) = lru_peer {
            if let Some(conn) = conns.remove(&peer) {
                conn.close().await;
            }
        }
    }

    pub async fn maintain_connections(&self) {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;

            let mut conns = self.connections.write().await;

            // Remove dead connections
            conns.retain(|_, conn| conn.is_alive());

            // Ensure minimum connections
            if conns.len() < self.min_connections {
                // Discover and connect to new peers
                drop(conns);  // Release lock
                self.connect_to_new_peers().await;
            }
        }
    }
}

pub struct ConnectionStats {
    last_used: Instant,
    bytes_sent: u64,
    bytes_received: u64,
    messages_sent: u64,
    messages_received: u64,
    latency_ms: u64,
    pinned: bool,  // Pinned connections not evicted
}
```

### Connection Lifecycle

```rust
pub struct Connection {
    // Underlying TLS stream
    stream: Arc<Mutex<TlsStream<TcpStream>>>,

    // Peer information
    peer_public_key: PublicKey,
    peer_address: SocketAddr,

    // Connection state
    state: Arc<RwLock<ConnectionState>>,

    // Heartbeat task handle
    heartbeat_task: Option<JoinHandle<()>>,
}

pub enum ConnectionState {
    Connecting,
    Handshaking,
    Connected,
    Closing,
    Closed,
}

impl Connection {
    pub async fn send(&self, data: &[u8]) -> Result<(), NetworkError> {
        // Check state
        {
            let state = self.state.read().await;
            if *state != ConnectionState::Connected {
                return Err(NetworkError::NotConnected);
            }
        }

        // Frame message (length prefix)
        let mut framed = Vec::with_capacity(data.len() + 4);
        framed.extend_from_slice(&(data.len() as u32).to_be_bytes());
        framed.extend_from_slice(data);

        // Send over TLS
        let mut stream = self.stream.lock().await;
        stream.write_all(&framed).await?;
        stream.flush().await?;

        Ok(())
    }

    pub async fn receive(&self) -> Result<Vec<u8>, NetworkError> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        let mut stream = self.stream.lock().await;
        stream.read_exact(&mut len_buf).await?;

        let len = u32::from_be_bytes(len_buf) as usize;

        // Sanity check
        if len > MAX_MESSAGE_SIZE {
            return Err(NetworkError::MessageTooLarge);
        }

        // Read message
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        Ok(buf)
    }

    async fn heartbeat_loop(&self) {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;

            // Send heartbeat
            let heartbeat = HeartbeatMessage {
                timestamp: current_timestamp(),
            };

            if self.send(&heartbeat.encode_to_vec()).await.is_err() {
                // Connection failed - mark as dead
                let mut state = self.state.write().await;
                *state = ConnectionState::Closed;
                break;
            }
        }
    }
}
```

## NAT Traversal

### UPnP/NAT-PMP

Automatically configure router port forwarding:

```rust
use igd::search_gateway;

pub async fn setup_port_forwarding(port: u16) -> Result<(), NatError> {
    // Search for UPnP gateway
    let gateway = tokio::task::spawn_blocking(move || {
        search_gateway(Default::default())
    }).await??;

    // Get external IP
    let external_ip = gateway.get_external_ip().await?;

    // Add port mapping
    gateway.add_port(
        igd::PortMappingProtocol::TCP,
        port,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port),
        3600,  // Lease duration: 1 hour
        "Meshara Node",
    ).await?;

    Ok(())
}
```

### STUN/TURN

For NAT traversal when UPnP unavailable:

```rust
pub async fn discover_public_address(&self) -> Result<SocketAddr, NatError> {
    // Use public STUN server
    let stun_server = "stun.l.google.com:19302";

    let client = stun::Client::new(stun_server).await?;
    let public_addr = client.get_mapped_address().await?;

    Ok(public_addr)
}
```

## Traffic Padding

Obscure message sizes and timing:

```rust
pub fn pad_message(message: Vec<u8>) -> Vec<u8> {
    // Find next power of 2 size
    let sizes = [256, 512, 1024, 2048, 4096, 8192, 16384];
    let target_size = sizes.iter()
        .find(|&&s| s >= message.len())
        .unwrap_or(&16384);

    let padding_needed = target_size - message.len();

    // Add padding
    let mut padded = message;
    padded.resize(*target_size, 0);

    // Set padding length in last 4 bytes
    let padding_len_bytes = (padding_needed as u32).to_be_bytes();
    padded[padded.len() - 4..].copy_from_slice(&padding_len_bytes);

    padded
}

pub fn remove_padding(padded: Vec<u8>) -> Vec<u8> {
    // Read padding length from last 4 bytes
    let padding_len = u32::from_be_bytes(
        padded[padded.len() - 4..].try_into().unwrap()
    ) as usize;

    // Remove padding
    let message_len = padded.len() - padding_len;
    padded[..message_len].to_vec()
}
```

## Performance Characteristics

**TLS Handshake**: 50-100ms (local network)

**Throughput**: ~100 MB/sec per connection (TLS overhead)

**Connection Pool**: 50-200 active connections typical

**mDNS Discovery**: < 1 second (local network)

**Bootstrap Connection**: 200-500ms

**NAT Traversal**: 1-3 seconds (UPnP) or 3-10 seconds (STUN)

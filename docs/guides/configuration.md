# Configuration Guide

Comprehensive guide to configuring Meshara nodes for different use cases.

## Basic Configuration

### Minimal Setup

Absolute minimum configuration:

```rust
let node = NodeBuilder::new()
    .build()
    .await?;
```

**Defaults**:
- Storage: `./meshara_data`
- Port: Random available port
- Privacy: Standard (direct/bridge routing)
- Discovery: None (manual peer addition only)
- Max peers: 50

### Recommended Production Setup

```rust
let node = NodeBuilder::new()
    .with_storage_path("/var/lib/meshara")
    .with_listen_port(443)  // Standard HTTPS port
    .with_max_peers(200)
    .with_min_peers(20)
    .enable_auto_discovery()
    .with_bootstrap_nodes(vec![
        "bootstrap1.example.com:443".parse()?,
        "bootstrap2.example.com:443".parse()?,
    ])
    .build()
    .await?;
```

## Storage Configuration

### Storage Path

```rust
let node = NodeBuilder::new()
    .with_storage_path("/path/to/storage")
    .build()
    .await?;
```

**Storage contains**:
- `keystore`: Encrypted private keys
- `config.db`: Node configuration
- `bloom_filters/`: Message deduplication filters
- `dht_cache/`: DHT routing table (if enabled)

### Storage Encryption

Keys are always encrypted at rest:

```rust
// With passphrase protection
let node = NodeBuilder::new()
    .with_storage_path("./meshara_data")
    .with_passphrase("strong-passphrase")
    .build()
    .await?;

// Passphrase required on restart
let node = NodeBuilder::new()
    .with_storage_path("./meshara_data")
    .unlock_with_passphrase("strong-passphrase")?
    .build()
    .await?;
```

**Without passphrase**:
- Keys encrypted with hardware-derived key
- Less secure (no password)
- Automatic unlock (no user interaction)

### Persistent vs Ephemeral

```rust
// Persistent storage (default)
let node = NodeBuilder::new()
    .with_storage_path("./meshara_data")
    .build()
    .await?;

// Ephemeral (in-memory only, identity lost on shutdown)
#[cfg(feature = "dev-mode")]
let node = NodeBuilder::new()
    .with_ephemeral_storage()
    .build()
    .await?;
```

## Network Configuration

### Listen Port

```rust
// Specific port
let node = NodeBuilder::new()
    .with_listen_port(443)
    .build()
    .await?;

// Random available port
let node = NodeBuilder::new()
    .with_listen_port(0)  // OS assigns port
    .build()
    .await?;

println!("Listening on port: {}", node.listen_port());
```

**Port recommendations**:
- `443`: Standard HTTPS (requires root/admin)
- `8443`: Alternative HTTPS
- `8080`: HTTP alternative
- `0`: Random (for testing)

### Bind Address

```rust
// Bind to specific interface
let node = NodeBuilder::new()
    .with_bind_address("192.168.1.100:443".parse()?)
    .build()
    .await?;

// Bind to all interfaces (default)
let node = NodeBuilder::new()
    .with_bind_address("0.0.0.0:443".parse()?)
    .build()
    .await?;

// IPv6
let node = NodeBuilder::new()
    .with_bind_address("[::]:443".parse()?)
    .build()
    .await?;
```

### Connection Limits

```rust
let node = NodeBuilder::new()
    .with_max_peers(200)      // Maximum concurrent connections
    .with_min_peers(20)        // Target minimum connections
    .with_max_pending_connections(50)  // Connection queue size
    .build()
    .await?;
```

**Tuning guidelines**:
- **Bridge nodes**: High max_peers (500+)
- **Client nodes**: Low max_peers (20-50)
- **Authority nodes**: Medium max_peers (100-200)
- **IoT devices**: Very low max_peers (5-10)

### Timeouts

```rust
let node = NodeBuilder::new()
    .with_connection_timeout(Duration::from_secs(30))
    .with_handshake_timeout(Duration::from_secs(10))
    .with_idle_timeout(Duration::from_secs(300))  // 5 minutes
    .build()
    .await?;
```

## Peer Discovery Configuration

### mDNS (Local Network)

```rust
let node = NodeBuilder::new()
    .enable_auto_discovery()  // Enables mDNS
    .with_mdns_service_name("my-meshara-network")
    .build()
    .await?;
```

**When to use**:
- Local area networks
- Development/testing
- Peer-to-peer scenarios without internet

**When NOT to use**:
- Internet-wide networks (mDNS doesn't cross routers)
- Strict network policies
- High-security environments

### Bootstrap Nodes

```rust
let bootstrap_nodes = vec![
    "bootstrap1.example.com:443".parse()?,
    "bootstrap2.example.com:443".parse()?,
    "192.168.1.100:8443".parse()?,
];

let node = NodeBuilder::new()
    .with_bootstrap_nodes(bootstrap_nodes)
    .build()
    .await?;
```

**Bootstrap node requirements**:
- High uptime (>99%)
- Stable IP address or DNS
- Sufficient bandwidth
- Public accessibility

### DHT Configuration

```rust
#[cfg(feature = "dht")]
let node = NodeBuilder::new()
    .enable_dht()
    .with_dht_k_value(20)        // K-bucket size
    .with_dht_alpha(3)            // Concurrent queries
    .with_dht_cache_ttl(Duration::from_secs(3600))  // 1 hour
    .build()
    .await?;
```

**DHT parameters**:
- `k_value`: Redundancy (default: 20)
- `alpha`: Parallelism (default: 3)
- `cache_ttl`: How long to cache routes

## Privacy Configuration

### Privacy Levels

```rust
// Standard: Direct/bridge routing
let node = NodeBuilder::new()
    .with_privacy_level(PrivacyLevel::Standard)
    .build()
    .await?;

// Enhanced: Onion routing when available
#[cfg(feature = "onion-routing")]
let node = NodeBuilder::new()
    .with_privacy_level(PrivacyLevel::Enhanced)
    .build()
    .await?;

// Maximum: Always onion routing
#[cfg(feature = "onion-routing")]
let node = NodeBuilder::new()
    .with_privacy_level(PrivacyLevel::Maximum)
    .with_onion_hops(3)  // Number of hops
    .build()
    .await?;
```

### Traffic Obfuscation

```rust
// HTTP/2 framing (HTTPS mimicry)
#[cfg(feature = "http2-framing")]
let node = NodeBuilder::new()
    .enable_http2_framing()
    .build()
    .await?;

// Traffic padding
let node = NodeBuilder::new()
    .enable_traffic_padding()
    .with_padding_sizes(vec![256, 512, 1024, 2048, 4096])
    .build()
    .await?;

// Cover traffic (dummy messages)
let node = NodeBuilder::new()
    .enable_cover_traffic()
    .with_cover_traffic_rate(Duration::from_secs(60))  // Every minute
    .build()
    .await?;
```

### Domain Fronting

```rust
#[cfg(feature = "domain-fronting")]
let node = NodeBuilder::new()
    .enable_domain_fronting()
    .with_fronting_domain("www.cloudfront.net")
    .with_real_domain("meshara-bridge.example.com")
    .build()
    .await?;
```

**CDN compatibility**:
- Cloudflare
- AWS CloudFront
- Google Cloud CDN
- Azure CDN

## Authority Configuration

### Trusting Authorities

```rust
let authority_keys = vec![
    PublicKey::from_hex("7f3a2b...")?,
    PublicKey::from_hex("9d4c1e...")?,
];

let node = NodeBuilder::new()
    .with_authority_keys(authority_keys)
    .build()
    .await?;
```

### Becoming an Authority

```rust
let node = NodeBuilder::new()
    .with_storage_path("/var/lib/meshara-authority")
    .with_listen_port(443)
    .with_network_profile(NetworkProfile::Authority)
    .enable_authority_mode()
    .build()
    .await?;

// Publish updates
node.publish_update(
    "1.0.0",
    update_binary,
    "Initial release"
).await?;
```

### Auto-Update Configuration

```rust
let node = NodeBuilder::new()
    .with_authority_keys(vec![authority_pubkey])
    .enable_auto_update()
    .with_update_check_interval(Duration::from_secs(3600))  // Check hourly
    .with_auto_install(true)  // Automatically apply updates
    .build()
    .await?;

// Or manual updates
let node = NodeBuilder::new()
    .with_authority_keys(vec![authority_pubkey])
    .enable_auto_update()
    .with_auto_install(false)  // Prompt user
    .build()
    .await?;

node.on_update_available(|event| async move {
    // Prompt user to approve update
    if user_approves(&event) {
        apply_update(&event).await;
    }
}).await?;
```

## Network Profiles

### Predefined Profiles

```rust
// Minimal (IoT, low resource)
let node = NodeBuilder::new()
    .with_network_profile(NetworkProfile::Minimal)
    .build()
    .await?;
// - Max 5 peers
// - No DHT
// - No auto-discovery
// - Minimal memory

// Standard (default, balanced)
let node = NodeBuilder::new()
    .with_network_profile(NetworkProfile::Standard)
    .build()
    .await?;
// - Max 50 peers
// - mDNS discovery
// - Standard routing

// Bridge (high connectivity)
let node = NodeBuilder::new()
    .with_network_profile(NetworkProfile::Bridge)
    .build()
    .await?;
// - Max 500 peers
// - DHT enabled
// - All discovery methods
// - High bandwidth

// Authority (publishing capability)
let node = NodeBuilder::new()
    .with_network_profile(NetworkProfile::Authority)
    .build()
    .await?;
// - Max 200 peers
// - DHT enabled
// - Stable identity required
```

### Custom Profile

```rust
let custom_profile = NetworkProfile {
    max_peers: 100,
    min_peers: 10,
    enable_dht: true,
    enable_mdns: false,
    enable_onion_routing: true,
    connection_timeout: Duration::from_secs(20),
    idle_timeout: Duration::from_secs(180),
};

let node = NodeBuilder::new()
    .with_custom_network_profile(custom_profile)
    .build()
    .await?;
```

## TLS Configuration

### Certificate Mode

```rust
// Self-signed (default, peer verification via public keys)
let node = NodeBuilder::new()
    .with_tls_mode(TlsMode::SelfSigned)
    .build()
    .await?;

// Let's Encrypt (for bridge nodes with DNS)
#[cfg(feature = "acme")]
let node = NodeBuilder::new()
    .with_tls_mode(TlsMode::ACME {
        domain: "bridge.example.com".to_string(),
        contact_email: "admin@example.com".to_string(),
    })
    .build()
    .await?;

// Custom certificate
let node = NodeBuilder::new()
    .with_tls_certificate(cert_pem, key_pem)
    .build()
    .await?;
```

### ALPN Configuration

```rust
let node = NodeBuilder::new()
    .with_alpn_protocol(b"meshara/1.0")  // Default
    .build()
    .await?;

// Custom ALPN (for private networks)
let node = NodeBuilder::new()
    .with_alpn_protocol(b"my-private-protocol/1.0")
    .build()
    .await?;
```

## Logging and Diagnostics

### Log Level

```rust
// Configure before creating node
use tracing_subscriber::EnvFilter;

tracing_subscriber::fmt()
    .with_env_filter(
        EnvFilter::from_default_env()
            .add_directive("meshara=debug".parse()?)
            .add_directive("meshara::network=trace".parse()?)
    )
    .init();

let node = NodeBuilder::new().build().await?;
```

### Log Output

```rust
use tracing_subscriber::fmt;

// File output
let file = std::fs::File::create("meshara.log")?;
let file_writer = std::io::BufWriter::new(file);

tracing_subscriber::fmt()
    .with_writer(file_writer)
    .with_ansi(false)
    .init();

// JSON format (for log aggregation)
tracing_subscriber::fmt()
    .json()
    .with_current_span(false)
    .init();
```

### Metrics

```rust
#[cfg(feature = "metrics")]
let node = NodeBuilder::new()
    .enable_metrics()
    .with_metrics_port(9090)  // Prometheus endpoint
    .build()
    .await?;

// Metrics available at http://localhost:9090/metrics
```

## Feature Flags

Enable optional features in `Cargo.toml`:

```toml
[dependencies]
meshara = { version = "1.0", features = [
    "onion-routing",    # Privacy mode
    "dht",              # Distributed peer discovery
    "http2-framing",    # HTTPS mimicry
    "domain-fronting",  # Censorship circumvention
    "metrics",          # Prometheus metrics
    "acme",             # Let's Encrypt support
] }
```

## Environment-Specific Configs

### Development

```rust
#[cfg(debug_assertions)]
let node = NodeBuilder::new()
    .with_storage_path("./dev_data")
    .with_listen_port(8443)
    .enable_auto_discovery()
    .with_privacy_level(PrivacyLevel::Standard)
    .build()
    .await?;
```

### Production

```rust
#[cfg(not(debug_assertions))]
let node = NodeBuilder::new()
    .with_storage_path("/var/lib/meshara")
    .with_listen_port(443)
    .with_max_peers(200)
    .with_bootstrap_nodes(production_bootstrap_nodes())
    .with_privacy_level(PrivacyLevel::Enhanced)
    .enable_metrics()
    .build()
    .await?;
```

### Testing

```rust
#[cfg(test)]
let node = NodeBuilder::new()
    .with_ephemeral_storage()
    .with_listen_port(0)  // Random port
    .build()
    .await?;
```

## Configuration File

Load configuration from file:

```rust
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct Config {
    storage_path: PathBuf,
    listen_port: u16,
    max_peers: usize,
    bootstrap_nodes: Vec<SocketAddr>,
    privacy_level: PrivacyLevel,
}

// Load from TOML
let config_str = std::fs::read_to_string("meshara.toml")?;
let config: Config = toml::from_str(&config_str)?;

let node = NodeBuilder::new()
    .with_storage_path(&config.storage_path)
    .with_listen_port(config.listen_port)
    .with_max_peers(config.max_peers)
    .with_bootstrap_nodes(config.bootstrap_nodes)
    .with_privacy_level(config.privacy_level)
    .build()
    .await?;
```

**Example `meshara.toml`**:

```toml
storage_path = "/var/lib/meshara"
listen_port = 443
max_peers = 200
privacy_level = "Enhanced"

[[bootstrap_nodes]]
address = "bootstrap1.example.com:443"

[[bootstrap_nodes]]
address = "bootstrap2.example.com:443"

[tls]
mode = "SelfSigned"

[discovery]
enable_mdns = false
enable_dht = true

[logging]
level = "info"
output = "/var/log/meshara.log"
```

## Runtime Configuration Updates

Some settings can be updated without restart:

```rust
// Update peer limits
node.update_config(|config| {
    config.max_peers = 300;
    config.min_peers = 30;
}).await?;

// Update privacy level
node.set_privacy_level(PrivacyLevel::Maximum).await?;

// Update bootstrap nodes
node.set_bootstrap_nodes(new_bootstrap_nodes).await?;
```

**Settings requiring restart**:
- Storage path
- Listen port
- Bind address
- TLS configuration

## Performance Tuning

### High Throughput

```rust
let node = NodeBuilder::new()
    .with_max_peers(500)
    .with_connection_pool_size(1000)
    .with_send_buffer_size(1024 * 1024)  // 1 MB
    .with_receive_buffer_size(1024 * 1024)
    .with_worker_threads(num_cpus::get())
    .build()
    .await?;
```

### Low Latency

```rust
let node = NodeBuilder::new()
    .with_privacy_level(PrivacyLevel::Standard)  // Direct routing
    .with_connection_timeout(Duration::from_secs(5))
    .disable_traffic_padding()  // Reduces overhead
    .with_tcp_nodelay(true)  // Disable Nagle's algorithm
    .build()
    .await?;
```

### Low Resource

```rust
let node = NodeBuilder::new()
    .with_network_profile(NetworkProfile::Minimal)
    .with_max_peers(5)
    .with_bloom_filter_size(1000)  // Smaller dedup filter
    .with_connection_pool_size(10)
    .disable_dht()
    .build()
    .await?;
```

## Security Hardening

```rust
let node = NodeBuilder::new()
    .with_passphrase("strong-passphrase")
    .with_privacy_level(PrivacyLevel::Maximum)
    .enable_rate_limiting()
    .with_max_message_size(1024 * 1024)  // 1 MB limit
    .with_peer_reputation_enabled(true)
    .with_untrusted_peer_timeout(Duration::from_secs(60))
    .disable_plaintext_messages()  // No unencrypted broadcasts
    .build()
    .await?;
```

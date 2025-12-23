# Authority API Reference

Authority nodes are trusted entities that publish signed content, such as software updates, to the network. This API covers both authority node operations and client-side authority management.

## Authority Concepts

**Authority**: Trusted node with special privileges (publishing updates, signing content)

**Trust Model**: Clients explicitly trust authority public keys. No certificate authority or PKI required.

**Multi-Signature**: Multiple authorities can sign same content for increased security.

## Client-Side Authority Management

### add_authority

Add trusted authority to the node's trust list.

```rust
impl Node {
    pub async fn add_authority(
        &self,
        public_key: PublicKey,
        identifier: String,
        trust_level: TrustLevel,
    ) -> Result<(), Error>
}
```

**Parameters**:
- `public_key`: Authority's Ed25519 public key
- `identifier`: Human-readable name (e.g., "Official Developer")
- `trust_level`: What this authority is trusted for

**Example**:
```rust
let authority_key = PublicKey::from_hex("7f3a2b1c...")?;

node.add_authority(
    authority_key,
    "Meshara Official".to_string(),
    TrustLevel::UpdateAuthority,
).await?;
```

### TrustLevel

Defines what an authority is trusted for.

```rust
pub enum TrustLevel {
    UpdateAuthority,      // Can publish software updates
    SigningAuthority,     // Can sign arbitrary messages
    BootstrapAuthority,   // Trusted for providing peer lists
}
```

**Multiple roles**:
```rust
// Authority trusted for both updates and bootstrap
node.add_authority(
    authority_key.clone(),
    "Developer Team".to_string(),
    TrustLevel::UpdateAuthority | TrustLevel::BootstrapAuthority,
).await?;
```

### remove_authority

Remove authority from trust list.

```rust
impl Node {
    pub async fn remove_authority(&self, public_key: &PublicKey) -> Result<(), Error>
}
```

**Example**:
```rust
node.remove_authority(&old_authority_key).await?;
```

### list_authorities

Get list of trusted authorities.

```rust
impl Node {
    pub async fn list_authorities(&self) -> Result<Vec<AuthorityInfo>, Error>
}

pub struct AuthorityInfo {
    pub public_key: PublicKey,
    pub identifier: String,
    pub trust_level: TrustLevel,
    pub added_at: SystemTime,
    pub last_seen: Option<SystemTime>,
}
```

**Example**:
```rust
let authorities = node.list_authorities().await?;

for authority in authorities {
    println!("{}: {} ({})",
             authority.identifier,
             authority.public_key.to_hex(),
             authority.trust_level);
}
```

## Authority Node Operations

### Becoming an Authority

Configure node as authority:

```rust
let authority_node = NodeBuilder::new()
    .with_storage_path("/var/lib/meshara-authority")
    .with_listen_port(443)
    .with_network_profile(NetworkProfile::Authority)
    .enable_authority_mode()
    .build()
    .await?;
```

**Requirements**:
- Stable identity (persistent storage)
- High uptime
- Good network connectivity
- Secure key management

### publish_update

Publish signed software update to network.

```rust
impl Node {
    pub async fn publish_update(
        &self,
        version: &str,
        package_data: Vec<u8>,
        changelog: &str,
    ) -> Result<MessageId, Error>
}
```

**Parameters**:
- `version`: Semantic version (e.g., "2.0.1")
- `package_data`: Binary update package
- `changelog`: Human-readable changelog

**Returns**: Message ID of broadcast

**Behavior**:
1. Creates UpdatePackage protobuf
2. Computes Blake3 checksum
3. Signs with authority private key
4. Broadcasts via gossip protocol

**Example**:
```rust
let update_binary = std::fs::read("update_v2.0.0.bin")?;
let changelog = std::fs::read_to_string("CHANGELOG.md")?;

let msg_id = authority_node.publish_update(
    "2.0.0",
    update_binary,
    &changelog,
).await?;

println!("Update published: {}", msg_id);
```

### publish_update_with_metadata

Publish update with additional metadata.

```rust
impl Node {
    pub async fn publish_update_with_metadata(
        &self,
        version: &str,
        package_data: Vec<u8>,
        changelog: &str,
        metadata: UpdateMetadata,
    ) -> Result<MessageId, Error>
}

pub struct UpdateMetadata {
    pub required_version: String,
    pub platform: Vec<String>,
    pub download_url: Option<String>,
    pub release_date: SystemTime,
    pub custom: HashMap<String, String>,
}
```

**Example**:
```rust
let metadata = UpdateMetadata {
    required_version: "1.9.0".to_string(),
    platform: vec!["linux-x86_64".to_string(), "macos-aarch64".to_string()],
    download_url: Some("https://releases.example.com/v2.0.0".to_string()),
    release_date: SystemTime::now(),
    custom: HashMap::new(),
};

authority_node.publish_update_with_metadata(
    "2.0.0",
    update_binary,
    "Bug fixes and improvements",
    metadata,
).await?;
```

### respond_to_query

Respond to queries from clients.

```rust
impl Node {
    pub async fn respond_to_query(
        &self,
        query_id: &QueryId,
        response_data: Vec<u8>,
    ) -> Result<(), Error>
}
```

**Called from query event handler**.

**Example**:
```rust
authority_node.on_query_received(|query: QueryEvent| async move {
    let response = match query.query_type.as_str() {
        "GET_LATEST_VERSION" => {
            let version = get_latest_version();
            version.as_bytes().to_vec()
        }

        "GET_UPDATE_PACKAGE" => {
            let version = String::from_utf8_lossy(&query.query_data);
            match load_update_package(&version) {
                Ok(package) => package,
                Err(_) => b"Version not found".to_vec(),
            }
        }

        "GET_PEER_LIST" => {
            serialize_known_peers()
        }

        _ => b"Unknown query type".to_vec(),
    };

    authority_node.respond_to_query(&query.query_id, response).await.unwrap();
}).await?;
```

### sign_message

Sign arbitrary message as authority.

```rust
impl Node {
    pub async fn sign_message(&self, message: &[u8]) -> Result<Signature, Error>
}
```

**Requires**: Authority mode enabled

**Example**:
```rust
let message = b"Official statement";
let signature = authority_node.sign_message(message).await?;

// Distribute message + signature
let signed_content = SignedMessage {
    content: message.to_vec(),
    signature,
    authority_key: authority_node.public_key().clone(),
};
```

## Client-Side Update Handling

### Auto-Update Configuration

```rust
let client_node = NodeBuilder::new()
    .with_authority_keys(vec![authority_pubkey])
    .enable_auto_update()
    .with_update_check_interval(Duration::from_secs(3600))  // Check hourly
    .with_auto_install(false)  // Require user approval
    .build()
    .await?;
```

### Manual Update Check

```rust
impl Node {
    pub async fn check_for_updates(
        &self,
        authority: &PublicKey,
    ) -> Result<Option<UpdateInfo>, Error>
}

pub struct UpdateInfo {
    pub version: String,
    pub size: usize,
    pub changelog: String,
    pub release_date: SystemTime,
    pub download_url: Option<String>,
}
```

**Example**:
```rust
match client_node.check_for_updates(&authority_key).await? {
    Some(update) => {
        println!("Update available: v{}", update.version);
        println!("Size: {} bytes", update.size);
        println!("Changelog:\n{}", update.changelog);

        if user_approves(&update) {
            download_and_apply_update(&update).await?;
        }
    }
    None => {
        println!("No updates available");
    }
}
```

### apply_update

Apply downloaded update.

```rust
impl Node {
    pub async fn apply_update(&self, update_package: &[u8]) -> Result<(), Error>
}
```

**Behavior**:
1. Verifies checksum
2. Validates signature
3. Applies update
4. May require restart

**Example**:
```rust
client_node.on_update_available(|event: UpdateEvent| async move {
    if !event.verified {
        eprintln!("Update signature invalid!");
        return;
    }

    // Verify checksum
    let checksum = blake3::hash(&event.package_data);
    if checksum.as_bytes() != event.checksum.as_slice() {
        eprintln!("Checksum mismatch!");
        return;
    }

    // Apply update
    match client_node.apply_update(&event.package_data).await {
        Ok(_) => println!("✓ Update applied successfully"),
        Err(e) => eprintln!("✗ Update failed: {}", e),
    }
}).await?;
```

## Multi-Signature Verification

Require multiple authorities to sign content.

```rust
impl Node {
    pub async fn set_multi_sig_threshold(&self, threshold: usize) -> Result<(), Error>
}
```

**Example**:
```rust
// Require 2 out of 3 authorities to sign
client_node.add_authority(authority1, "Authority 1".to_string(), TrustLevel::UpdateAuthority).await?;
client_node.add_authority(authority2, "Authority 2".to_string(), TrustLevel::UpdateAuthority).await?;
client_node.add_authority(authority3, "Authority 3".to_string(), TrustLevel::UpdateAuthority).await?;

client_node.set_multi_sig_threshold(2).await?;

// Updates must be signed by at least 2 of the 3 authorities
```

**Verification**:
```rust
client_node.on_update_available(|event: UpdateEvent| async move {
    if event.verified && event.signature_count >= 2 {
        println!("✓ Update verified by {} authorities", event.signature_count);
        // Safe to apply
    } else {
        println!("✗ Insufficient signatures ({}/2)", event.signature_count);
    }
}).await?;
```

## Querying Authorities

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

**Example**:
```rust
let query = b"GET_LATEST_VERSION";

let response = client_node.query_authority(
    &authority_key,
    query,
    Duration::from_secs(30),
).await?;

let version = String::from_utf8(response)?;
println!("Latest version: {}", version);
```

### Structured Queries

```rust
#[derive(Serialize, Deserialize)]
struct VersionQuery {
    platform: String,
    current_version: String,
}

let query = VersionQuery {
    platform: "linux-x86_64".to_string(),
    current_version: "1.9.0".to_string(),
};

let query_bytes = serde_json::to_vec(&query)?;

let response = client_node.query_authority(
    &authority_key,
    &query_bytes,
    Duration::from_secs(30),
).await?;

let update_info: UpdateInfo = serde_json::from_slice(&response)?;
```

## Authority Discovery

### find_authorities

Discover authorities on the network.

```rust
impl Node {
    pub async fn find_authorities(&self) -> Result<Vec<AuthorityAdvertisement>, Error>
}

pub struct AuthorityAdvertisement {
    pub public_key: PublicKey,
    pub identifier: String,
    pub services: Vec<String>,
    pub proof_of_work: Option<Vec<u8>>,
}
```

**Example**:
```rust
let authorities = client_node.find_authorities().await?;

for authority in authorities {
    println!("Found authority: {} ({})",
             authority.identifier,
             authority.public_key.to_hex());

    println!("Services: {}", authority.services.join(", "));

    // Optionally trust this authority
    if user_trusts(&authority) {
        client_node.add_authority(
            authority.public_key,
            authority.identifier,
            TrustLevel::UpdateAuthority,
        ).await?;
    }
}
```

## Update Package Format

Recommended structure for update packages:

```
update_package.tar.gz
├── metadata.json       # Version, checksums, etc.
├── binary/
│   ├── meshara         # Main binary
│   └── libmeshara.so   # Libraries
├── config/
│   └── default.toml    # Default configuration
└── migration.sql       # Database migrations (if applicable)
```

**metadata.json**:
```json
{
  "version": "2.0.0",
  "release_date": "2024-01-15T10:30:00Z",
  "checksums": {
    "meshara": "blake3:7f3a2b1c...",
    "libmeshara.so": "blake3:9d4c1e..."
  },
  "platform": "linux-x86_64",
  "required_version": "1.9.0"
}
```

## Security Best Practices

### For Authority Nodes

1. **Secure key storage**: Use hardware security modules (HSM) or secure enclaves

2. **Air-gapped signing**: Sign updates on offline machine, transfer signatures only

3. **Multi-signature**: Require multiple keys to sign critical updates

4. **Audit logging**: Log all signing operations

5. **Key rotation**: Periodically rotate signing keys with migration period

**Example: Air-gapped signing**:
```rust
// On secure offline machine
let authority_key = load_from_hsm()?;
let update_hash = blake3::hash(&update_package);

let signature = authority_key.sign(update_hash.as_bytes());

// Transfer signature to online machine
std::fs::write("signature.bin", signature.to_bytes())?;

// On online machine
let signature = Signature::from_bytes(&std::fs::read("signature.bin")?)?;
publish_update_with_signature(&update_package, signature).await?;
```

### For Clients

1. **Pin authority keys**: Include in application at build time

2. **Verify checksums**: Always verify package checksums

3. **Multi-sig verification**: Require multiple authorities for critical updates

4. **Gradual rollout**: Don't auto-install on critical systems

5. **Backup before update**: Create restore point

**Example: Pinned authorities**:
```rust
const OFFICIAL_AUTHORITY: &str = "7f3a2b1c...";  // Hardcoded at compile time

let authority_key = PublicKey::from_hex(OFFICIAL_AUTHORITY)?;

let node = NodeBuilder::new()
    .with_authority_keys(vec![authority_key])
    .build()
    .await?;

// Cannot be modified at runtime
```

## Performance Considerations

**Update propagation time**:
- 100 nodes: ~2 seconds
- 1,000 nodes: ~5 seconds
- 10,000 nodes: ~10 seconds

**Query latency**:
- Direct connection: 50-200ms
- Via bridges: 200-500ms
- Via onion: 500-1000ms

**Signature verification**: ~0.05ms per signature

**Throughput**: Authority can publish ~100 updates/second

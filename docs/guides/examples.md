# Examples

Complete, production-ready examples demonstrating Meshara's capabilities.

## Simple Secure Messaging

Two-node encrypted messaging with minimal code.

```rust
use meshara::{Node, NodeBuilder, MessageEvent};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Alice's node
    let alice = NodeBuilder::new()
        .with_storage_path("./alice")
        .with_listen_port(8443)
        .build()
        .await?;

    // Bob's node
    let bob = NodeBuilder::new()
        .with_storage_path("./bob")
        .with_listen_port(8444)
        .build()
        .await?;

    alice.start().await?;
    bob.start().await?;

    println!("Alice: {}", alice.public_key().to_hex());
    println!("Bob: {}", bob.public_key().to_hex());

    // Bob receives messages
    bob.on_message_received(|event: MessageEvent| async move {
        println!("Bob got: {}", String::from_utf8_lossy(&event.content));
    }).await?;

    // Connect Alice to Bob
    alice.add_peer("127.0.0.1:8444".parse()?, Some(bob.public_key())).await?;

    // Alice sends to Bob
    alice.send_private_message(&bob.public_key(), b"Hello, Bob!").await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    alice.stop().await?;
    bob.stop().await?;

    Ok(())
}
```

## Decentralized Chat Application

Full-featured group chat with command-line interface.

```rust
use meshara::{Node, NodeBuilder, MessageEvent, PeerEvent};
use std::io::{self, Write};
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    let username = args.get(1).cloned().unwrap_or_else(|| "anonymous".to_string());
    let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(8443);

    // Create node
    let node = NodeBuilder::new()
        .with_storage_path(format!("./chat_{}", username))
        .with_listen_port(port)
        .enable_auto_discovery()
        .build()
        .await?;

    node.start().await?;

    println!("╔══════════════════════════════════════════════════════╗");
    println!("║         Meshara Decentralized Chat v1.0            ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();
    println!("Username: {}", username);
    println!("Node ID: {}", node.node_id());
    println!("Public Key: {}", node.public_key().to_hex());
    println!("Listening on: 0.0.0.0:{}", port);
    println!();

    // Track online users
    let users = std::sync::Arc::new(tokio::sync::RwLock::new(
        std::collections::HashMap::<PublicKey, String>::new()
    ));

    // Receive messages
    {
        let users = users.clone();
        node.on_message_received(move |event: MessageEvent| {
            let users = users.clone();
            async move {
                let content = String::from_utf8_lossy(&event.content);

                // Parse message format: "username: message"
                if let Some((sender_name, message)) = content.split_once(": ") {
                    // Store username mapping
                    users.write().await.insert(event.sender.clone(), sender_name.to_string());

                    println!("\r[{}] {}", sender_name, message);
                } else {
                    // Fallback for messages without username
                    let sender_short = &event.sender.to_hex()[..8];
                    println!("\r[{}...] {}", sender_short, content);
                }

                print!("> ");
                io::stdout().flush().unwrap();
            }
        }).await?;
    }

    // Peer connection events
    {
        let users = users.clone();
        node.on_peer_connected(move |event: PeerEvent| {
            let users = users.clone();
            async move {
                let user = users.read().await
                    .get(&event.public_key)
                    .cloned()
                    .unwrap_or_else(|| format!("{}...", &event.peer_id.to_hex()[..8]));

                println!("\r✓ {} connected", user);
                print!("> ");
                io::stdout().flush().unwrap();
            }
        }).await?;
    }

    {
        let users = users.clone();
        node.on_peer_disconnected(move |event: PeerEvent| {
            let users = users.clone();
            async move {
                let user = users.read().await
                    .get(&event.public_key)
                    .cloned()
                    .unwrap_or_else(|| format!("{}...", &event.peer_id.to_hex()[..8]));

                println!("\r✗ {} disconnected", user);
                print!("> ");
                io::stdout().flush().unwrap();
            }
        }).await?;
    }

    println!("Commands:");
    println!("  /connect <ip:port>  - Connect to peer");
    println!("  /peers              - List connected peers");
    println!("  /quit               - Exit");
    println!("  <message>           - Send message to all");
    println!();

    // Read user input
    let stdin = tokio::io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    print!("> ");
    io::stdout().flush()?;

    while let Some(line) = lines.next_line().await? {
        let line = line.trim();

        if line.starts_with('/') {
            // Handle commands
            let parts: Vec<&str> = line.splitn(2, ' ').collect();

            match parts[0] {
                "/connect" => {
                    if parts.len() < 2 {
                        println!("Usage: /connect <ip:port>");
                    } else {
                        match parts[1].parse() {
                            Ok(addr) => {
                                match node.add_peer(addr, None).await {
                                    Ok(peer_id) => println!("✓ Connected to {}", peer_id),
                                    Err(e) => println!("✗ Connection failed: {}", e),
                                }
                            }
                            Err(e) => println!("✗ Invalid address: {}", e),
                        }
                    }
                }

                "/peers" => {
                    let peers = node.list_peers().await?;
                    println!("Connected peers: {}", peers.len());

                    let users_lock = users.read().await;
                    for peer in peers {
                        let user = users_lock
                            .get(&peer.public_key)
                            .cloned()
                            .unwrap_or_else(|| "unknown".to_string());

                        println!("  {} - {} ({})", user, peer.peer_id, peer.address);
                    }
                }

                "/quit" => {
                    println!("Shutting down...");
                    node.stop().await?;
                    break;
                }

                _ => {
                    println!("Unknown command. Available: /connect /peers /quit");
                }
            }
        } else if !line.is_empty() {
            // Send message to all peers
            let message = format!("{}: {}", username, line);

            match node.broadcast_message(message.as_bytes()).await {
                Ok(_) => {}  // Success
                Err(e) => println!("✗ Send failed: {}", e),
            }
        }

        print!("> ");
        io::stdout().flush()?;
    }

    Ok(())
}
```

**Usage**:
```bash
# Terminal 1
cargo run --example chat Alice 8443

# Terminal 2
cargo run --example chat Bob 8444

# In Bob's terminal
/connect 127.0.0.1:8443

# Type messages in either terminal
```

## Software Update Distribution

Authority node publishing signed updates, clients receiving and verifying.

### Authority Node

```rust
use meshara::{Node, NodeBuilder, NetworkProfile};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Create authority node with stable identity
    let authority = NodeBuilder::new()
        .with_storage_path("/var/lib/meshara-authority")
        .with_listen_port(443)
        .with_network_profile(NetworkProfile::Authority)
        .enable_authority_mode()
        .build()
        .await?;

    authority.start().await?;

    println!("Authority node started");
    println!("Public key: {}", authority.public_key().to_hex());
    println!("Share this key with clients!");
    println!();

    // Publish updates when ready
    loop {
        println!("Enter update version (or 'quit'):");
        let mut version = String::new();
        std::io::stdin().read_line(&mut version)?;
        let version = version.trim();

        if version == "quit" {
            break;
        }

        println!("Enter changelog:");
        let mut changelog = String::new();
        std::io::stdin().read_line(&mut changelog)?;

        println!("Enter path to update package:");
        let mut path = String::new();
        std::io::stdin().read_line(&mut path)?;
        let path = path.trim();

        // Read update package
        let package_data = std::fs::read(path)?;

        // Publish update
        match authority.publish_update(version, package_data, changelog.trim()).await {
            Ok(msg_id) => {
                println!("✓ Update published: {}", msg_id);
                println!("Broadcasting to network...");
            }
            Err(e) => {
                println!("✗ Failed to publish: {}", e);
            }
        }
    }

    authority.stop().await?;

    Ok(())
}
```

### Client Node

```rust
use meshara::{Node, NodeBuilder, UpdateEvent, PublicKey};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Authority's public key (from authority node output)
    let authority_pubkey = PublicKey::from_hex(
        std::env::var("AUTHORITY_KEY")
            .expect("Set AUTHORITY_KEY environment variable")
    )?;

    // Create client node
    let client = NodeBuilder::new()
        .with_storage_path("./client_data")
        .with_listen_port(8443)
        .with_authority_keys(vec![authority_pubkey.clone()])
        .with_bootstrap_nodes(vec!["authority.example.com:443".parse()?])
        .enable_auto_update()
        .with_update_check_interval(tokio::time::Duration::from_secs(3600))  // Check hourly
        .build()
        .await?;

    client.start().await?;

    println!("Client node started");
    println!("Trusted authority: {}", authority_pubkey.to_hex());
    println!("Listening for updates...");
    println!();

    // Handle update notifications
    client.on_update_available(|event: UpdateEvent| async move {
        if !event.verified {
            println!("⚠ Warning: Update signature invalid!");
            return;
        }

        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("📦 Update Available!");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Version: {}", event.version);
        println!("Size: {} bytes", event.package_data.len());
        println!("Changelog:");
        println!("{}", event.changelog);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        // Verify checksum
        let computed_checksum = blake3::hash(&event.package_data);
        if computed_checksum.as_bytes() != event.checksum.as_slice() {
            println!("✗ Checksum mismatch! Update corrupted.");
            return;
        }

        println!("✓ Checksum verified");

        // Save update package
        let filename = format!("update_{}.bin", event.version);
        if let Err(e) = std::fs::write(&filename, &event.package_data) {
            println!("✗ Failed to save update: {}", e);
            return;
        }

        println!("✓ Update saved to: {}", filename);
        println!();
        println!("Apply update? (y/n)");

        let mut response = String::new();
        if std::io::stdin().read_line(&mut response).is_ok() {
            if response.trim().to_lowercase() == "y" {
                println!("Applying update...");
                apply_update(&event.package_data).await;
                println!("✓ Update applied successfully!");
            } else {
                println!("Update deferred.");
            }
        }
    }).await?;

    // Keep running
    tokio::signal::ctrl_c().await?;

    client.stop().await?;

    Ok(())
}

async fn apply_update(package_data: &[u8]) {
    // Implementation depends on your update mechanism
    // Examples:
    // - Extract and replace binary
    // - Apply configuration changes
    // - Database migrations
    // - etc.

    println!("Update package size: {} bytes", package_data.len());
    // ... actual update logic ...
}
```

## Private Messaging App

End-to-end encrypted messaging with contact list.

```rust
use meshara::{Node, NodeBuilder, MessageEvent, PublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;

#[derive(Serialize, Deserialize, Clone)]
struct Contact {
    name: String,
    public_key: PublicKey,
    last_seen: Option<u64>,
}

struct MessagingApp {
    node: Node,
    contacts: HashMap<String, Contact>,
    message_history: Vec<(String, String, u64)>,  // (from, message, timestamp)
}

impl MessagingApp {
    async fn new(username: &str) -> Result<Self, Box<dyn Error>> {
        let node = NodeBuilder::new()
            .with_storage_path(format!("./messaging_{}", username))
            .with_listen_port(0)  // Random port
            .enable_auto_discovery()
            .build()
            .await?;

        node.start().await?;

        // Load contacts
        let contacts = Self::load_contacts(username)?;

        Ok(Self {
            node,
            contacts,
            message_history: Vec::new(),
        })
    }

    fn load_contacts(username: &str) -> Result<HashMap<String, Contact>, Box<dyn Error>> {
        let path = format!("./messaging_{}/contacts.json", username);

        if std::path::Path::new(&path).exists() {
            let data = std::fs::read_to_string(&path)?;
            Ok(serde_json::from_str(&data)?)
        } else {
            Ok(HashMap::new())
        }
    }

    fn save_contacts(&self, username: &str) -> Result<(), Box<dyn Error>> {
        let path = format!("./messaging_{}/contacts.json", username);
        let data = serde_json::to_string_pretty(&self.contacts)?;
        std::fs::write(&path, data)?;
        Ok(())
    }

    async fn add_contact(&mut self, name: String, public_key: PublicKey) {
        self.contacts.insert(name.clone(), Contact {
            name,
            public_key,
            last_seen: None,
        });
    }

    async fn send_message(&self, contact_name: &str, message: &str) -> Result<(), Box<dyn Error>> {
        let contact = self.contacts.get(contact_name)
            .ok_or("Contact not found")?;

        self.node.send_private_message(&contact.public_key, message.as_bytes()).await?;

        Ok(())
    }

    async fn list_contacts(&self) {
        println!("Contacts:");
        for (name, contact) in &self.contacts {
            println!("  {} - {}", name, contact.public_key.to_hex());
        }
    }

    async fn run(&mut self, username: String) -> Result<(), Box<dyn Error>> {
        println!("Messaging App - User: {}", username);
        println!("Your public key: {}", self.node.public_key().to_hex());
        println!();

        // Setup message receiver
        let history = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let contacts = std::sync::Arc::new(tokio::sync::RwLock::new(self.contacts.clone()));

        {
            let history = history.clone();
            let contacts = contacts.clone();

            self.node.on_message_received(move |event: MessageEvent| {
                let history = history.clone();
                let contacts = contacts.clone();

                async move {
                    let message = String::from_utf8_lossy(&event.content).to_string();

                    // Find sender in contacts
                    let sender_name = {
                        let contacts_lock = contacts.read().await;
                        contacts_lock.iter()
                            .find(|(_, c)| c.public_key == event.sender)
                            .map(|(name, _)| name.clone())
                            .unwrap_or_else(|| format!("{}...", &event.sender.to_hex()[..8]))
                    };

                    // Store in history
                    history.lock().await.push((sender_name.clone(), message.clone(), event.timestamp));

                    println!("\r[{}]: {}", sender_name, message);
                    print!("> ");
                    std::io::stdout().flush().unwrap();
                }
            }).await?;
        }

        // Command loop
        let stdin = std::io::stdin();
        loop {
            print!("> ");
            std::io::stdout().flush()?;

            let mut line = String::new();
            stdin.read_line(&mut line)?;
            let line = line.trim();

            let parts: Vec<&str> = line.splitn(2, ' ').collect();

            match parts[0] {
                "/add" => {
                    if parts.len() < 2 {
                        println!("Usage: /add <name> <public_key>");
                        continue;
                    }

                    let subparts: Vec<&str> = parts[1].splitn(2, ' ').collect();
                    if subparts.len() < 2 {
                        println!("Usage: /add <name> <public_key>");
                        continue;
                    }

                    let name = subparts[0].to_string();
                    match PublicKey::from_hex(subparts[1]) {
                        Ok(pubkey) => {
                            self.add_contact(name.clone(), pubkey).await;
                            self.save_contacts(&username)?;
                            println!("✓ Added contact: {}", name);
                        }
                        Err(e) => println!("✗ Invalid public key: {}", e),
                    }
                }

                "/contacts" => {
                    self.list_contacts().await;
                }

                "/msg" => {
                    if parts.len() < 2 {
                        println!("Usage: /msg <contact> <message>");
                        continue;
                    }

                    let subparts: Vec<&str> = parts[1].splitn(2, ' ').collect();
                    if subparts.len() < 2 {
                        println!("Usage: /msg <contact> <message>");
                        continue;
                    }

                    let contact_name = subparts[0];
                    let message = subparts[1];

                    match self.send_message(contact_name, message).await {
                        Ok(_) => println!("✓ Sent to {}", contact_name),
                        Err(e) => println!("✗ Send failed: {}", e),
                    }
                }

                "/history" => {
                    let hist = history.lock().await;
                    println!("Message history:");
                    for (from, msg, timestamp) in hist.iter() {
                        println!("[{}] {}: {}", timestamp, from, msg);
                    }
                }

                "/quit" => {
                    self.node.stop().await?;
                    break;
                }

                _ => {
                    println!("Commands: /add /contacts /msg /history /quit");
                }
            }
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let username = std::env::args().nth(1).unwrap_or_else(|| "user".to_string());

    let mut app = MessagingApp::new(&username).await?;
    app.run(username).await?;

    Ok(())
}
```

## IoT Device Communication

Lightweight node for resource-constrained devices.

```rust
use meshara::{Node, NodeBuilder, NetworkProfile, MessageEvent};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Minimal configuration for IoT device
    let device = NodeBuilder::new()
        .with_storage_path("/data/meshara")
        .with_listen_port(8443)
        .with_network_profile(NetworkProfile::Minimal)
        .with_max_peers(3)  // Very low peer count
        .with_bootstrap_nodes(vec![
            "gateway.local:443".parse()?,  // Local gateway
        ])
        .build()
        .await?;

    device.start().await?;

    println!("IoT Device Online");
    println!("Device ID: {}", device.node_id());

    // Send sensor data periodically
    let gateway_key = get_gateway_public_key()?;

    loop {
        // Read sensor data
        let temperature = read_temperature_sensor()?;
        let humidity = read_humidity_sensor()?;

        // Create JSON payload
        let payload = serde_json::json!({
            "device_id": device.node_id().to_hex(),
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            "temperature": temperature,
            "humidity": humidity,
        });

        // Send to gateway
        device.send_private_message(&gateway_key, payload.to_string().as_bytes())
            .await?;

        // Sleep for 60 seconds
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    }
}

fn get_gateway_public_key() -> Result<PublicKey, Box<dyn Error>> {
    // Load from configuration
    let key_hex = std::fs::read_to_string("/data/gateway.key")?;
    Ok(PublicKey::from_hex(key_hex.trim())?)
}

fn read_temperature_sensor() -> Result<f32, Box<dyn Error>> {
    // Mock implementation - replace with actual sensor reading
    Ok(22.5)
}

fn read_humidity_sensor() -> Result<f32, Box<dyn Error>> {
    // Mock implementation
    Ok(45.0)
}
```

These examples demonstrate real-world Meshara applications covering messaging, updates, IoT, and more. Each example is complete and can be adapted for production use.

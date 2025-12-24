//! Alice - Simple messaging example
//!
//! This binary demonstrates basic encrypted messaging with Meshara.
//! Alice sends a message to Bob and waits for a response.

use anyhow::Result;
use clap::Parser;
use meshara::{Event, NodeBuilder, PublicKey};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

#[derive(Parser, Debug)]
#[command(author, version, about = "Alice - Simple Meshara messaging example", long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value = "9000")]
    port: u16,

    /// Bob's public key (hex-encoded, 64 bytes for Ed25519)
    #[arg(short, long)]
    bob_pubkey: Option<String>,

    /// Storage directory for keys
    #[arg(short, long)]
    storage: Option<PathBuf>,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("meshara_simple_messaging={},meshara={}", log_level, log_level))
        .init();

    // Setup storage directory
    let storage_path = args.storage.unwrap_or_else(|| {
        let mut path = std::env::temp_dir();
        path.push("meshara_alice");
        path
    });

    info!("Alice starting...");
    info!("Storage directory: {}", storage_path.display());

    // Build and start node
    let mut node = NodeBuilder::new()
        .with_storage_path(storage_path.to_str().unwrap())
        .with_listen_port(args.port)
        .build()?;

    // Track received messages
    let received_messages = Arc::new(Mutex::new(Vec::new()));
    let received_clone = Arc::clone(&received_messages);

    // Register event handler
    node.on_event(move |event| {
        if let Event::MessageReceived {
            sender, content, ..
        } = event
        {
            let msg = String::from_utf8_lossy(&content).to_string();
            info!("📨 Received from {}: {}", sender.fingerprint(), msg);

            let received_clone = Arc::clone(&received_clone);
            tokio::spawn(async move {
                received_clone.lock().await.push(msg);
            });
        }
    });

    node.start().await?;

    let listen_addr = node.listen_address().unwrap();
    let my_pubkey = node.public_key();

    println!("════════════════════════════════════════════════════════════");
    println!("Alice's Node");
    println!("════════════════════════════════════════════════════════════");
    println!("Listening on:  {}", listen_addr);
    println!("Node ID:       {}", node.node_id().to_hex());
    println!("Public Key:    {}", hex::encode(my_pubkey.to_bytes()));
    println!("════════════════════════════════════════════════════════════");
    println!();

    // If Bob's public key is provided, send a message
    if let Some(bob_pubkey_hex) = args.bob_pubkey {
        // Decode Bob's public key
        let bob_key_bytes = hex::decode(&bob_pubkey_hex)?;
        if bob_key_bytes.len() != 64 {
            anyhow::bail!("Invalid public key length: expected 64 bytes, got {}", bob_key_bytes.len());
        }
        let mut key_array = [0u8; 64];
        key_array.copy_from_slice(&bob_key_bytes);
        let bob_pubkey = PublicKey::from_bytes(&key_array)?;

        info!("Sending message to Bob...");
        let message = "Hello Bob! This is Alice. 👋";
        let message_id = node.send_private_message(&bob_pubkey, message.as_bytes()).await?;

        println!("✅ Sent message to Bob");
        println!("   Message ID: {}", message_id.to_hex());
        println!("   Content: {}", message);
        println!();
    } else {
        println!("💡 To send a message to Bob, restart with:");
        println!("   cargo run --bin alice -- --bob-pubkey <BOB_PUBLIC_KEY>");
        println!();
    }

    println!("Waiting for messages... (Press Ctrl+C to exit)");
    println!();

    // Keep running and display received messages
    let mut last_count = 0;
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let messages = received_messages.lock().await;
        if messages.len() > last_count {
            for msg in messages.iter().skip(last_count) {
                println!("📬 Message: {}", msg);
            }
            last_count = messages.len();
        }
    }
}

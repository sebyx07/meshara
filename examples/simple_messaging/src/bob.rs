//! Bob - Simple messaging example
//!
//! This binary demonstrates basic encrypted messaging with Meshara.
//! Bob waits for messages from Alice and responds.

use anyhow::Result;
use clap::Parser;
use meshara::{Event, NodeBuilder};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

#[derive(Parser, Debug)]
#[command(author, version, about = "Bob - Simple Meshara messaging example", long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value = "9001")]
    port: u16,

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
        path.push("meshara_bob");
        path
    });

    info!("Bob starting...");
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
    println!("Bob's Node");
    println!("════════════════════════════════════════════════════════════");
    println!("Listening on:  {}", listen_addr);
    println!("Node ID:       {}", node.node_id().to_hex());
    println!("Public Key:    {}", hex::encode(my_pubkey.to_bytes()));
    println!("════════════════════════════════════════════════════════════");
    println!();
    println!("💡 Alice can send messages to Bob using this public key:");
    println!("   cargo run --bin alice -- --bob-pubkey {}", hex::encode(my_pubkey.to_bytes()));
    println!();
    println!("Waiting for messages from Alice... (Press Ctrl+C to exit)");
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

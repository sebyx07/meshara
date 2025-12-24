//! Meshara Chat - A terminal-based decentralized chat application
//!
//! This application demonstrates the full capabilities of the Meshara library:
//! - Encrypted peer-to-peer messaging
//! - Group broadcast messages
//! - Peer discovery
//! - Event-driven architecture
//! - Terminal UI with message history

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event as TermEvent, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use meshara::{Event, Node, NodeBuilder, NodeId};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Terminal,
};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

mod chat;
mod ui;

use chat::ChatApp;

/// Meshara Chat - Decentralized encrypted chat application
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Your username in the chat
    #[arg(short, long)]
    username: String,

    /// Port to listen on
    #[arg(short, long, default_value = "0")]
    port: u16,

    /// Bootstrap peer address (format: node_id@host:port)
    #[arg(short, long)]
    bootstrap: Option<String>,

    /// Storage directory for node data
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
        .with_env_filter(format!("meshara_chat={},meshara={}", log_level, log_level))
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();

    info!("Starting Meshara Chat as user: {}", args.username);

    // Determine storage path
    let storage_path = args.storage.unwrap_or_else(|| {
        let dirs = directories::ProjectDirs::from("com", "meshara", "chat")
            .expect("Could not determine config directory");
        let base_dir = dirs.data_dir();
        base_dir.join(&args.username)
    });

    info!("Using storage path: {}", storage_path.display());

    // Build and start the node
    let mut node = NodeBuilder::new()
        .with_storage_path(storage_path.to_str().unwrap())
        .build()
        .context("Failed to create node")?;

    info!("Node created with ID: {}", node.node_id().to_hex());

    // Start the node
    node.start()
        .await
        .context("Failed to start node")?;

    let listen_addr = node.listen_address().unwrap();
    info!("Node started successfully on {}", listen_addr);
    println!("Listening on: {}", listen_addr);
    println!("Node ID: {}", node.node_id().to_hex());

    // Bootstrap to a peer if specified
    if let Some(ref bootstrap_addr) = args.bootstrap {
        info!("Bootstrapping to peer: {}", bootstrap_addr);
        // Parse bootstrap address: node_id@host:port
        // For now, we'll handle this in the chat app
    }

    // Create the chat application
    let chat_app = Arc::new(RwLock::new(ChatApp::new(
        node,
        args.username,
        args.bootstrap,
    )));

    // Run the terminal UI
    run_ui(chat_app).await?;

    Ok(())
}

/// Run the terminal user interface
async fn run_ui(chat_app: Arc<RwLock<ChatApp>>) -> Result<()> {
    // Setup terminal
    enable_raw_mode().context("Failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .context("Failed to setup terminal")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("Failed to create terminal")?;

    // Start the event loop
    let result = run_app(&mut terminal, chat_app).await;

    // Restore terminal
    disable_raw_mode().context("Failed to disable raw mode")?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .context("Failed to restore terminal")?;
    terminal.show_cursor().context("Failed to show cursor")?;

    // Propagate any errors
    result?;

    Ok(())
}

/// Main application loop
async fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    chat_app: Arc<RwLock<ChatApp>>,
) -> Result<()> {
    loop {
        // Draw UI
        {
            let app = chat_app.read().await;
            terminal.draw(|f| ui::draw(f, &app))?;
        }

        // Handle input with timeout
        if event::poll(std::time::Duration::from_millis(100))? {
            if let TermEvent::Key(key) = event::read()? {
                let mut app = chat_app.write().await;

                match key.code {
                    KeyCode::Char('q') if app.input_mode == ui::InputMode::Normal => {
                        // Quit
                        return Ok(());
                    }
                    KeyCode::Char('i') if app.input_mode == ui::InputMode::Normal => {
                        // Enter insert mode
                        app.input_mode = ui::InputMode::Editing;
                    }
                    KeyCode::Esc if app.input_mode == ui::InputMode::Editing => {
                        // Exit insert mode
                        app.input_mode = ui::InputMode::Normal;
                    }
                    KeyCode::Enter if app.input_mode == ui::InputMode::Editing => {
                        // Send message
                        app.send_message().await?;
                    }
                    KeyCode::Char(c) if app.input_mode == ui::InputMode::Editing => {
                        // Add character to input
                        app.input.push(c);
                    }
                    KeyCode::Backspace if app.input_mode == ui::InputMode::Editing => {
                        // Remove character
                        app.input.pop();
                    }
                    KeyCode::Up if app.input_mode == ui::InputMode::Normal => {
                        // Scroll messages up
                        app.scroll_up();
                    }
                    KeyCode::Down if app.input_mode == ui::InputMode::Normal => {
                        // Scroll messages down
                        app.scroll_down();
                    }
                    KeyCode::Char('p') if app.input_mode == ui::InputMode::Normal => {
                        // Show peers
                        app.show_peers().await;
                    }
                    KeyCode::Char('h') if app.input_mode == ui::InputMode::Normal => {
                        // Show help
                        app.show_help();
                    }
                    _ => {}
                }
            }
        }

        // Process any pending events from the node
        {
            let mut app = chat_app.write().await;
            app.process_events().await?;
        }
    }
}

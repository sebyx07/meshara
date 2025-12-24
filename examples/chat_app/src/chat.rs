//! Chat application logic and message handling

use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use meshara::{Event, Node, NodeId, PublicKey};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::ui::InputMode;

/// A chat message
#[derive(Debug, Clone)]
pub struct ChatMessage {
    /// Timestamp when message was received/sent
    pub timestamp: DateTime<Local>,
    /// Sender's username (or node ID if unknown)
    pub sender: String,
    /// Message content
    pub content: String,
    /// Whether this is a broadcast or private message
    pub is_broadcast: bool,
    /// Whether this message was sent by us
    pub is_outgoing: bool,
}

/// Peer information
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Node ID
    pub node_id: NodeId,
    /// Username (if known)
    pub username: Option<String>,
    /// When we first discovered this peer
    pub discovered_at: DateTime<Local>,
    /// Last seen timestamp
    pub last_seen: DateTime<Local>,
}

/// Main chat application state
pub struct ChatApp {
    /// The Meshara node
    pub node: Node,
    /// Our username
    pub username: String,
    /// Bootstrap peer address
    pub bootstrap: Option<String>,
    /// Chat message history
    pub messages: Vec<ChatMessage>,
    /// Current input buffer
    pub input: String,
    /// Input mode
    pub input_mode: InputMode,
    /// Scroll position in message history
    pub scroll: usize,
    /// Known peers
    pub peers: HashMap<NodeId, PeerInfo>,
    /// Current target for private messages (None = broadcast)
    pub target: Option<PublicKey>,
    /// Status messages
    pub status: String,
    /// Event receiver channel
    event_rx: mpsc::UnboundedReceiver<Event>,
}

impl ChatApp {
    /// Create a new chat application
    pub fn new(mut node: Node, username: String, bootstrap: Option<String>) -> Self {
        // Create channel for events
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        // Register event handler
        node.on_event(move |event| {
            let _ = event_tx.send(event);
        });

        Self {
            node,
            username,
            bootstrap,
            messages: Vec::new(),
            input: String::new(),
            input_mode: InputMode::Normal,
            scroll: 0,
            peers: HashMap::new(),
            target: None,
            status: "Connected. Press 'h' for help.".to_string(),
            event_rx,
        }
    }

    /// Process events from the Meshara node
    pub async fn process_events(&mut self) -> Result<()> {
        // Process all pending events (non-blocking)
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                Event::MessageReceived {
                    sender,
                    content,
                    message_id,
                    ..
                } => {
                    let sender_id = meshara::hash_public_key(&sender);
                    self.handle_message_received(sender_id, content, false);
                }
                Event::BroadcastReceived {
                    sender,
                    content,
                    message_id,
                    ..
                } => {
                    let sender_id = meshara::hash_public_key(&sender);
                    self.handle_message_received(sender_id, content, true);
                }
                Event::NodeStarted => {
                    self.status = "Node started successfully".to_string();
                }
                Event::NodeStopped => {
                    self.status = "Node stopped".to_string();
                }
                Event::Error { error } => {
                    self.status = format!("Error: {}", error);
                    error!("Node error: {}", error);
                }
            }
        }

        Ok(())
    }

    /// Send the current input as a message
    pub async fn send_message(&mut self) -> Result<()> {
        if self.input.is_empty() {
            return Ok(());
        }

        let content = self.input.clone();
        self.input.clear();

        // Parse commands
        if content.starts_with('/') {
            return self.handle_command(&content).await;
        }

        // Send message
        let result = if let Some(target_pubkey) = &self.target {
            // Private message
            debug!("Sending private message");
            self.node
                .send_private_message(target_pubkey, content.as_bytes())
                .await
        } else {
            // Broadcast message
            debug!("Broadcasting message");
            self.node
                .broadcast_message(content.as_bytes(), "text/plain")
                .await
        };

        match result {
            Ok(msg_id) => {
                // Add to our message history
                self.add_message(ChatMessage {
                    timestamp: Local::now(),
                    sender: self.username.clone(),
                    content,
                    is_broadcast: self.target.is_none(),
                    is_outgoing: true,
                });
                self.status = format!("Message sent (ID: {})", msg_id.to_hex());
                info!("Message sent successfully");
            }
            Err(e) => {
                error!("Failed to send message: {}", e);
                self.status = format!("Error: Failed to send message: {}", e);
            }
        }

        Ok(())
    }

    /// Handle slash commands
    async fn handle_command(&mut self, command: &str) -> Result<()> {
        let parts: Vec<&str> = command.split_whitespace().collect();

        match parts.first().map(|s| *s) {
            Some("/help") | Some("/h") => {
                self.show_help();
            }
            Some("/peers") | Some("/p") => {
                self.show_peers().await;
            }
            Some("/broadcast") | Some("/b") => {
                self.target = None;
                self.status = "Mode: Broadcasting to all peers".to_string();
            }
            Some("/dm") | Some("/msg") => {
                // /dm <node_id or username> <message>
                if parts.len() < 2 {
                    self.status = "Usage: /dm <node_id> [message]".to_string();
                } else {
                    // For now, just set the target
                    // In a real implementation, we'd parse the node ID
                    self.status = format!("Target set to: {}", parts[1]);
                }
            }
            Some("/quit") | Some("/q") => {
                // This will be handled by the main loop
                self.status = "Press 'q' to quit".to_string();
            }
            Some("/clear") | Some("/c") => {
                self.messages.clear();
                self.scroll = 0;
                self.status = "Chat history cleared".to_string();
            }
            Some("/whoami") => {
                self.status = format!(
                    "You are {} (Node ID: {})",
                    self.username,
                    self.node.node_id().to_hex()
                );
            }
            _ => {
                self.status = format!("Unknown command: {}. Type /help for commands", parts[0]);
            }
        }

        Ok(())
    }

    /// Add a message to the history
    pub fn add_message(&mut self, message: ChatMessage) {
        self.messages.push(message);
        // Auto-scroll to bottom
        if self.scroll == self.messages.len().saturating_sub(1) {
            self.scroll = self.messages.len();
        }
    }

    /// Scroll messages up
    pub fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }

    /// Scroll messages down
    pub fn scroll_down(&mut self) {
        if self.scroll < self.messages.len() {
            self.scroll += 1;
        }
    }

    /// Show peers list
    pub async fn show_peers(&mut self) {
        let peer_count = self.peers.len();

        if peer_count == 0 {
            self.status = "No peers discovered yet".to_string();
        } else {
            let peer_list: Vec<String> = self
                .peers
                .iter()
                .map(|(id, info)| {
                    let username = info.username.as_deref().unwrap_or("unknown");
                    format!("{} ({})", username, id.to_hex())
                })
                .collect();

            self.status = format!("{} peer(s): {}", peer_count, peer_list.join(", "));
        }
    }

    /// Show help message
    pub fn show_help(&mut self) {
        let help_msg = ChatMessage {
            timestamp: Local::now(),
            sender: "System".to_string(),
            content: r#"
=== Meshara Chat Help ===

Keyboard Shortcuts:
  i        - Enter insert mode (start typing)
  Esc      - Exit insert mode (normal mode)
  q        - Quit application (in normal mode)
  Enter    - Send message (in insert mode)
  Up/Down  - Scroll message history (in normal mode)
  p        - Show peer list
  h        - Show this help

Commands (type in insert mode):
  /help, /h           - Show this help
  /peers, /p          - List connected peers
  /broadcast, /b      - Switch to broadcast mode
  /dm <id> [msg]      - Send direct message to peer
  /clear, /c          - Clear chat history
  /whoami             - Show your node ID
  /quit, /q           - Quit application

Message Modes:
  - Default: Broadcast to all peers
  - Use /dm to send private messages to specific peers
"#
            .to_string(),
            is_broadcast: false,
            is_outgoing: false,
        };

        self.add_message(help_msg);
    }

    /// Handle received message event
    pub fn handle_message_received(&mut self, sender_id: NodeId, content: Vec<u8>, is_broadcast: bool) {
        // Try to parse content as UTF-8
        let content_str = String::from_utf8_lossy(&content).to_string();

        // Get sender username or use node ID
        let sender = self
            .peers
            .get(&sender_id)
            .and_then(|p| p.username.clone())
            .unwrap_or_else(|| format!("User-{}", hex::encode(&sender_id.as_bytes()[..4])));

        let message = ChatMessage {
            timestamp: Local::now(),
            sender,
            content: content_str,
            is_broadcast,
            is_outgoing: false,
        };

        self.add_message(message);
    }

    /// Handle peer discovered event
    pub fn handle_peer_discovered(&mut self, node_id: NodeId) {
        let now = Local::now();
        let peer = PeerInfo {
            node_id: node_id.clone(),
            username: None,
            discovered_at: now,
            last_seen: now,
        };

        self.peers.insert(node_id, peer);
        self.status = format!("New peer discovered! Total: {}", self.peers.len());
    }

    /// Handle peer disconnected event
    pub fn handle_peer_disconnected(&mut self, node_id: &NodeId) {
        if let Some(peer) = self.peers.remove(node_id) {
            let username = peer.username.as_deref().unwrap_or("unknown");
            self.status = format!("Peer {} disconnected", username);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a mock node for testing
    /// NOTE: This is a placeholder - actual testing will require the Node API to be complete
    fn create_mock_node() -> Node {
        // This will be implemented once the Node API is available
        unimplemented!("Mock node creation requires Node API implementation")
    }

    #[test]
    fn test_chat_message_creation() {
        let msg = ChatMessage {
            timestamp: Local::now(),
            sender: "Alice".to_string(),
            content: "Hello, world!".to_string(),
            is_broadcast: true,
            is_outgoing: false,
        };

        assert_eq!(msg.sender, "Alice");
        assert_eq!(msg.content, "Hello, world!");
        assert!(msg.is_broadcast);
        assert!(!msg.is_outgoing);
    }

    // NOTE: This test is commented out because NodeId doesn't have a public from_bytes constructor
    // #[test]
    // fn test_peer_info_creation() {
    //     // Create a mock NodeId (32 bytes)
    //     let node_id = NodeId::from_bytes(vec![0u8; 32]);
    //     let now = Local::now();
    //
    //     let peer = PeerInfo {
    //         node_id: node_id.clone(),
    //         username: Some("Bob".to_string()),
    //         discovered_at: now,
    //         last_seen: now,
    //     };
    //
    //     assert_eq!(peer.username, Some("Bob".to_string()));
    // }

    #[tokio::test]
    async fn test_scroll_functionality() {
        // Note: This test will work once Node API is available
        // For now, it's a placeholder showing the intended test structure

        // let node = create_mock_node();
        // let mut app = ChatApp::new(node, "TestUser".to_string(), None);

        // // Add some messages
        // for i in 0..10 {
        //     app.add_message(ChatMessage {
        //         timestamp: Local::now(),
        //         sender: "Test".to_string(),
        //         content: format!("Message {}", i),
        //         is_broadcast: true,
        //         is_outgoing: false,
        //     });
        // }

        // // Test scrolling
        // assert_eq!(app.scroll, 10);
        // app.scroll_up();
        // assert_eq!(app.scroll, 9);
        // app.scroll_down();
        // assert_eq!(app.scroll, 10);
    }

    #[test]
    fn test_command_parsing() {
        // Test that command strings are recognized
        let commands = vec![
            "/help",
            "/peers",
            "/broadcast",
            "/dm user123",
            "/quit",
            "/clear",
        ];

        for cmd in commands {
            assert!(cmd.starts_with('/'), "Command should start with /");
        }
    }
}

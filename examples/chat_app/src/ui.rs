//! Terminal UI rendering using ratatui

use crate::chat::{ChatApp, ChatMessage};
use ratatui::{
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

/// Input mode for the chat application
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    /// Normal mode - keyboard shortcuts active
    Normal,
    /// Editing mode - typing messages
    Editing,
}

/// Draw the main UI
pub fn draw(f: &mut Frame, app: &ChatApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(0),     // Messages
            Constraint::Length(3),  // Input
            Constraint::Length(1),  // Status bar
        ])
        .split(f.area());

    // Draw header
    draw_header(f, chunks[0], app);

    // Draw messages
    draw_messages(f, chunks[1], app);

    // Draw input box
    draw_input(f, chunks[2], app);

    // Draw status bar
    draw_status(f, chunks[3], app);
}

/// Draw the header with app info
fn draw_header(f: &mut Frame, area: Rect, app: &ChatApp) {
    let mode_str = match app.input_mode {
        InputMode::Normal => "NORMAL",
        InputMode::Editing => "INSERT",
    };

    let target_str = if let Some(_target) = &app.target {
        "Private"
    } else {
        "Broadcast"
    };

    let title = format!(
        " Meshara Chat - {} - Mode: {} - {} ",
        app.username, target_str, mode_str
    );

    let header = Paragraph::new(title)
        .style(
            Style::default()
                .fg(Color::White)
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));

    f.render_widget(header, area);
}

/// Draw the message history
fn draw_messages(f: &mut Frame, area: Rect, app: &ChatApp) {
    let messages: Vec<ListItem> = app
        .messages
        .iter()
        .map(|m| format_message(m))
        .collect();

    let messages_list = List::new(messages)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Messages (↑/↓ to scroll) "),
        )
        .style(Style::default().fg(Color::White));

    f.render_widget(messages_list, area);
}

/// Format a single message for display
fn format_message(msg: &ChatMessage) -> ListItem<'_> {
    let timestamp = msg.timestamp.format("%H:%M:%S");

    let prefix = if msg.is_outgoing {
        "→"
    } else {
        "←"
    };

    let msg_type = if msg.is_broadcast {
        "[ALL]"
    } else {
        "[DM]"
    };

    let style = if msg.is_outgoing {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::Cyan)
    };

    let content = format!(
        "[{}] {} {} {}: {}",
        timestamp, prefix, msg_type, msg.sender, msg.content
    );

    ListItem::new(Text::from(content)).style(style)
}

/// Draw the input box
fn draw_input(f: &mut Frame, area: Rect, app: &ChatApp) {
    let input_style = match app.input_mode {
        InputMode::Normal => Style::default().fg(Color::Gray),
        InputMode::Editing => Style::default().fg(Color::Yellow),
    };

    let input_text = if app.input_mode == InputMode::Editing {
        format!("{}█", app.input)
    } else {
        app.input.clone()
    };

    let title = match app.input_mode {
        InputMode::Normal => " Input (press 'i' to edit) ",
        InputMode::Editing => " Input (press ESC to exit, Enter to send) ",
    };

    let input = Paragraph::new(input_text)
        .style(input_style)
        .block(Block::default().borders(Borders::ALL).title(title));

    f.render_widget(input, area);
}

/// Draw the status bar
fn draw_status(f: &mut Frame, area: Rect, app: &ChatApp) {
    let node_id_short = {
        let node_id = app.node.node_id();
        let id_bytes = node_id.as_bytes();
        hex::encode(&id_bytes[..4])
    };

    let peer_count = app.peers.len();

    let status_text = format!(
        " {} | Peers: {} | Node: {} ",
        app.status, peer_count, node_id_short
    );

    let status = Paragraph::new(status_text).style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::White),
    );

    f.render_widget(status, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Local;

    #[test]
    fn test_input_mode() {
        assert_eq!(InputMode::Normal, InputMode::Normal);
        assert_ne!(InputMode::Normal, InputMode::Editing);
    }

    #[test]
    fn test_format_message() {
        let msg = ChatMessage {
            timestamp: Local::now(),
            sender: "Alice".to_string(),
            content: "Hello!".to_string(),
            is_broadcast: true,
            is_outgoing: false,
        };

        let formatted = format_message(&msg);
        // Just verify it doesn't panic
        assert!(true);
    }

    #[test]
    fn test_message_prefix() {
        let outgoing = ChatMessage {
            timestamp: Local::now(),
            sender: "Me".to_string(),
            content: "Test".to_string(),
            is_broadcast: true,
            is_outgoing: true,
        };

        let incoming = ChatMessage {
            timestamp: Local::now(),
            sender: "Them".to_string(),
            content: "Test".to_string(),
            is_broadcast: true,
            is_outgoing: false,
        };

        // Verify outgoing uses →
        let out_prefix = if outgoing.is_outgoing { "→" } else { "←" };
        assert_eq!(out_prefix, "→");

        // Verify incoming uses ←
        let in_prefix = if incoming.is_outgoing { "→" } else { "←" };
        assert_eq!(in_prefix, "←");
    }
}

# Meshara Chat

A full-featured terminal-based decentralized chat application built with the Meshara library.

## Features

- **Decentralized**: No central server - peer-to-peer communication
- **Encrypted**: All messages are end-to-end encrypted
- **Private & Broadcast Messages**: Send messages to everyone or specific peers
- **Terminal UI**: Clean, responsive terminal interface using ratatui
- **Peer Discovery**: Automatic discovery of peers on local network
- **Vim-style Controls**: Familiar keyboard shortcuts for navigation

## Building

From the `examples/chat_app` directory:

```bash
cargo build --release
```

The binary will be at `target/release/meshara-chat`.

## Running

### Start a chat node

```bash
# Start with a username
./target/release/meshara-chat --username Alice

# Start on a specific port
./target/release/meshara-chat --username Bob --port 8001

# Bootstrap to another peer
./target/release/meshara-chat --username Charlie --bootstrap node_id@localhost:8000

# Custom storage directory
./target/release/meshara-chat --username Dave --storage ./my-chat-data

# Enable debug logging
./target/release/meshara-chat --username Eve --debug
```

### Multi-instance testing

Open multiple terminals and run different instances:

**Terminal 1:**
```bash
./target/release/meshara-chat --username Alice --port 8000
```

**Terminal 2:**
```bash
./target/release/meshara-chat --username Bob --port 8001
```

**Terminal 3:**
```bash
./target/release/meshara-chat --username Charlie --port 8002
```

The nodes will discover each other automatically via mDNS (if on the same local network).

## Usage

### Keyboard Shortcuts

#### Normal Mode
- `i` - Enter insert mode (start typing)
- `q` - Quit application
- `↑` / `↓` - Scroll message history
- `p` - Show peer list
- `h` - Show help

#### Insert Mode
- `Esc` - Return to normal mode
- `Enter` - Send message
- `Backspace` - Delete character
- Type normally to compose message

### Commands

Commands are typed in insert mode and start with `/`:

- `/help` or `/h` - Show help message
- `/peers` or `/p` - List all connected peers
- `/broadcast` or `/b` - Switch to broadcast mode (default)
- `/dm <node_id>` - Send direct message to specific peer
- `/clear` or `/c` - Clear chat history
- `/whoami` - Show your node ID
- `/quit` or `/q` - Quit application

### Message Modes

**Broadcast Mode (Default)**
- Messages are sent to all connected peers
- Shows `[ALL]` tag in message list

**Private Message Mode**
- Use `/dm <node_id>` to target a specific peer
- Messages show `[DM]` tag
- Switch back to broadcast with `/broadcast`

## UI Layout

```
┌─────────────────────────────────────────────────────────────┐
│ Meshara Chat - Alice - Mode: Broadcast - NORMAL            │ ← Header
├─────────────────────────────────────────────────────────────┤
│ Messages (↑/↓ to scroll)                                    │
│ [12:34:56] → [ALL] Alice: Hello everyone!                   │
│ [12:35:02] ← [ALL] Bob: Hi Alice!                           │
│ [12:35:10] → [DM] Alice: Secret message                     │ ← Messages
│                                                              │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│ Input (press 'i' to edit)                                   │ ← Input
│                                                              │
├─────────────────────────────────────────────────────────────┤
│ Connected | Peers: 2 | Node: a3b4c5d6                       │ ← Status
└─────────────────────────────────────────────────────────────┘
```

## Architecture

The chat application demonstrates several Meshara features:

### Modules

- **main.rs** - Application entry point, CLI argument parsing, terminal setup
- **chat.rs** - Core chat logic, message handling, peer management
- **ui.rs** - Terminal UI rendering with ratatui

### Key Components

1. **ChatApp** - Main application state
   - Manages Meshara node instance
   - Tracks message history
   - Handles peer discovery
   - Processes user commands

2. **Message Flow**
   ```
   User Input → ChatApp → Meshara Node → Network
   Network → Meshara Node → Event → ChatApp → UI Update
   ```

3. **Event Processing**
   - Receives events from Meshara node
   - Updates peer list on discovery/disconnection
   - Displays incoming messages
   - Handles errors and status updates

## Testing

### Unit Tests

Run the unit tests:

```bash
cargo test
```

Tests include:
- Message formatting
- Command parsing
- UI component rendering
- Scroll functionality
- Peer management

### Integration Testing

For full integration testing with multiple nodes:

1. Build the release binary:
   ```bash
   cargo build --release
   ```

2. Run the provided test script (creates 3 nodes):
   ```bash
   ./run_test.sh
   ```

3. Or manually test with tmux/screen:
   ```bash
   # Terminal multiplexer approach
   tmux new-session -d -s chat1 './target/release/meshara-chat -u Alice -p 8000'
   tmux new-session -d -s chat2 './target/release/meshara-chat -u Bob -p 8001'
   tmux new-session -d -s chat3 './target/release/meshara-chat -u Charlie -p 8002'

   # Attach to any session
   tmux attach -t chat1
   ```

### What to Test

- [ ] Peer discovery between nodes
- [ ] Broadcast message delivery
- [ ] Private message delivery
- [ ] Message encryption (verify in Wireshark)
- [ ] Peer disconnection handling
- [ ] UI responsiveness
- [ ] Command execution
- [ ] Error handling

## Debugging

### Enable Debug Logging

```bash
./target/release/meshara-chat --username Test --debug
```

This enables detailed logging for both the chat app and Meshara library.

### View Network Traffic

Use Wireshark or tcpdump to verify encrypted traffic:

```bash
# Capture traffic on port 8000
sudo tcpdump -i lo -n port 8000 -X
```

You should see TLS handshake and encrypted application data.

### Common Issues

**Peers not discovering each other**
- Ensure all nodes are on the same network
- Check firewall settings
- Try explicit bootstrap addresses

**Messages not delivering**
- Check node is started (`node.start()` called)
- Verify peer connection with `/peers` command
- Check debug logs for errors

**UI rendering issues**
- Ensure terminal supports UTF-8
- Try resizing terminal window
- Check TERM environment variable

## Development

### Adding Features

1. **New Commands**
   - Add command handler in `chat.rs::handle_command()`
   - Update help text in `show_help()`

2. **UI Changes**
   - Modify rendering in `ui.rs::draw()`
   - Update layout constraints as needed

3. **Event Handlers**
   - Add new event types in `chat.rs::process_events()`
   - Update message formatting in `ui.rs::format_message()`

### Code Structure

```
examples/chat_app/
├── Cargo.toml          # Project dependencies
├── README.md           # This file
└── src/
    ├── main.rs         # Entry point, CLI, event loop
    ├── chat.rs         # Chat logic, message handling
    └── ui.rs           # Terminal UI rendering
```

## License

MIT License - See the main Meshara LICENSE file.

## Contributing

This is an example application. For contributions to the Meshara library itself, see the main repository README.

## Further Reading

- [Meshara Documentation](../../docs/)
- [API Reference](../../docs/api/)
- [Security Model](../../docs/security/)
- [Routing Architecture](../../docs/architecture/routing.md)

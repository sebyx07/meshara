#!/bin/bash
# Test script for running multiple Meshara Chat instances

set -e

echo "Building Meshara Chat..."
cargo build --release

echo ""
echo "========================================="
echo "Meshara Chat - Multi-Instance Test"
echo "========================================="
echo ""
echo "This script will help you test the chat app with multiple instances."
echo ""
echo "Instructions:"
echo "  1. Open 3 separate terminal windows"
echo "  2. In each terminal, run one of the following commands:"
echo ""
echo "Terminal 1 (Alice):"
echo "  cd $(pwd)"
echo "  ./target/release/meshara-chat --username Alice --port 8000 --debug"
echo ""
echo "Terminal 2 (Bob):"
echo "  cd $(pwd)"
echo "  ./target/release/meshara-chat --username Bob --port 8001 --debug"
echo ""
echo "Terminal 3 (Charlie):"
echo "  cd $(pwd)"
echo "  ./target/release/meshara-chat --username Charlie --port 8002 --debug"
echo ""
echo "========================================="
echo ""
echo "The nodes should discover each other via mDNS (if on same network)."
echo "You can also manually connect them if needed."
echo ""
echo "Press Enter to see a quick demo (requires tmux)..."
read

if ! command -v tmux &> /dev/null; then
    echo "tmux not found. Please install tmux or run the instances manually."
    exit 1
fi

echo "Starting 3 chat instances in tmux sessions..."
echo ""

# Start first instance
tmux new-session -d -s meshara-alice "./target/release/meshara-chat --username Alice --port 8000 --debug"
echo "✓ Started Alice on port 8000 (tmux session: meshara-alice)"

# Small delay
sleep 1

# Start second instance
tmux new-session -d -s meshara-bob "./target/release/meshara-chat --username Bob --port 8001 --debug"
echo "✓ Started Bob on port 8001 (tmux session: meshara-bob)"

# Small delay
sleep 1

# Start third instance
tmux new-session -d -s meshara-charlie "./target/release/meshara-chat --username Charlie --port 8002 --debug"
echo "✓ Started Charlie on port 8002 (tmux session: meshara-charlie)"

echo ""
echo "All instances started!"
echo ""
echo "To attach to a session:"
echo "  tmux attach -t meshara-alice"
echo "  tmux attach -t meshara-bob"
echo "  tmux attach -t meshara-charlie"
echo ""
echo "To switch between sessions:"
echo "  Ctrl+B, then D (detach)"
echo "  tmux attach -t <session-name>"
echo ""
echo "To kill all sessions:"
echo "  tmux kill-session -t meshara-alice"
echo "  tmux kill-session -t meshara-bob"
echo "  tmux kill-session -t meshara-charlie"
echo ""

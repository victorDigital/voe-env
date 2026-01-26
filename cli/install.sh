#!/bin/bash

# Installation script for VOE CLI
# This script builds and installs the CLI as 've' command

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🔨 Building VOE CLI..."
cargo build --release

if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi

BINARY_PATH="$SCRIPT_DIR/target/release/ve"
INSTALL_PATH="/usr/local/bin/ve"

# Check if binary exists
if [ ! -f "$BINARY_PATH" ]; then
    echo "❌ Binary not found at $BINARY_PATH"
    exit 1
fi

# Install to /usr/local/bin
echo "📦 Installing to $INSTALL_PATH..."
sudo cp "$BINARY_PATH" "$INSTALL_PATH"
sudo chmod +x "$INSTALL_PATH"

if [ $? -eq 0 ]; then
    echo "✅ Installation successful!"
    echo ""
    echo "You can now use 've' command:"
    echo "  ve auth  - Authenticate with the server"
    echo "  ve test  - Test the protected API endpoint"
    echo ""
    echo "To rebuild and reinstall, just run: ./install.sh"
else
    echo "❌ Installation failed!"
    exit 1
fi

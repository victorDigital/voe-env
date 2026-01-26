#!/bin/bash

# Build script for VOE CLI
# This script compiles the CLI and optionally installs it

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🔨 Building VOE CLI..."

# Build in release mode
cargo build --release

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
    echo ""
    echo "Binary location: $SCRIPT_DIR/target/release/ve"
    echo ""
    echo "To install globally, run:"
    echo "  ./install.sh"
    echo ""
    echo "Or manually:"
    echo "  sudo cp target/release/ve /usr/local/bin/ve"
    echo "  sudo chmod +x /usr/local/bin/ve"
else
    echo "❌ Build failed!"
    exit 1
fi

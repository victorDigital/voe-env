.PHONY: build install clean run test auth

# Build the CLI in release mode
build:
	@echo "🔨 Building VOE CLI..."
	cargo build --release
	@echo "✅ Build complete! Binary: target/release/ve"

# Build and install globally
install: build
	@echo "📦 Installing to /usr/local/bin/ve..."
	sudo cp target/release/ve /usr/local/bin/ve
	sudo chmod +x /usr/local/bin/ve
	@echo "✅ Installation complete!"

# Clean build artifacts
clean:
	cargo clean
	@echo "🧹 Cleaned build artifacts"

# Quick rebuild (development)
dev:
	cargo build
	@echo "✅ Development build complete! Binary: target/debug/ve"

# Run auth command (requires installation)
auth:
	ve auth

# Run test command (requires installation)
test:
	ve test

# Rebuild and reinstall
reinstall: clean install

# VOE CLI

A minimal command-line interface for interacting with the VOE environment vault.

## Features

- Device authorization flow for secure authentication
- Minimal dependencies for easy deployment

## Building

Ensure you have Rust installed. Then:

```bash
cd cli
cargo build --release
```

## Running

```bash
./target/release/voe-cli
```

The CLI will guide you through the device authorization process:
1. Visit the provided URL
2. Enter the user code
3. The CLI will poll for authorization and display the access token upon success

## Configuration

Set the `VOE_BASE_URL` environment variable to match your server URL (default: http://localhost:5173).

```bash
export VOE_BASE_URL=https://your-server.com
./target/release/voe-cli
```

## Security

This CLI uses Better Auth's device authorization plugin for secure, OAuth-like authentication without storing credentials locally.
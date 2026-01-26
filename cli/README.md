# VOE CLI

A minimal command-line interface for interacting with the VOE environment vault.

## Features

- Device authorization flow for secure authentication
- Token persistence (no need to login every time)
- Protected API testing
- Minimal dependencies for easy deployment

## Installation

### Quick Install

```bash
cd cli
./install.sh
```

This will build and install the CLI as the `ve` command globally.

### Manual Installation

```bash
cd cli
make install
# or
cargo build --release
sudo cp target/release/ve /usr/local/bin/ve
sudo chmod +x /usr/local/bin/ve
```

## Usage

Once installed, you can use the `ve` command:

```bash
# Initialize VOE in the current directory
ve init
# or with arguments
ve init --path org:product:dev --password mypassword

# Push .env file to the vault
ve push

# Authenticate with the server
ve auth

# Test the protected API endpoint
ve test
```

The `ve test` command will automatically authenticate if no valid token is found.

## Building

### Quick Build

```bash
cd cli
./build.sh
# or
make build
```

### Development Build

```bash
cd cli
make dev
# or
cargo build
```

### Rebuild and Reinstall

```bash
cd cli
make reinstall
# or
make clean && make install
```

## Commands

- `ve init` - Initialize VOE in the current directory
  - `--path, -p` - Vault path (e.g., org:product:dev)
  - `--password, -P` - Vault password/lock
  - If not provided, will prompt for input
  - Creates/updates `.env` file with `VE_VAULT_KEYPASS=path;password`
  - Skips if `.env` already contains `VE_VAULT_KEYPASS`

- `ve push` - Push .env file to the online vault
  - Reads `.env` file from current directory
  - Encrypts all environment variables using the vault password
  - Uploads encrypted values to the server
  - Requires authentication (auto-authenticates if needed)

- `ve auth` - Authenticate with the VOE server using device authorization

- `ve test` - Test the protected API endpoint (auto-authenticates if needed)

## Configuration

Set the `VOE_BASE_URL` environment variable to match your server URL (default: http://localhost:5173).

```bash
export VOE_BASE_URL=https://your-server.com
ve auth
```

## Token Storage

Tokens are stored in `~/.voe/token.json` and are automatically:
- Loaded on startup
- Validated for expiration
- Refreshed if invalid

## Security

This CLI uses Better Auth's device authorization plugin for secure, OAuth-like authentication. Tokens are stored locally but are never committed to git (see `.gitignore`).
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
# VOE CLI

VOE (Vault of Environments) CLI - Secure environment variable management with online vault storage.

## Installation

```bash
cargo install --path .
```

## .env.example Synchronization

The CLI automatically keeps `.env.example` files in sync with your local environment variables:

- **Never creates** `.env.example` - only updates it if it already exists
- **Keys only** - stores environment variable keys with placeholder values (`xxx`)
- **Auto-sync** - updated whenever `.env` is modified (init, pull, change-password)
- **Preserves structure** - maintains existing comments and formatting in `.env.example`

Example `.env.example`:
```bash
# Database configuration
DATABASE_URL=xxx
DB_USER=xxx

# API settings
API_KEY=xxx
DEBUG=xxx
```

## Commands

- `ve init` - Initialize VOE in the current directory
  - `--path, -p` - Vault path (e.g., org:product:dev)
  - `--password, -P` - Vault password/lock
  - If not provided, will prompt for input
  - Creates/updates `.env` file with `VE_VAULT_KEYPASS=path+password`
  - Updates `.env.example` if it exists
  - Skips if `.env` already contains `VE_VAULT_KEYPASS`

- `ve push` - Push .env file to the online vault
  - `--force` - Force push - delete server variables not present locally (requires confirmation)
  - Reads `.env` file from current directory
  - Encrypts all environment variables using the vault password
  - Uploads encrypted values to the server
  - Requires authentication (auto-authenticates if needed)

- `ve pull` - Pull .env file from the online vault
  - `--force` - Force replace with server version, may delete unsynced variables
  - `-p, --path` - Vault path (e.g., org:product:dev) - initializes if .env doesn't exist
  - `-P, --password` - Vault password/lock - initializes if .env doesn't exist
  - If .env doesn't exist and path/password are provided, initializes the project first
  - Merges server variables with local ones (update mode) or replaces completely (force mode)
  - Updates `.env.example` if it exists
  - Requires authentication (auto-authenticates if needed)

- `ve change-password` - Change vault password (only if local and server are identical)
  - `-P, --password` - New vault password/lock
  - If not provided, will prompt for input
  - Verifies local and server environments are exactly the same
  - Re-encrypts all variables with new password and uploads to server
  - Updates local `.env` file with new password
  - Updates `.env.example` if it exists

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
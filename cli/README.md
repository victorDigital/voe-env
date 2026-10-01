# VOE CLI

A minimal command-line interface for interacting with the VOE environment vault.

## Features

- Device authorization flow for secure authentication
- Token persistence (no need to login every time)
- Protected API testing
- Minimal dependencies for easy deployment

## Installation

### Hosted installer

Open your VOE site's homepage and copy the install command for your platform. It downloads the matching binary, adds `ve` to PATH, and saves the site URL in `~/.voe/server-url`. Open a new terminal and run `ve auth` to sign in.

The installer supports macOS, Linux (including WSL), and Windows on x86_64 and ARM64. Rust is only required when building the CLI from source.

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

## Updating

Run `ve update` to download the latest platform binary from your configured site and replace the current executable. Your saved site URL, login token, and environment files are preserved. `VOE_BASE_URL` can override the site used for updates.

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

The CLI uses the URL saved by the hosted installer. Set `VOE_BASE_URL` to override it. Without either setting, the default is `https://env.voe.dk`.

```bash
export VOE_BASE_URL=https://your-server.com
ve auth
```

## CI and releases

`.github/workflows/cli.yml` builds all six platform binaries on pull requests and pushes to `main`. Pushing a `cli-v*` tag also publishes the binaries and `SHA256SUMS` as a GitHub release:

```bash
git tag cli-v0.1.0
git push origin cli-v0.1.0
```

Commit and push the CLI and workflow changes before tagging. The first release must be published before the homepage installer can download binaries. The web app redirects `/downloads/<asset>` to the latest release; set `VOE_CLI_RELEASE_URL` to a specific release's download URL to pin the version.

## Token Storage

Tokens are stored in `~/.voe/token.json` and are automatically:

- Loaded on startup
- Validated for expiration
- Refreshed if invalid

## Security

This CLI uses Better Auth's device authorization plugin for secure, OAuth-like authentication. Tokens are stored locally but are never committed to git (see `.gitignore`).

# VOE CLI

The CLI encrypts and decrypts organization secrets locally. Sign in once through your browser; there is no vault password.

## Install and connect

Use the installer on your VOE homepage, or build with `cargo build --release` in `cli/`.

```sh
ve init
ve status
ve pull --dry-run
ve pull
ve push
```

Create the workspace in the web app first. Folders can be created during `ve init`. Interactive `ve init` starts browser enrollment when there is no active local session. `ve auth` opens the approval URL automatically in a terminal; use `--no-browser` to open the printed URL yourself. Unlock your vault and select the workspaces to grant. The CLI link fills the fingerprint input automatically; manual entry remains available. The browser compares that fingerprint with the enrolled public key before you explicitly authorize access. This step binds the CLI's encryption key to your approval. A device only receives keys for the selected workspaces, and every request also checks current membership and role.

`--org` accepts a workspace name (case-insensitive) or its exact ID. Run `ve init` without `--org` to select your only workspace automatically or choose from a searchable numbered list. Type part of a name to filter, `/` to reset the list, or `q` to cancel. Duplicate names also open the chooser; scripts must pass a unique name or exact ID. In a terminal, omit `--path` to choose an existing folder (including the root) or enter `n` to create one. New paths such as `product:production` create any missing parent folders and reuse existing ones. Viewers can select existing folders only, and creation requires any pending key rotation to be completed in the web app. Pass `--path product:production` to select an existing folder directly, or `--path /` for the root. Without a terminal, or with `--no-input`, `--json`, or `--quiet`, pass `--path` explicitly (`--path /` for root). Prompts are disabled in these modes; missing information produces a recovery command.

Credentials and the device private key are stored in macOS Keychain, Windows Credential Manager, or the Linux Secret Service. Linux requires a running, unlocked Secret Service; there is no plaintext fallback. Sessions expire and revoked devices must be enrolled again. Headless CI/workload identities are not supported by this version.

macOS may ask for your password to approve Keychain access initially or after an update; allow only the `ve` executable you trust.

`.voe.json` contains only the server URL, organization ID, and folder ID and can be committed. `.env` contains the application secrets you pull and should stay out of version control. Neither file stores a vault password.

## Commands

| Command | Behavior |
| --- | --- |
| `ve auth` | Browser approval and device key enrollment |
| `ve logout` | Delete local credentials; revoke the device in web settings to block server access |
| `ve workspaces` | List organization IDs, names, and your roles |
| `ve init [--org NAME_OR_ID] [--path folder:path]` | Choose a workspace, then select or create a folder interactively |
| `ve push` | Encrypt and upsert local variables, preserving other remote variables |
| `ve push --force` | Also delete remote variables absent from this folder's local `.env` |
| `ve pull` | Merge remote values; choose how to resolve differing keys interactively |
| `ve pull --conflicts keep-local` | Keep conflicting local values, add remote-only keys, preserve local-only keys |
| `ve pull --conflicts use-remote` | Accept remote values while preserving local-only keys |
| `ve pull --force` | Replace `.env` with this folder's remote variables |
| `ve status` | Show workspace, folder, server, file, authentication, and sync counts |
| `ve push --dry-run` / `ve pull --dry-run` | Preview key names and added/updated/deleted/unchanged counts without writing |
| `ve diff` / `ve diff --all` | Show differences; include unchanged keys with `--all`; never print values |
| `ve list` | Show the workspace tree, including empty folders and secret names |
| `ve search PATTERN` | Search secret names in that organization |
| `ve validate` | Check environment file syntax and duplicate names |
| `ve completions SHELL` | Generate a shell completion script |
| `ve whoami` / `ve test` | Check the authenticated account |
| `ve update` | Install a newer release from your configured server, or report that ve is already up to date |

`push` and `pull` show the workspace/folder and file being synchronized. Unchanged values are not uploaded or rewritten. Pull still regenerates the environment file when it changes; comments and formatting are not preserved. `--force` replaces the complete local file on pull and removes remote-only keys on push. Use `--dry-run` first to inspect deletions. A pull preview with unresolved conflicts reports the proposed remote updates and marks that a resolution is required.

The nearest `.voe.json` in the current directory or its parents defines the project root. The default `.env`, and relative `--file` paths, resolve from that root. `ve init` writes a configuration in the current directory, allowing a nested project to have its own workspace and folder. Without a project, `ve validate --file PATH` resolves from the current directory.

```sh
ve pull --file .env.local --conflicts use-remote
ve status --json
ve push --dry-run --json
ve init --org wemuda --path app:development --no-input
ve completions zsh > ~/.zfunc/_ve
```

Global `--json` emits one JSON result on stdout; runtime errors are JSON on stderr and exit nonzero. `--quiet` suppresses normal human output, but errors remain visible. `--no-input` disables prompts. Auth approval instructions always go to stderr so manual browser approval can proceed. Shell completion scripts support Bash, Zsh, Fish, PowerShell, and Elvish; load the generated script through your shell's completion setup.

Push, pull, and other server operations show a compact animated activity bar in interactive terminals while waiting for a response. It clears before prompts, results, and errors. Update downloads use the same styling with byte counts and a percentage when the download size is known. Progress is capped at 10 redraws per second and hidden with `--json`, `--quiet`, or redirected output.

`VOE_BASE_URL` overrides the saved installer URL in `~/.voe/server-url`; the default is `https://env.voe.dk`. Project commands, including `auth`, `logout`, `whoami`, and `workspaces`, use the nearest `.voe.json` server. Outside a project they use the configured default; `update` uses the configured default download server. HTTPS is required except on localhost.

A concurrent edit or key rotation rejects stale pushes. Pull again before retrying. Removal blocks new requests immediately; downloaded `.env` files cannot be revoked.

## Development

```sh
cargo test
cargo build
python3 tests/test_update.py target/debug/ve
```

Shared browser/Rust encryption vectors live in `web/test/fixtures/vault-v1.json`. Those keys are public test fixtures, never production keys. Release builds use the native OS credential backend; Linux cross-builds vendor the D-Bus/OpenSSL dependencies.

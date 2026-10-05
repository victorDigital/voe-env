# VOE CLI

The CLI encrypts and decrypts organization secrets locally. Sign in once through your browser; there is no vault password.

## Install and connect

Use the installer on your VOE homepage, or build with `cargo build --release` in `cli/`.

```sh
ve auth
ve workspaces
ve init --org wemuda
ve pull
ve push
```

Create the workspace in the web app first. Folders can be created during `ve init`. During `ve auth`, open the printed URL, unlock your vault, paste the full device fingerprint from your terminal, and select the workspaces to grant. This step binds the CLI's encryption key to your approval. A device only receives keys for the selected workspaces, and every request also checks current membership and role.

`--org` accepts a workspace name (case-insensitive) or its exact ID. Run `ve init` without `--org` to select your only workspace automatically or choose from a numbered list. Duplicate names also open the chooser; scripts must pass a unique name or exact ID. In a terminal, omit `--path` to choose an existing folder (including the root) or enter `n` to create one. New paths such as `product:production` create any missing parent folders and reuse existing ones. Viewers can select existing folders only, and creation requires any pending key rotation to be completed in the web app. Pass `--path product:production` to select an existing folder directly, or `--path /` for the root. Without a terminal, omitting `--path` continues to use the root.

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
| `ve pull` | Merge remote values; refuse conflicting local values |
| `ve pull --force` | Replace `.env` with this folder's remote variables |
| `ve diff` | Compare names and equality without printing values |
| `ve list` | Show the workspace tree, including empty folders and secret names |
| `ve search PATTERN` | Search secret names in that organization |
| `ve validate` | Check `.env` syntax and duplicate names |
| `ve whoami` / `ve test` | Check the authenticated account |
| `ve update` | Install a newer release from your configured server, or report that ve is already up to date |

Downloads show a compact progress bar in interactive terminals, capped at 10 redraws per second. When the server omits the download size, only the downloaded byte count is shown. Redirected output stays plain text.

`VOE_BASE_URL` overrides the saved installer URL in `~/.voe/server-url`; the default is `https://env.voe.dk`. `push`, `pull`, `list`, `diff`, and `search` use the server saved in `.voe.json`. Use the same server when running `ve auth`. HTTPS is required except on localhost.

A concurrent edit or key rotation rejects stale pushes. Pull again before retrying. Removal blocks new requests immediately; downloaded `.env` files cannot be revoked.

## Development

```sh
cargo test
cargo build
python3 tests/test_update.py target/debug/ve
```

Shared browser/Rust encryption vectors live in `web/test/fixtures/vault-v1.json`. Those keys are public test fixtures, never production keys. Release builds use the native OS credential backend; Linux cross-builds vendor the D-Bus/OpenSSL dependencies.

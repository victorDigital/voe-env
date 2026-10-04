# VOE CLI

The CLI encrypts and decrypts organization secrets locally. Sign in once through your browser; there is no vault password.

## Install and connect

Use the installer on your VOE homepage, or build with `cargo build --release` in `cli/`.

```sh
ve auth
ve workspaces
ve init --org wemuda --path product:production
ve pull
ve push
```

Create the workspace and folder in the web app first. During `ve auth`, open the printed URL, unlock your vault, paste the full device fingerprint from your terminal, and select the workspaces to grant. This step binds the CLI's encryption key to your approval. A device only receives keys for the selected workspaces, and every request also checks current membership and role.

`--org` accepts a workspace name (case-insensitive) or its exact ID. Run `ve init` without `--org` to select your only workspace automatically or choose from a numbered list. Duplicate names also open the chooser; scripts must pass a unique name or exact ID. Omit `--path` to use the workspace root.

Credentials and the device private key are stored in macOS Keychain, Windows Credential Manager, or the Linux Secret Service. Linux requires a running, unlocked Secret Service; there is no plaintext fallback. Sessions expire and revoked devices must be enrolled again. Headless CI/workload identities are not supported by this version.

`.voe.json` contains only the server URL, organization ID, and folder ID and can be committed. `.env` contains the application secrets you pull and should stay out of version control. Neither file stores a vault password.

## Commands

| Command | Behavior |
| --- | --- |
| `ve auth` | Browser approval and device key enrollment |
| `ve logout` | Delete local credentials; revoke the device in web settings to block server access |
| `ve workspaces` | List organization IDs, names, and your roles |
| `ve init [--org NAME_OR_ID] [--path folder:path]` | Choose a workspace and existing folder; defaults to the root |
| `ve push` | Encrypt and upsert local variables, preserving other remote variables |
| `ve push --force` | Also delete remote variables absent from this folder's local `.env` |
| `ve pull` | Merge remote values; refuse conflicting local values |
| `ve pull --force` | Replace `.env` with this folder's remote variables |
| `ve diff` | Compare names and equality without printing values |
| `ve list` | Show the workspace tree, including empty folders and secret names |
| `ve search PATTERN` | Search secret names in that organization |
| `ve validate` | Check `.env` syntax and duplicate names |
| `ve whoami` / `ve test` | Check the authenticated account |
| `ve update` | Replace the executable with the latest release from your configured server |

`VOE_BASE_URL` overrides the saved installer URL in `~/.voe/server-url`; the default is `https://env.voe.dk`. `push`, `pull`, `list`, `diff`, and `search` use the server saved in `.voe.json`. Use the same server when running `ve auth`. HTTPS is required except on localhost.

A concurrent edit or key rotation rejects stale pushes. Pull again before retrying. Removal blocks new requests immediately; downloaded `.env` files cannot be revoked.

## Existing installations

Back up your database and keep old browser keys until migration is verified. Open **Workspace settings → Migrate legacy vaults**, enter the old folder passwords once, and migrate into a personal workspace. Old recipients are never added automatically. Legacy vaults remain available as a read-only archive.

Upgrade the CLI, run `ve auth` and `ve init --org ...`, then `ve pull` after verifying the new workspace. Successful pulls remove `VE_VAULT_KEYPASS` from `.env`. The new CLI ignores old plaintext `~/.voe/token.json` credentials; remove that old file after successful enrollment. The old `share`, `unshare`, `shares`, and password-changing commands have been retired.

## Development

```sh
cargo test
cargo build
python3 tests/test_update.py target/debug/ve
```

Shared browser/Rust encryption vectors live in `web/test/fixtures/vault-v1.json`. Those keys are public test fixtures, never production keys. Release builds use the native OS credential backend; Linux cross-builds vendor the D-Bus/OpenSSL dependencies.

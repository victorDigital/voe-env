# VOE web

SvelteKit, Better Auth, Drizzle, and PostgreSQL 15+.

## Run locally

Copy `.env.example` to `.env`, configure PostgreSQL and authentication, then:

```sh
bun install
bun run dev
```

Use `http://localhost:5173` for local passkey development. Hosted origins require HTTPS. `BETTER_AUTH_URL` defines both the accepted origin and the passkey RP hostname. Changing that hostname invalidates access to existing passkeys; do not change it casually. Leave `PUBLIC_BETTER_AUTH_URL` empty for same-origin requests.

Configure `EMAIL_API_KEY` with a Resend API key and `EMAIL_FROM` with a verified sender. Email links bootstrap verified accounts and invitation acceptance. Existing vault access still requires an enrolled PRF passkey or offline recovery key. Password sign-in is disabled. Do not deploy this release before testing email delivery and the supported passkey providers.

The app applies checked-in migrations at startup. Back up before deploying. The new tables are additive; legacy ciphertext and shares are retained. Legacy vault/share APIs now return 410 and old CLIs must be upgraded.

## Encryption and authorization

- Better Auth organizations own all folders and secrets. Fixed owner/admin/member/viewer roles are enforced again by application APIs.
- Passkey PRF → HKDF-SHA-256 → AES-256-GCM account-key envelope. Each independent passkey needs its own enrolled envelope.
- A random account key protects a separate RSA-3072 OAEP-SHA-256 identity. A generated offline recovery key independently wraps the account key. The recovery authentication proof is domain-separated and hashed on the server; it does not reveal the encryption key.
- Organization keys are OAEP envelopes bound to organization, recipient, and epoch. Recipient public-key bindings are encrypted and authenticated with the organization key and checked during rotation. New member/device fingerprints must be verified through a trusted channel before provisioning.
- Every folder has a random AES-256-GCM key; secret values authenticate organization, folder ID, secret ID, name, and epoch. Nonces are random for every encryption.
- Keys stay in browser memory and lock after 15 minutes or sign-out. CLI private keys and session tokens use native OS credential storage.
- Removing members/devices blocks reads immediately and pauses writes. An unlocked admin replaces every folder key and ciphertext and every remaining recipient envelope in one version-checked transaction. Rewrapping existing folder keys is not treated as rotation.
- An admin-assisted identity reset requires another provisioned owner/admin in every affected workspace. The user signs in again by email, confirms the reset, enrolls a new identity, and waits for verified admin provisioning. A lone owner needs their original recovery key or a working passkey.

Workspace reads/writes currently use bounded whole-workspace snapshots: at most 2,000 folders, 10,000 secrets, 1,000 recipients, and a 16 MB JSON request. This keeps migration and rotation atomic. A failed operation can be retried from the last committed revision; larger deployments need chunked staging before these limits are raised.

Names, memberships, roles, and audit metadata remain visible to the server. E2EE cannot revoke downloaded plaintext or protect against malicious client code delivered by a compromised web origin. Rotate the actual downstream credentials after a suspected compromise.

## Migration

Use the migration screen to copy legacy ciphertext into an owner-only personal workspace. The client unlocks each old password domain, re-encrypts every value, downloads it again, and compares every plaintext before completing the migration. A server checkpoint records the destination and source digest before upload. Interrupted uploads can be retried; if the upload committed, use **Verify completed migration**. Source data is frozen, and destination revisions guard verification.

Old share recipients keep only their previous archive access. Invite them explicitly to a workspace once its complete audience has been reviewed. Retain the database backup and old browser keys; do not drop legacy tables yet. Once a migrated workspace accepts new writes, rollback needs reconciliation rather than restoring an old snapshot over it.

## Verification

```sh
bun run check
bun test test/auth-pages.test.ts test/vault-crypto.test.ts
bun run build
```

`test/workspaces.integration.ts` and `test/browser.integration.ts` are opt-in checks against a disposable database named `voe_passwordless_test`. They insert synthetic accounts/data. Never point them at production. Create that disposable database on your local PostgreSQL server, then run `bun run dev:test`. The runner uses `BETTER_AUTH_URL=http://localhost:5174`, an empty `PUBLIC_BETTER_AUTH_URL`, and `BETTER_AUTH_SECRET=voe-passwordless-local-test-secret-only`. The scripts read the connection credentials from `.env` but explicitly select the disposable database.

```sh
bun test/workspaces.integration.ts
bunx playwright install chromium
bun test/browser.integration.ts
```

The browser test uses Chromium's virtual PRF authenticator for onboarding, recovery, a second passkey, and encrypted CRUD. This is not a compatibility certification for real iCloud, Google, Windows, or hardware passkey providers. Check supported devices and provider sync before migrating production data. Test Resend delivery against a controlled mailbox separately.

Set `VOE_TEST_CLI=1` for the browser integration script to also exercise the real built `cli/target/debug/ve` binary. This creates and deletes a synthetic localhost:5174 entry in the native OS credential store and uses a temporary project directory. Build the CLI first.

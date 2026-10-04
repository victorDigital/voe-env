# Organizations and passwordless access

Status: design approved by the user, including organization-wide folder visibility, passkey unlock, random encryption keys, admin provisioning, recovery, and CLI enrollment. Implementation now exists in the web app and Rust CLI. See `web/README.md` for operating requirements, current snapshot limits, and validation. Production migration remains a deliberate user operation; real passkey-provider compatibility and email delivery must be verified before rollout. Original design reviewed on 2026-10-04.

See [end-to-end flow diagrams](organizations-passwordless-flow.md).

## Recommendation and decision

Use Better Auth organizations as the ownership and authorization boundary, passkeys for human authentication, and randomly generated encryption keys instead of vault passwords.

Preserve end-to-end encryption: only authorized clients hold usable decryption keys. Server-managed decryption and server-held recovery keys are excluded. Use passkey PRF to unlock client keys, with explicit backup and device enrollment. Passwordless login alone does not provide passwordless decryption.

Do not introduce one shared organization password or reuse a login credential as a data encryption key. One personal master password can support an E2EE design, but conflicts with the desired passwordless experience and still requires organization key distribution and recovery.

## Original implementation before this overhaul

- Better Auth 1.7.7 is locked in `web/bun.lock`. The server enables email/password, device authorization, bearer sessions, and device approval logging.
- `env_vault` belongs to a user and has a unique `(userId, fullKey)` constraint. Folder hierarchy is implicit in colon-separated keys.
- `folder_shares` grants read/readwrite access to an individual, including descendants, with optional expiry.
- The browser encrypts a vault password to a recipient's RSA public key. Its unencrypted private key is stored in localStorage, and missing browser keys cause a new pair to be generated.
- Both web and Rust derive AES keys from passwords using PBKDF2 with the same fixed salt. The CLI writes the vault password into `VE_VAULT_KEYPASS` inside `.env`.
- Vault APIs infer the target owner from existing data and matching shares. Organizations should replace this ambiguous owner resolution.
- CLI device login exists already. CLI creation of E2EE shares is currently unimplemented.

Relevant code: `web/src/lib/server/auth.ts`, `web/src/lib/server/db/schema.ts`, `web/src/lib/server/env-vault.ts`, `web/src/lib/server/shares.ts`, `web/src/lib/crypto.ts`, `web/src/routes/dashboard/env/ShareDialog.svelte`, `web/src/routes/api/vault/*`, and `cli/src/main.rs`.

## Organization model

An organization owns its folders and secrets. Each folder belongs to exactly one organization. Users join organizations rather than receiving individual folder shares. Removing a user does not delete the organization's secrets.

Create a single-member workspace for personal data using the same organization model. Additional workspaces are explicit. For v1, all members can read every folder within their organization; folders are organizational structure, not separate permission boundaries. Use separate organizations for different audiences. Add Better Auth teams and application-level folder grants only if selective folder access is a confirmed requirement.

Use a fixed role set, implemented through Better Auth access control with application resources for folders and secrets:

| Role | Read secrets | Edit secrets/folders | Manage members | Delete org / transfer ownership |
| --- | --- | --- | --- | --- |
| Owner | Yes | Yes | Yes | Yes |
| Admin | Yes | Yes | Yes, excluding owner control | No |
| Member | Yes | Yes | No | No |
| Viewer | Yes | No | No | No |

Preserve Better Auth's management permissions when extending roles. Viewer is an application-defined role. Enforce the last-owner rule and prevent admins from promoting themselves to owner. Invitations must target verified email identities, expire, and be accepted by the intended user. Do not add members merely because an email domain matches.

Better Auth supplies memberships, invitations, roles, and active organization state. The app must enforce authorization on its own secret APIs and SvelteKit actions; installing the plugin does not do that automatically. See [Better Auth organizations](https://better-auth.com/docs/plugins/organization).

## Data and API design

Add Better Auth's organization/member/invitation tables and session organization fields through reviewed Drizzle migrations. Generate against the installed, compatible plugin versions rather than copying a schema from newer documentation.

Introduce explicit application records:

- `folder`: ID, organization ID, parent folder ID, name, created/updated timestamps.
- `secret`: ID, organization ID, folder ID, name, encrypted value, encryption format/key version, createdBy/updatedBy, timestamps.
- `folder_key`: folder ID, key version, wrapped random data key, wrapping key identifier.
- `encryption_identity`: user ID, versioned encryption public key, encrypted private key, authenticated enrollment record.
- `account_key_envelope`: user ID, passkey credential or recovery method, PRF input/derivation version, wrapped account key.
- `organization_key_envelope`: organization ID, key epoch, member/device identity ID, wrapped organization key, provisioning identity and authenticated record.
- `encryption_device`: user ID, public key, enrollment/revocation state, authenticated enrollment record.
- `audit_event`: organization, actor/session, operation, resource IDs, result, timestamp; no values or key material.

Use a real root folder per organization, unique sibling names, and unique secret names within a folder. Enforce same-organization parent and secret-folder relationships in database constraints. Keep colon-separated paths as a CLI/display representation resolved to IDs within the selected organization; reject ambiguous separators. Empty folders should exist independently of secrets.

Every data operation takes an explicit organization ID and resource ID or organization-relative path. The server checks current membership, action permission, and resource ownership through a shared authorization service before querying data or decrypting. Scope list, search, export, batch operations, and mutations equally. The active organization is UI state, never proof of access. Avoid stale membership/role caches that keep revoked access alive.

## Passwordless authentication

Add the compatible `@better-auth/passkey` package and client plugin. Set a deliberate HTTPS origin and RP ID; require user verification. Use a verified email invitation/onboarding link to establish the account, then enroll a passkey before granting secret access. Existing users enroll while authenticated before password login is retired.

Normal use is passkey sign-in through the device's biometric or PIN prompt, followed by direct access to authorized folders. There is no app password or folder password. Passkey settings should support multiple credentials, backup enrollment, and revocation. Require recent passkey verification for adding credentials, owner changes, and recovery configuration.

Design recovery before disabling password login. Prefer a second passkey and single-use recovery codes, with a controlled recovery flow, notifications, and session revocation. An email-only fallback would make email compromise sufficient to bypass the stronger normal login. Recovery for authentication is distinct from recovery of E2EE keys.

The current passkey documentation includes registration and extension APIs, but verify compatibility with the installed version before using them. See [Better Auth passkeys](https://better-auth.com/docs/plugins/passkey).

## Client-side encryption format

Generate a random 256-bit AES data key for each folder on an authorized client. Encrypt each value with AES-GCM using a fresh nonce and authenticated context containing organization ID, folder ID, secret ID, and format/key version. Encrypt each folder key using the organization wrapping key; store only wrapped keys with ciphertext in PostgreSQL.

Use maintained browser/Rust cryptographic implementations and a reviewed envelope format. Select one interoperable authenticated public-key wrapping construction during the prototype; do not invent a custom encryption protocol. Keep encryption keys separate from authentication session tokens and `BETTER_AUTH_SECRET`. See [OWASP cryptographic storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).

The server authorizes ciphertext and envelope access but cannot decrypt either. Folder names, organization membership, secret names, and activity metadata remain visible in v1; the encrypted content is the secret value. Distinguish rewrapping unchanged data keys from replacing compromised data keys and re-encrypting values.

Previously downloaded values cannot be revoked. If a former member may misuse credentials they already read, rotate those actual downstream credentials as well.

## Passwordless key access and recovery

Keep encryption/decryption on authorized clients and replace passwords with random keys. Because v1 access is organization-wide, use one versioned organization wrapping key, with separate random folder data keys beneath it. Wrap the organization key separately for each authorized member's encryption identity. These are cryptographic key envelopes, not a second source of permission rules.

Protect each user's encryption identity with a random account key. Wrap that account key separately for each enrolled PRF-capable passkey, using WebAuthn PRF output through a reviewed key derivation/wrapping construction. Ordinary WebAuthn authentication signatures are not encryption keys. PRF results and unwrapped keys must stay on the client and must not be forwarded by authentication serialization, telemetry, or logging.

Better Auth currently documents PRF extension inputs and returned extension results; it does not implement the vault key hierarchy or key recovery. PRF availability must be tested across target browsers, devices, passkey providers, and synced credentials. A new independent passkey requires a new key envelope; logging in on a new device is not by itself proof that decryption keys are available. See [WebAuthn extensions](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions).

Joining has two states: accepted membership and provisioned decryption access. An existing owner's or admin's unlocked client verifies the new member's encryption identity and wraps the organization key to it. The invite UI shows pending key approval until this finishes; offline admins cannot provision automatically. Bind device/member keys to verified enrollment, with authenticated key records and an explicit verification strategy; a server-supplied public key alone is not a defense against malicious key substitution. Avoid exposing raw private keys in localStorage.

Require an offline generated recovery key that wraps the account key, and encourage a second enrolled passkey with its own account-key envelope. Test recovery during onboarding. Treat this encryption recovery key separately from single-use login recovery codes. An unlocked owner/admin can restore organization access to a recovered member identity; a lone owner needs their own usable backup. Email account recovery alone cannot decrypt old data. Unsupported PRF devices need an approved device-transfer/recovery flow; do not silently fall back to server escrow while claiming E2EE. Losing every usable credential, recovery key, and authorized recovering device/member means permanent data loss.

CLI approval must additionally bind the CLI's generated encryption public key to the authenticated device authorization ceremony and deliver only encrypted key material to that CLI. Wrap the approved organizations' keys to that device rather than handing it the user's account recovery root. Store private material in the OS credential store. The existing device flow supplies a session token, not a key exchange protocol.

On removal, deny API/key-envelope access immediately and rotate the organization key plus affected data keys for future confidentiality against retained old keys. An authorized unlocked client must perform the rotation, including fresh envelopes for remaining members/devices. Use a versioned, resumable rotation with an atomic activation step; reject old-epoch writes and block new secret writes until the new epoch is ready. Re-encrypt retained data when required by policy. Rewrapping the same folder keys is insufficient if the removed member already has those keys. Downloaded plaintext remains unrecoverable by the service.

Prototype browser compatibility, new-device unlock, CLI pairing, invitation provisioning, and recovery before committing to the full migration. Keep unlocked material in memory, clear it on lock/logout, and require a new unlock after expiry or reload. Browser E2EE also remains vulnerable to malicious client code served by a compromised origin; state that limitation accurately.

## Web and CLI experience

Replace Share with workspace membership management. Add a workspace switcher, invitation acceptance, members/roles, and passkey settings. Keep folder navigation and editing familiar. Show organization and folder explicitly before moves/imports that change the audience.

Keep `ve auth` and the existing Better Auth first-party device flow: open the browser, sign in with a passkey, approve the CLI. Store the session token in the OS credential store. Device authorization produces a Better Auth session token; do not assume its scope field independently limits vault access. All CLI requests still pass organization authorization. See [Better Auth device authorization](https://better-auth.com/docs/plugins/device-authorization).

Add workspace selection and a project config holding only non-secret server/organization/folder identifiers. `ve push` and `ve pull` stop requesting passwords after migration. Remove the password from `.env`; the file still contains exported application secrets by design. Defer CI support from the first cut unless required: an automation identity needs both scoped API authorization and independently provisioned E2EE keys, held by the workload rather than the server.

## Implementation sequence

1. Use the approved E2EE and organization-wide folder visibility model. Inventory legacy owners, paths, share audiences/permissions/expiry, and data volumes without printing values. Prototype PRF unlock, a second passkey, recovery, and browser-to-CLI enrollment on the target clients. Finalize the reviewed interoperable envelope format.
2. Implement organizations, fixed roles, passkeys, onboarding/recovery, and shared server authorization. Add reviewed Drizzle migrations and preserve login access during enrollment.
3. Introduce folders/secrets with explicit organization IDs, versioned client-side encryption, and member/device key envelopes. Implement provisioning, rotation, isolation, and cryptographic tests before exposing migrated data.
4. Build workspace/member UI and update CLI authorization, configuration, token/private-key storage, and push/pull behavior.
5. Migrate through an explicit resumable operation, then cut over each completed workspace to the new APIs. Disable legacy writes for a workspace while migrating, or enforce version checks so concurrent edits cannot be lost.
6. Retire individual share APIs, browser RSA key storage, vault password controls, old CLI share/password commands, and old tables only after migration and restore verification. Reject legacy CLI writes clearly after cutover.

## Migration requirements

Back up the database and all required key material first. Create personal organizations for existing owners and map data to explicit folders without changing the audience automatically. Old path prefixes that resemble org names are not reliable organization identities.

Never convert every existing folder recipient into a member of the owner's entire organization: that could reveal unrelated secrets and extend access past an old expiry. Present the audience change for review. Split folders into organizations with matching access needs, explicitly approve broader access, or defer those folders. Preserve old access until reviewed cutover; expiration and mixed per-folder permissions must be accounted for explicitly.

Existing ciphertext cannot be converted with a database-only migration because the server does not have the passwords. An authorized browser or CLI unlocks each legacy password domain locally, decrypts, and writes the new format through the chosen encryption path. This is a one-time legacy unlock, even though future use is passwordless. If neither a password, usable recipient key, nor another authorized plaintext copy exists, the data cannot be recovered through the migration.

Use migration IDs/checkpoints, source revisions, count validation, and authenticated decryption checks. Verify every record before marking its workspace complete. Keep old ciphertext and needed keys for a defined rollback window; once new writes start, rollback requires reconciliation and cannot simply restore an old snapshot. Remove legacy `.env` password entries only after successful cutover.

## Completion checks

- Cross-organization requests fail for guessed IDs, lists/search/export, nested folders, and bulk operations through both web and CLI.
- Every role has the intended permissions; removed members and downgraded roles lose access on the next authorized request, including with existing browser/CLI sessions.
- Invitations reject wrong users, expiry, and replay; ownership cannot be orphaned.
- Passkey enrollment, login, backup credential, lost-device recovery, and device approval work without an application password.
- Encryption round trips, tampering rejection, context binding, nonce generation, key rotation, and missing-envelope behavior are covered. Run shared Rust/browser format vectors and device/recovery tests; verify PRF output and usable keys never reach server requests or telemetry.
- Migration is resumable after failure, rejects conflicting writes, preserves values and intended audiences, and has a tested backup restore process.
- No new vault passwords or raw long-lived private keys are written to `.env`, localStorage, logs, or repository files.
- Run relevant web tests, type checking/build, Rust tests, and visual verification of the final onboarding, organization, and folder flows during implementation.

# Organizations and passwordless access

VOE is an organization-based, end-to-end encrypted secrets platform. Accounts use passkeys; encryption keys are generated randomly and unlocked locally. See [flow diagrams](organizations-passwordless-flow.md) and [setup and verification](../web/README.md).

## Onboarding

1. Verify an email address through a sign-in link.
2. Create a PRF-capable passkey and save an offline recovery key. Verify the saved key before finishing setup.
3. Create a workspace or accept an invitation.
4. For an invited member, an unlocked admin verifies their identity fingerprint and grants encryption access.

Personal vaults use a single-member workspace. Every member can read every folder in their workspace; separate audiences use separate workspaces.

## Permissions

| Role | Read secrets | Edit folders and secrets | Manage members | Delete workspace |
| --- | --- | --- | --- | --- |
| Owner | Yes | Yes | Yes | Yes |
| Admin | Yes | Yes | Except owners | No |
| Member | Yes | Yes | No | No |
| Viewer | Yes | No | No | No |

Better Auth provides memberships and invitations. Application APIs verify membership, role, resource ownership, encryption provisioning, and the current key epoch. Changes cannot remove the last owner. Invitations expire and can only be accepted by their intended verified account.

## Encryption

A random account key protects the user's RSA encryption identity. Each passkey has an account-key envelope protected by a WebAuthn PRF-derived key. An independent offline recovery key provides a separate account-key envelope.

A workspace key is wrapped separately for each approved member or CLI device. It protects random per-folder encryption keys. Secret values use AES-256-GCM with authenticated organization, folder, secret ID, name, and epoch. Browser and Rust clients share the same versioned format and test vectors.

The server stores ciphertext and wrapped keys. PRF output, plaintext values, and usable encryption keys stay on clients. Names, membership, and roles remain visible to the server. Browser key material stays in memory and clears on lock, timeout, or sign-out.

## Recovery and revocation

A second passkey or offline recovery key restores access. An identity reset requires another provisioned admin in every affected workspace. That admin verifies the replacement identity before granting access. A lone owner needs a working passkey or their recovery key. Email alone cannot decrypt secrets.

Removing a member or device immediately blocks API access and pauses writes. An unlocked admin rotates organization and folder keys, re-encrypts values, and provisions remaining recipients in one version-checked transaction. Previously downloaded plaintext cannot be revoked.

## Web and CLI

The sidebar switches workspaces. Workspace settings manage invitations, members, roles, and encryption access. Account settings manage passkeys and approved CLI devices. Unlock, recovery, and initial vault setup open in a modal.

`ve auth` opens browser approval, verifies the device fingerprint, and grants keys for selected workspaces. Session credentials and the device private key use the OS credential store. `ve init` selects a workspace and folder; `.voe.json` stores their identifiers and the server URL. `ve push` and `ve pull` encrypt and decrypt locally without a vault password.

Database schema migrations remain versioned deployment infrastructure. Fresh installations use the same current schema as existing workspace installations.

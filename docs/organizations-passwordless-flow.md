# Passwordless end-to-end flow

These diagrams describe the implemented organization/key hierarchy. See `web/README.md` for deployment requirements, verification, and the limits of virtual-authenticator testing. Better Auth verifies identity and membership; the application enforces secret permissions; authorized clients perform all secret encryption and decryption.

## First setup and the key hierarchy

After verified onboarding, the browser registers a passkey and generates a random account key and a separate encryption identity. Creating an organization generates its organization key; creating each folder generates a folder key. Public identity keys and encrypted key envelopes are uploaded. The user saves an offline recovery key and can enroll a second passkey, each protecting another copy of the same account key.

An envelope is an encrypted copy of a key. The arrows below mean “unlocks an encrypted copy,” not “derive every key from one credential.” All underlying data keys are random.

```mermaid
flowchart TD
    P[Passkey PRF output] --> D[Derive local wrapping key]
    D --> A[Account key]
    R[Offline recovery key] --> A
    B[Second enrolled passkey with PRF] --> A
    A --> I[Personal encryption private key]
    I --> O[Organization key]
    O --> F1[Folder A key]
    O --> F2[Folder B key]
    F1 --> S1[Folder A secret values]
    F2 --> S2[Folder B secret values]
```

Passkeys for signing in and personal encryption identities are separate key pairs. The passkey's private signing key stays in its authenticator. PRF output, decrypted encryption keys, and secret plaintext stay on clients. The server knows organization membership, public keys, folder/secret names, and encrypted records.

## Sign in, read, and save

```mermaid
sequenceDiagram
    actor U as You
    participant B as Your browser
    participant P as Passkey authenticator
    participant S as Server and Better Auth
    B->>S: Request sign-in challenge
    S-->>B: Challenge
    U->>P: Approve with biometric or device PIN
    P-->>B: Signed login proof and local PRF result
    B->>S: Login proof only, never PRF result
    S->>S: Verify proof and create session
    S-->>B: Authenticated session
    B->>S: Request organization folder
    S->>S: Check current membership and read permission
    S-->>B: Encrypted key envelopes and secret values
    B->>B: PRF unlocks account key and encryption identity
    B->>B: Unlock organization key, then folder key
    B->>B: Decrypt values locally
    B-->>U: Display secrets
    U->>B: Edit a secret
    B->>B: Encrypt with folder key and fresh nonce
    B->>S: Send ciphertext and key version
    S->>S: Check write permission and current key version
    S->>S: Store encrypted value
```

An authenticated session and an unlocked client are separate states. Existing sessions may still need a local passkey unlock after reload or lock. Lock/logout clears decrypted key material from browser memory. PRF support must be proven on the supported browser/authenticator combinations before using production secrets.

## Invite a member

```mermaid
sequenceDiagram
    participant A as Admin browser, unlocked
    participant S as Server and Better Auth
    participant M as New member browser
    A->>S: Invite email with organization role
    M->>S: Verify identity and accept invitation
    M->>M: Enroll passkey, create encryption identity and recovery
    M->>S: Upload public key and encrypted personal key material
    S-->>M: Membership accepted, awaiting key approval
    A->>A: Verify member identity and encryption public key binding
    A->>A: Encrypt organization key to member public key
    A->>S: Upload authenticated member key envelope
    S->>S: Verify admin permission and envelope identity/version
    M->>S: Request organization data
    S->>S: Check member read permission
    S-->>M: Encrypted organization key, folder keys, and values
    M->>M: Unlock with passkey and decrypt locally
```

The server can deliver an already encrypted envelope; it cannot create a usable envelope for a new member on its own. Admin key verification needs an authenticated enrollment mechanism and an explicit verification method; merely trusting an arbitrary public key returned by the server is insufficient.

## Enroll and use the CLI

```mermaid
sequenceDiagram
    participant C as CLI on your computer
    participant B as Your browser
    participant S as Server and Better Auth
    C->>C: Generate device encryption key pair
    C->>S: Start device authorization and key enrollment
    C->>B: Open approval page
    B->>B: Passkey sign-in and local unlock
    B->>B: Verify enrollment binds this CLI key and request
    B->>B: Encrypt approved organization keys to CLI public key
    B->>S: Approve device and upload encrypted key envelopes
    C->>S: Redeem approved device request
    S-->>C: Session token and permitted encrypted envelopes
    C->>C: Store token and private key in OS credential store
    C->>S: Pull folder with organization ID
    S->>S: Check current membership and read permission
    S-->>C: Ciphertext and encrypted folder key
    C->>C: Unlock keys and decrypt locally
    C->>C: Write application secrets to .env
```

Push reverses the data path: encrypt on the CLI, check write permission on the server, store ciphertext. Project configuration contains only server/organization/folder identifiers. `.env` contains exported application secrets, with no vault password. Enrollment key binding and key delivery are application features added alongside the existing Better Auth device flow, not capabilities supplied by that flow alone.

## Recovery and removal

- Lost passkey: authenticate through the controlled recovery flow, then unlock with the offline encryption recovery key or a second enrolled PRF-capable passkey and enroll a replacement. An unlocked owner/admin can instead provision organization access to a verified replacement encryption identity. Email alone cannot decrypt encrypted secrets.
- Removed member/device: block subsequent API and envelope access immediately. An authorized unlocked client rotates organization and affected folder keys and provisions the remaining identities. Reject old-key writes; resume new writes after the new epoch is activated.
- Previously downloaded plaintext remains accessible to its holder. Rotate downstream credentials where required. Losing all usable decrypting identities and backups permanently loses access to the data.

E2EE protects stored values from server-side decryption. It does not hide metadata or protect against a compromised browser, CLI, or malicious application code delivered by the web origin.

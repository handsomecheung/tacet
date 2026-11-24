# Tacet Login & Authentication Specification

This document details the architecture, cryptographic pipelines, daemon REST contracts, and CLI interfaces for authenticating Tacet with upstream Bitwarden and self-hosted Vaultwarden servers.

Tacet supports two distinct authentication methods:
1. **Interactive Password Authentication** (`grant_type=password`) with optional Two-Factor Authentication (TOTP).
2. **API Key Authentication** (`grant_type=client_credentials`) designed for headless servers, automated scripts, and CI/CD pipelines.

---

## 1. Zero-Knowledge Security Model & Invariants

Both authentication methods strictly maintain Bitwarden's **zero-knowledge cryptographic guarantees**:

- **The upstream server never knows your decryption keys**: The server stores only ciphertext and salt metadata.
- **Tokens and keys are separated**: Possessing an OAuth access token authorizes the client to synchronize encrypted vault blobs (`CipherStrings`), but **cannot** decrypt any secrets without deriving or providing the Master Key.
- **In-Memory Custody Only**: Decrypted symmetric keys (`SymmetricKey`, 64 bytes) reside strictly in the memory of the background daemon (`tacetd`), protected with `ZeroizeOnDrop` allocations. Keys are never written to disk.
- **Auto-Lock Zeroization**: An idle auto-lock timer wipes symmetric keys from memory after a configurable duration (default: 30 minutes).

---

## 2. Password Authentication Flow (`grant_type=password`)

Password login authenticates using the account's master password and email, establishing both an authorized session and an unlocked key custody state in a single interactive workflow.

```
+---------------+     1. POST /identity/accounts/prelogin (email)      +--------------------+
|               | ---------------------------------------------------> |                    |
|               | <--------------------------------------------------- |                    |
|               |     2. Returns KDF params (KDF type, iterations)     |                    |
|               |                                                      |                    |
|               |     3. Key Derivation:                               |                    |
|               |        MasterKey = KDF(MasterPassword, Salt=email)   |                    |
|    tacetd     |        MasterPasswordHash = PBKDF2(MasterKey, iter=1)| Upstream Bitwarden |
|   (Daemon)    |                                                      | / Vaultwarden      |
|               |     4. POST /identity/connect/token                  |                    |
|               |        grant_type=password & password=Hash           |                    |
|               | ---------------------------------------------------> |                    |
|               | <--------------------------------------------------- |                    |
|               |     5. Returns access_token + Protected SymmetricKey |                    |
|               |                                                      |                    |
|               |     6. Decrypt Key:                                  |                    |
|               |        SymmetricKey = Decrypt(ProtectedKey, Stretched)                    |
|               |     7. GET /api/sync -> Encrypted Vault Cache        |                    |
+---------------+ ---------------------------------------------------> +--------------------+
```

### Detailed Cryptographic Steps:
1. **Prelogin (`POST /identity/accounts/prelogin`)**:
   Retrieves KDF configuration for the supplied email:
   - `kdf: 0`: PBKDF2-SHA256 (default: 600,000 iterations).
   - `kdf: 1`: Argon2id (iterations, memory limit in MB, parallelism).
2. **Master Key Derivation (32 Bytes)**:
   Derived using the master password and lowercase, trimmed email as salt:
   $$\text{MasterKey} = \text{KDF}(\text{password}, \text{salt} = \text{email})$$
3. **Master Password Hash Derivation**:
   Generated to authenticate against the identity server without exposing the master key:
   $$\text{MasterPasswordHash} = \text{Base64}(\text{PBKDF2-SHA256}(\text{password} = \text{MasterKey}, \text{salt} = \text{password}, \text{iter} = 1, \text{len} = 32))$$
4. **Token Exchange (`POST /identity/connect/token`)**:
   - `grant_type`: `"password"`
   - `username`: `<email>`
   - `password`: `<MasterPasswordHash>`
   - `scope`: `"api offline_access"`
   - `deviceType`: `25` (Linux) / `24` (macOS) / `23` (Windows)
   - `deviceIdentifier`: Persistent UUID from `~/.config/tacet/device_id`
   - `deviceName`: `"tacet-cli"`
5. **Two-Factor Authentication Handling**:
   If the upstream server returns HTTP 400 with `invalid_grant` and `TwoFactorProviders`, `tacet` catches the challenge and prompts the user for their 6-digit TOTP code, retrying with `twoFactorProvider=0` and `twoFactorToken=<code>`.
6. **Key Decryption & In-Memory Custody**:
   - The master key is stretched into encryption and MAC components via HKDF-Expand:
     $$\text{EncKey} = \text{HKDF}(\text{MasterKey}, \text{info} = \text{"enc"}, 32)$$
     $$\text{MacKey} = \text{HKDF}(\text{MasterKey}, \text{info} = \text{"mac"}, 32)$$
   - The user's account key (returned in `token_resp.Key` as a Type 2 CipherString) is verified via HMAC-SHA256 and decrypted with AES-256-CBC to yield the 64-byte `SymmetricKey`.
   - Master password and intermediate master keys are zeroized immediately.

---

## 3. API Key Authentication Flow (`grant_type=client_credentials`)

API Key authentication uses Bitwarden **Personal API Keys** (`client_id` starting with `user.`, plus a high-entropy `client_secret`) or **Organization API Keys**.

### Why API Key Login Requires Separate Decryption
The OAuth2 Client Credentials flow authenticates the client machine and authorizes syncing encrypted data, but the upstream server **never has custody of your master key or unencrypted symmetric key**. Therefore, API keys cannot decrypt secrets on their own.

Tacet bridges this gap by offering two ergonomic execution modes:
- **One-Shot Unlock**: Supplying the master password during API login (via flag `--password` or environment variable `TACET_PASSWORD`) immediately derives keys and leaves the daemon unlocked.
- **Two-Step Unlock**: Running API login without a password stores the session and syncs the vault in a `locked` state; subsequent `tacet unlock` invocations provide the password when secret resolution is needed.

```
+---------------+     1. POST /identity/connect/token                  +--------------------+
|               |        grant_type=client_credentials                 |                    |
|               |        client_id=user.xxx & client_secret=yyy        |                    |
|               | ---------------------------------------------------> |                    |
|               | <--------------------------------------------------- |                    |
|               |     2. Returns access_token                          |                    |
|               |                                                      |                    |
|               |     3. GET /api/sync (Bearer access_token)           |                    |
|    tacetd     | ---------------------------------------------------> | Upstream Bitwarden |
|   (Daemon)    | <--------------------------------------------------- | / Vaultwarden      |
|               |     4. Returns profile { email, key } + ciphers      |                    |
|               |                                                      |                    |
|               |     5. POST /identity/accounts/prelogin (email)      |                    |
|               | ---------------------------------------------------> |                    |
|               | <--------------------------------------------------- |                    |
|               |     6. Returns KDF settings for profile email        |                    |
|               |                                                      |                    |
|               |     [Optional One-Shot Step]                         |                    |
|               |     If master_password provided:                     |                    |
|               |        MasterKey = KDF(password, salt=profile.email) |                    |
|               |        SymmetricKey = Decrypt(profile.key, Stretched)|                    |
|               |        Daemon State: UNLOCKED                        |                    |
|               |     Else:                                            |                    |
|               |        Daemon State: LOCKED (awaiting tacet unlock)  |                    |
+---------------+                                                      +--------------------+
```

### Detailed Operational Steps:
1. **Client Credentials Exchange**:
   Sends `grant_type=client_credentials`, `client_id`, and `client_secret` to `POST /identity/connect/token`.
   - `client_id` is automatically normalized: trimmed of whitespace and quotes, and prepended with `user.` if supplied as a raw UUID without a prefix.
   - The OAuth `scope` is set to `api.organization` for organization API keys (`organization.<uuid>`) and `api` for personal keys (`user.<uuid>`).
2. **Profile & Vault Synchronization**:
   Calls `GET /api/sync` with the bearer token. The response contains `sync_resp.profile`, which exposes:
   - `profile.email`: The registered account email address.
   - `profile.key`: The user's Type 2 protected symmetric key.
   - `profile.privateKey`: The user's encrypted RSA-2048 private key (for organization collections).
3. **KDF Parameter Resolution**:
   Using `profile.email` (or a user-specified email override), `tacetd` queries `POST /identity/accounts/prelogin` to fetch the account's KDF algorithm and iteration count.
4. **Session Persistence**:
   Session metadata (`server_url`, `email`, normalized `api_client_id`, `access_token`, optional `refresh_token`, `expires_at`, `kdf_params`, and encrypted key metadata) is written to `~/.config/tacet/session.json` with strict Unix permissions (`0600`). The API client ID identifies the session's authentication method and account; the API client secret is not persisted. Password sessions have `api_client_id: null`.
5. **Decryption (If Password Provided)**:
   If `master_password` is provided, `tacetd` computes the master key and decrypts the symmetric key into memory, returning `unlocked: true`. If omitted, `tacetd` returns `unlocked: false`.

### Access Token Renewal and API-Key Recovery

Attachment reads and `tacet sync` require upstream authentication. Before either operation, the daemon checks whether the access token has expired or has 60 seconds or less remaining. It uses a refresh token when one is available. API-key sessions can have no refresh token; in that case, obtaining a new access token requires another `client_credentials` exchange.

When upstream authentication requires a new login, the daemon returns HTTP 401 with the structured error code `reauthentication_required`. The CLI handles that response as follows:

1. Read `TACET_CLIENT_ID` and `TACET_CLIENT_SECRET` from the current CLI process environment, falling back to `BW_CLIENTID` and `BW_CLIENTSECRET` respectively. The `TACET_` variables take precedence; missing or empty credentials leave the original error unchanged.
2. Read the daemon's current session status. Recovery is eligible only when the session has an `api_client_id` matching the normalized environment client ID. Password sessions and mismatched credentials do not trigger API-key authentication.
3. Send the credentials to `POST /v1/reauthenticate`. The daemon validates the client ID again and authenticates against the session's existing server; `TACET_SERVER` does not override that server during recovery.
4. Replace and persist the session tokens and expiry, preserving cached vault contents, decrypted keys, and the current lock state. No master password, prelogin request, or vault sync is needed for this token-only renewal.
5. Retry the original operation once. A failed reauthentication or a second authentication failure ends the command without further retries or interactive prompts. Recovery does not write login messages to stdout, preserving attachment output.

Server-rejected access tokens can trigger recovery even before their recorded expiry. HTTP 400 or 401 from a refresh attempt also requires reauthentication. Transient upstream errors and authentication failures from the separate attachment blob download do not trigger API-key recovery.

| Operation | Server token required | Behavior when the vault is locked |
|---|---|---|
| Attachment `read` | Yes; eligible for automatic recovery | Requires `tacet unlock` before downloading |
| `sync` | Yes; eligible for automatic recovery | Can sync; recovery leaves the vault locked |
| Field `read`, `inject`, `run` | No; values resolve from the local cache without token renewal | Requires `tacet unlock` |

The environment of an already running daemon can differ from that of the current CLI process. Credentials must be available to each CLI invocation that may need recovery; values supplied only to an earlier login command or only inside `run --env-file` are not process environment credentials for recovery.

When upgrading, update both `tacet` and `tacetd` and restart the daemon. Older session files load with `api_client_id: null`; perform one explicit API-key login after upgrading to record the authentication method and enable recovery. The absence of a refresh token alone is not treated as proof of an API-key session.

---

## 4. `tacetd` REST API Specification

### `POST /v1/login`
Establishes a session using either Password or API Key authentication.

#### Request Schema (`application/json`):
```json
{
  "server_url": "https://vault.bitwarden.com",
  
  // --- Password Flow ---
  "email": "user@example.com",
  "master_password": "SuperSecretPassword123!",
  "two_factor_provider": 0,
  "two_factor_token": "123456",

  // --- API Key Flow ---
  "client_id": "user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "client_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
```

#### Fields:
| Field | Type | Description |
|---|---|---|
| `server_url` | string | **Required**. Bitwarden / Vaultwarden endpoint URL. |
| `client_id` | string? | API client ID. If present along with `client_secret`, triggers API Key authentication. |
| `client_secret` | string? | API client secret. |
| `email` | string? | Account email. Required for Password flow; automatically resolved from profile in API Key flow. |
| `master_password` | string? | Master password. Required for Password flow; optional in API Key flow (omission leaves vault locked). |
| `two_factor_provider` | u8? | 2FA provider ID (`0` for Authenticator TOTP). |
| `two_factor_token` | string? | 6-digit TOTP code when responding to a 2FA challenge. |

#### Response (`200 OK`):
```json
{
  "unlocked": true,
  "item_count": 42
}
```

#### Error Responses:
- `400 Bad Request`: Missing mandatory parameters (e.g. neither valid API key nor email/password supplied).
- `401 Unauthorized`: Invalid credentials (bad client secret, bad password, or missing 2FA token).
- `502 Bad Gateway`: Upstream Bitwarden server unreachable or invalid profile returned.

---

### `POST /v1/unlock`
Restores key custody from a previously authenticated session without requiring re-login.

Unlock derives keys using cached session metadata and the supplied master password. It does not validate or renew upstream tokens and can succeed with an expired server token.

#### Request Schema (`application/json`):
```json
{
  "master_password": "SuperSecretPassword123!"
}
```

#### Response (`200 OK`):
```json
{
  "unlocked": true
}
```

### `GET /v1/status`

Returns daemon state, including the normalized API client ID for API-key sessions:

```json
{
  "running": true,
  "logged_in": true,
  "unlocked": true,
  "server_url": "https://vault.example.com",
  "api_client_id": "user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "item_count": 42
}
```

`api_client_id` is null for password sessions, legacy sessions, and logged-out state. `logged_in` indicates that a local session exists; it does not guarantee that its upstream access token remains valid.

### `POST /v1/reauthenticate`

Renews tokens for an existing API-key session without replacing the vault or changing its lock state. This endpoint is used by automatic CLI recovery; it is not a separate CLI command.

#### Request Schema (`application/json`):

```json
{
  "client_id": "user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "client_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
```

The normalized client ID must match the existing session. The server URL comes exclusively from that session. The client secret is used for the upstream token exchange, zeroized when the request is dropped, and never persisted.

#### Response (`200 OK`):

```json
{
  "authenticated": true
}
```

#### Error Responses:

- `400 Bad Request`: The current session is not an API-key session or its client ID does not match.
- `401 Unauthorized`: No current session, or the upstream server rejected the supplied credentials.
- `500 Internal Server Error`: Device metadata or session persistence failed.
- `502 Bad Gateway`: The upstream server could not complete the token exchange.

### Reauthentication Error Contract

Attachment reads and sync return the following response when a new upstream login is required:

```json
{
  "error": "Session expired. Run 'tacet login' again.",
  "code": "reauthentication_required"
}
```

The HTTP status is 401; the human-readable message can differ for rejected tokens or failed refresh attempts. Recovery relies on `code`, not message matching or HTTP 401 alone. Locked-vault errors do not carry this code. Blob-download failures and transient upstream failures return errors without triggering automatic reauthentication.

---

## 5. CLI Command Reference & Environment Variables

### Global & Subcommand Flags

#### `tacet login`
```bash
tacet login [OPTIONS]
```

| Flag | Env Variable | Description |
|---|---|---|
| `-s, --server <URL>` | `TACET_SERVER` | Server URL (default: `https://vault.bitwarden.com`) |
| `-e, --email <EMAIL>` | `TACET_EMAIL` | Account email address |
| `--apikey` | — | Force API Key authentication mode |
| `--client-id <ID>` | `TACET_CLIENT_ID` (or `BW_CLIENTID`) | API Client ID (`user.xxxx`) |
| `--client-secret <SECRET>` | `TACET_CLIENT_SECRET` (or `BW_CLIENTSECRET`) | API Client Secret |
| `--password <PWD>` | `TACET_PASSWORD` (or `BW_PASSWORD`) | Master Password (enables non-interactive unlock) |

#### `tacet unlock`
```bash
tacet unlock [--password <PWD>]
```
Unlocks a locked daemon session using the master password (either prompted interactively or read from `--password` / `TACET_PASSWORD` / `BW_PASSWORD`).

---

## 6. Headless & CI/CD Integration Examples

### Example 1: GitHub Actions / Automated Pipeline
In continuous integration environments, interactive prompts fail immediately. Store credentials as repository secrets and run `tacet` headlessly:

```yaml
name: Deploy Application

on:
  push:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      TACET_CLIENT_ID: ${{ secrets.BW_CLIENTID }}
      TACET_CLIENT_SECRET: ${{ secrets.BW_CLIENTSECRET }}
    steps:
      - uses: actions/checkout@v4

      - name: Install Tacet
        run: |
          curl -sSL https://raw.githubusercontent.com/.../scripts/build.sh | bash
          echo "$HOME/bin" >> $GITHUB_PATH

      - name: Authenticate Tacet via API Key
        env:
          TACET_SERVER: ${{ secrets.VAULT_URL }}
          TACET_PASSWORD: ${{ secrets.BW_PASSWORD }}
        run: |
          tacet login --apikey

      - name: Run Build with Injected Secrets
        run: |
          tacet sync
          tacet run -- npm run build && tacet run -- ./deploy.sh
```

The job-level API credentials are available to later CLI invocations, so `sync` and attachment reads can recover expired tokens without prompting. `TACET_PASSWORD` is needed for the initial unlock and is scoped to the login step here. Token recovery preserves the lock state; if the daemon subsequently auto-locks, provide the master password to `tacet unlock` before reading or injecting secrets.

### Example 2: Developer Local Terminal (Interactive)
```bash
# Interactive API key login
tacet login --apikey
# 1. Prompts for Server URL
# 2. Prompts for API Client ID
# 3. Prompts for API Client Secret
# 4. Prompts for Master Password (press Enter to leave locked)

# If left locked:
tacet unlock
```

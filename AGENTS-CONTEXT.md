# AI Agent Context for Tacet

`tacet` is a zero-knowledge CLI secret manager and environment injector compatible with Bitwarden and self-hosted Vaultwarden servers. It consists of a stateless CLI (`tacet`) and a background daemon (`tacetd`) communicating over a secure Unix Domain Socket (UDS).

This document outlines the architecture, cryptographic pipelines, security invariants, API specifications, and development rules for AI Agents operating on `koishi/tacet`.

---

## 1. Core Rules & Policies for Agents

1. **Security & Zeroization Invariants:**
   - **Never Persist Plaintext Secrets:** Sensitive values (passwords, tokens, TOTP seeds, decrypted notes/fields) must never be written to persistent storage or unredacted log files.
   - **Zeroize Keys on Drop:** All cryptographic keys (`SymmetricKey`, `StretchedMasterKey`, raw key slices) must implement `zeroize::Zeroize` or be wrapped in `zeroize::Zeroizing<T>`.
   - **Master Password Handling:** Master passwords must be wiped immediately after deriving KDF output.
   - **Strict File Permissions:** Any file containing authentication tokens or cached ciphers (`session.json`, `vault.cache`) must be created with Unix mode `0600`; enclosing directories must be `0700`.
   - **No TCP Listeners:** The daemon must never bind to network TCP sockets (`127.0.0.1`, `0.0.0.0`). It must exclusively communicate via Unix Domain Sockets (`tacetd.sock`).
   - **Peer Validation:** The daemon must inspect connecting socket peers (`SO_PEERCRED`) and reject any process whose UID does not match the daemon process UID with HTTP `403 Forbidden`.

2. **Code Integrity & Conventions:**
   - When comments are needed, write them in **English**.
   - Maintain idiomatic Rust code conforming to Rust 2021 edition.
   - Follow strict error handling with typed error enums (`thiserror`) and avoid panics (`unwrap()` / `expect()`) in production code paths.
   - Changes must pass `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check`.

3. **Git State Rule:**
   - Unless explicitly instructed otherwise by the user, **do not change the Git state** (do not stage changes, create commits, or push).

4. **URI Design & Ergonomics Policy ("The 'One Obvious Way' Principle"):**
   - **Single Canonical Representation:** There should be one—and preferably only one—obvious way to reference any secret. Avoid introducing redundant aliases, alternative shorthands, or syntactic synonyms (e.g. no `_` shorthand for `personal`, and strictly canonical scopes `personal`, `org`, `*`).
   - **No Built-in Field Aliases (Prevent Custom Field Collisions):** Bitwarden custom field names allow arbitrary strings. Adding alias shortcuts (like `user`, `pass`, `otp`, `note`, `url`) hijacks those names from custom fields and causes user confusion. All built-in field targets must strictly adhere to Bitwarden's canonical field names: `username`, `password`, `totp`, `totp_secret`, `notes`, `uri` (`uri.<n>`). Any other unqualified target first matches a custom field, then an attachment filename or ID.
   - **Deterministic Hierarchical Paths:** Allow `/` directly in folder and collection paths. Parse from the end using `<item>/<target>`, `<item>/fields/<custom_field>`, or `<item>/files/<filename-or-id>`; preceding segments form the folder or collection. The literal penultimate markers `fields` and `files` select custom fields and attachments explicitly. They reserve those path positions, including paths previously addressing an item named `files`. Determine the structure before percent-decoding names. Use `%2F` for slashes within organization, item, field, and attachment names. Existing encoded folder and collection paths remain supported. Never introduce heuristic or vault-dependent dynamic parsers; URI parsing must remain pure, static, and deterministic.
   - **Attachment Resolution:** Unqualified targets match built-in fields, custom fields, then attachments. Fall back only when a field is absent, never on empty values or decryption errors. Filenames match exactly and case-sensitively; exact attachment IDs take priority. Duplicate filenames return ambiguity errors with matching IDs. Explicit `fields/` targets cannot select attachments.
   - **Attachment Output:** `read` writes attachment bytes to stdout without UTF-8 conversion, trimming, or a trailing newline. Base64 and hex encode the original bytes; explicit `trim` and `json` modifiers are rejected. Shell redirection is controlled by the caller; do not introduce plaintext attachment caches or temporary files. `inject`, `run`, and `/v1/resolve` support explicit and implicit attachment matches through the same download and decryption path as `read`. Decode attachments as strict UTF-8 after any encoding, preserving all whitespace (`trim=false` by default); invalid UTF-8 is an error. `run` rejects NUL-containing environment values before spawning a child. Any resolution failure aborts before writing output or executing the child.

---

## 2. Project Architecture & Codebase Structure

```text
koishi/tacet/
├── Cargo.toml
├── scripts/
│   └── build.sh                # Release build and ~/bin/ installation script
├── src/
│   ├── lib.rs
│   ├── bin/
│   │   ├── tacet.rs            # CLI binary entrypoint
│   │   └── tacetd.rs           # Daemon binary entrypoint
│   ├── crypto/                 # Bitwarden-compatible cryptographic primitives
│   │   ├── mod.rs
│   │   ├── cipher_string.rs    # Type 2 (AES-CBC+HMAC) & Type 4 (RSA-OAEP) parsing/decryption
│   │   ├── hkdf.rs             # HKDF-Expand for encryption & MAC keys
│   │   ├── kdf.rs              # PBKDF2-SHA256 & Argon2id master key derivation
│   │   ├── key.rs              # Zeroizing SymmetricKey custody container
│   │   └── password_hash.rs    # MasterPasswordHash derivation for upstream OAuth
│   ├── upstream/               # Bitwarden / Vaultwarden API client
│   │   ├── mod.rs
│   │   ├── client.rs           # reqwest-based API client (prelogin, token, sync, attachment download)
│   │   ├── endpoints.rs        # URL discovery for official & self-hosted servers
│   │   └── models.rs           # Serde models for sync, tokens, and ciphers
│   ├── storage/                # Local encrypted storage & configuration
│   │   ├── mod.rs
│   │   ├── paths.rs            # XDG base directories (~/.config/tacet, ~/.cache/tacet, $XDG_RUNTIME_DIR)
│   │   ├── session.rs          # Session metadata persistence (tokens, server URL, key hashes)
│   │   └── vault_cache.rs      # Encrypted vault cache persistence (vault.cache)
│   ├── uri/                    # tacet:// URI parser & AST
│   │   ├── mod.rs
│   │   ├── parser.rs           # URI syntax parser (scope, item, field, query modifiers)
│   │   └── types.rs            # Scope, FieldTarget, and QueryModifiers types
│   ├── resolver/               # Secret resolution engine
│   │   ├── mod.rs
│   │   ├── engine.rs           # Vault traversal, item matching, and field extraction
│   │   ├── json_path.rs        # Nested JSON dot-path evaluation
│   │   └── totp.rs             # Live RFC 6238 TOTP calculation (totp-rs)
│   ├── daemon/                 # HTTP-over-UDS server (axum)
│   │   ├── mod.rs
│   │   ├── app.rs              # axum router setup
│   │   ├── routes.rs           # REST endpoints (status, login, unlock, lock, logout, sync, resolve, read, list, attachments)
│   │   ├── server.rs           # UnixListener bind, socket permission enforcement & peer UID check
│   │   └── state.rs            # In-memory custody state and idle auto-lock background timer
│   └── cli/                    # CLI execution & process management
│       ├── mod.rs
│       ├── client.rs           # HTTP client over Unix Domain Socket
│       ├── commands/           # Subcommands (login, unlock, lock, logout, status, sync, list, read, inject, run)
│       ├── masker.rs           # Real-time stdout/stderr secret stream redaction
│       ├── run.rs              # Process spawn, env injection, and streaming output handler
│       └── autospawn.rs        # Automatic background daemon spawning wrapper
└── tests/                      # Integration test suites
    ├── attachment_tests.rs
    ├── cli_tests.rs
    ├── crypto_tests.rs
    ├── daemon_tests.rs
    ├── resolver_tests.rs
    ├── storage_tests.rs
    ├── upstream_tests.rs
    └── uri_tests.rs
```

---

## 3. Cryptographic Pipeline Specifications

All cryptographic operations strictly adhere to the Bitwarden Cryptographic Specification:

```
[Master Password] + [Email (lowercase, trimmed)]
                       │
                       ▼
       ┌───────────────────────────────┐
       │ KDF: PBKDF2-SHA256 / Argon2id │
       └───────────────┬───────────────┘
                       │
                       ▼
               [Master Key (32B)]
               /               \
              /                 \
             ▼                   ▼
┌─────────────────────────┐   ┌─────────────────────────┐
│ PBKDF2-SHA256 (1 iter)  │   │ HKDF-Expand (SHA-256)   │
│ salt = Master Password  │   │ info = b"enc" / b"mac"  │
└────────────┬────────────┘   └────────────┬────────────┘
             │                             │
             ▼                             ▼
   [MasterPasswordHash]           [StretchedMasterKey (64B)]
             │                             │
             ▼                             ▼
   POST /identity/token          Decrypt Protected SymmetricKey
             │                             │
             ▼                             ▼
       [OAuth Token]                 [SymmetricKey (64B)]
                                     ├── EncKey (32B)
                                     └── MacKey (32B)
```

1. **Prelogin (`POST /identity/accounts/prelogin`):**
   - Retrieves KDF type: `0` (PBKDF2-SHA256) or `1` (Argon2id).
   - Parameters: PBKDF2 iterations (default: 600,000) or Argon2id iterations, memory (MB), and parallelism.
2. **Master Key Derivation (32 Bytes):**
   - Derived using `master_password` with `email.trim().to_lowercase()` as the salt.
3. **Master Password Hash & Upstream Authentication:**
   - `Base64(PBKDF2-SHA256(password = MasterKey, salt = master_password, iterations = 1, dkLen = 32))`
   - Authenticates against `POST {server}/identity/connect/token` via `grant_type=password`.
   - Submits client device parameters required by Vaultwarden/Bitwarden: `deviceType` (`25` on Linux), `deviceIdentifier` (persistent UUID from `~/.config/tacet/device_id`), and `deviceName` (`tacet-cli`).
4. **Stretched Master Key (64 Bytes):**
   - HKDF-Expand with SHA-256: `EncKey = HKDF(MasterKey, info = b"enc", 32)` and `MacKey = HKDF(MasterKey, info = b"mac", 32)`.
5. **Decryption of User Symmetric Key:**
   - The user's encrypted `Key` is returned during login as a `Type 2` CipherString.
   - Decrypted using `StretchedMasterKey` to yield the final 64-byte `SymmetricKey`.
   - Master password and intermediate master keys are immediately zeroized.
6. **CipherString Formats:**
   - **Type 2 (`Aes256_HmacSha256_B64`):** Format `2.<iv_b64>|<ciphertext_b64>|<mac_b64>`. Decryption verifies constant-time HMAC-SHA256 over `iv + ciphertext` with `MacKey` before AES-256-CBC decryption with `EncKey`.
   - **Type 4 (`Rsa2048_OaepSha1_B64`):** Format `4.<ciphertext_b64>`. Decryption uses RSA-2048 private key with OAEP padding and SHA-1 digest (used for organization symmetric keys).

---

## 4. `tacetd` HTTP-over-UDS API Contract

### Transport & Security
- **Socket Path:** `$XDG_RUNTIME_DIR/tacet/tacetd.sock` (fallback: `/tmp/tacet-$UID/tacetd.sock`).
- **Permissions:** Directory `0700`, socket file `0600`.
- **Peer Check:** Peer UID verified on connection; mismatches return `403 Forbidden`.
- **Auto-Lock:** Background task locks in-memory keys after `idle_ttl` (default: 30 minutes).

### REST Endpoints

| Method & Path | Request Body | Success Response (`200 OK`) | Error Codes | Notes |
|---|---|---|---|---|
| `GET /v1/status` | None | `{"running": true, "logged_in": bool, "unlocked": bool, "server_url": string, "api_client_id": string?, "item_count": u32}` | — | Health and state check |
| `POST /v1/login` | `{"server_url": string, "email": string?, "master_password": string?, "client_id": string?, "client_secret": string?, "two_factor_token": string?}` | `{"unlocked": bool, "item_count": u32}` | 400, 401, 502 | Upstream password or API key auth, sync, unlock |
| `POST /v1/reauthenticate` | `{"client_id": string, "client_secret": string}` | `{"authenticated": true}` | 400, 401, 500, 502 | Renew tokens for the same API-key session; preserve cache and lock state |
| `POST /v1/unlock` | `{"master_password": string}` | `{"unlocked": true}` | 400, 401 | Restores SymmetricKey into memory |
| `POST /v1/lock` | None | `{"locked": true}` | — | Zeroizes SymmetricKey immediately |
| `POST /v1/logout` | None | `{"logged_out": true}` | — | Zeroizes keys and purges local storage |
| `POST /v1/sync` | None | `{"synced": true, "item_count": u32}` | 401, 502 | Refreshes token & updates vault cache |
| `POST /v1/resolve` | `{"uris": [string]}` | `{"secrets": {string: string}}` | 400, 401, 404, 409, 413, 500, 502 | Batch field and attachment resolution; attachment output must be valid UTF-8 after encoding |
| `POST /v1/read` | `{"uri": string}` | Raw value bytes | 400, 401, 404, 409, 413, 500, 502 | Single field or attachment; no extra newline |
| `GET /v1/items/{item_id}/attachments` | None | `{"attachments": [{"id": string, "name": string, "uri": string}]}` | 400, 401, 404, 409, 500, 502 | Lists cached attachment metadata by item UUID without downloading contents |
| `GET /v1/list` | None (Query: `?scope=..&search=..`) | `{"items": [{"id": "..", "name": "..", "scope": "..", "folder": "..", "cipher_type": "..", "uri_prefix": ".."}], "total": usize}` | 400, 401, 500 | Lists cached item summaries with decrypted names or UUID fallbacks |

For `GET /v1/list`, organization items produce one entry per collection membership, with the same item `id` and a collection-specific `scope` and `uri_prefix`. Scope and search filters apply to each entry independently. `total` counts returned entries, not unique items. Entries are sorted by item name, then scope, then item ID. `tacet list --json` outputs the same entries as an array; the table footer reports both entry and unique item counts.

Listing must retain empty and attachment-only items. If the name is empty or the name, item key, or organization key cannot be decrypted, use the item's UUID as its displayed name and URI item target rather than skipping the item. Preserve every collection membership even when collection names cannot be decrypted, using collection UUIDs as fallback names. These fallback entries still obey scope/search filters and the unlocked-vault requirement; their presence does not imply that secret reads can succeed.

Listing, attachment discovery, and URI lookup use the daemon's in-memory vault cache without automatic sync. Search filters match item names, IDs, folders, and scopes, not attachment filenames. Old cache schemas may have discarded attachment metadata; refresh with `tacet sync` after upgrading or changing vault items elsewhere. `unlock` only restores decryption keys and cannot renew upstream authentication. A cached item/attachment lookup failure returns 404 before any download; obtaining the download URL or downloading the blob can also return an upstream 404.

Persist the normalized, non-secret `api_client_id` for API-key logins and clear it for password logins. Missing values in older sessions default to null and never imply API-key login. Upstream authentication failures from attachment downloads in `read` or `resolve`, or from `sync`, return HTTP 401 with `code: "reauthentication_required"`; locked-vault errors, blob-download authentication errors, and transient upstream failures do not use that code. These upstream operations share token expiry and refresh handling. The CLI retries a coded failure once after authenticating through `/v1/reauthenticate`, using `TACET_CLIENT_ID`/`TACET_CLIENT_SECRET` (with `BW_CLIENTID`/`BW_CLIENTSECRET` fallbacks) from its own process environment. Require a matching session client ID on both sides and use the existing session's server, never an environment server override. Do not persist API client secrets or require a master password for token-only renewal. Reauthentication must preserve the vault, keys, and lock state. Legacy sessions require one explicit API-key login to enable recovery.

Text-field resolution through `/v1/resolve` (including `inject` and `run`) and `/v1/read` uses the local cache without validating server tokens or triggering reauthentication. Attachments in either endpoint require online downloads and support the same automatic recovery as sync. All secret resolution requires an unlocked vault. Upgrade both binaries and restart the daemon before enabling recovery for a legacy session.

Deserialize `SyncResponse.ciphers` with the shared filter that excludes non-null `deletedDate`. This applies to upstream sync and cache loading, so listing, status counts, field resolution, injection, and attachment access all exclude trashed items, including UUID lookups. Missing/null deletion dates remain compatible with older servers. Caches written by older Tacet versions discarded this date and require one fresh `tacet sync` after upgrading; the missing state cannot be reconstructed offline.

Archive state is a per-user preference and must not affect Tacet's usable vault. Do not filter archived items or model `archivedDate`; archived items remain listable, readable, and injectable. After upgrading from a version that filtered archived items, sync again to restore those entries to the cache.

For `POST /v1/read`, `Content-Type` is `application/octet-stream` for raw attachments and `text/plain; charset=utf-8` for fields or encoded attachments. `X-Tacet-Value-Kind` is `field` or `attachment`, identifying the value kind. The CLI writes the returned bytes without appending a newline for either kind. Text fields preserve leading and trailing whitespace by default (`trim=false`); trimming requires an explicit `trim=true` URI modifier, including in `inject` and `run`. Responses include `Cache-Control: no-store`.

Attachment reads obtain a fresh URL from upstream `GET /ciphers/{cipher_id}/attachment/{attachment_id}`, falling back to the sync-provided URL only if that endpoint returns 404. Blob requests never carry the vault bearer token. Type 2 binary payloads contain `type || IV || MAC || ciphertext`; verify HMAC before decrypting or returning any plaintext. Attachment names and dedicated keys use the item's effective key, including wrapped item keys; legacy attachments without dedicated keys use the user or organization key. All decrypted key material must be zeroized. The initial implementation buffers encrypted attachments with a 64 MiB limit enforced against both content length and received chunks. No plaintext files are created. Release key guards before network requests and recheck the unlocked state before decryption, so locking remains responsive during downloads.

---

## 5. CLI Execution & Safety Guarantees

1. **Automatic Daemon Management (`ensure_daemon_running`):**
   - The CLI tests connectivity to the UDS socket before executing commands.
   - If unreachable, it forks/spawns `tacetd` detached and polls `/v1/status` until ready (timeout: 5 seconds).
2. **Fail-Fast Policy:**
   - In `tacet run` and `tacet inject`, if any URI fails to resolve (e.g. locked vault, missing item, ambiguous match), the command aborts immediately with a non-zero exit code before child process execution. In directory injection, `--in-dir` requires exactly one of `--out-dir` or `--in-place`. All URIs across the directory are resolved in one batch and nothing is written if any fails. With `--out-dir`, existing outputs require `--force`. With `--in-place`, exactly one of `-i`/`--in` or `--in-dir` is required; stdin is unsupported. Only templates are replaced, without requiring `--force`; `-o`/`--out`, `--out-dir`, `--force`, and `--copy-all` are incompatible. Symlinks, including dangling symlinks, are skipped. Non-UTF-8 files are skipped in directory mode; a non-UTF-8 single-file input returns an error without changes. Output and replaced files have mode `0600`. Each file replacement is atomic, but a write failure can leave a partially updated directory. In-place replacement removes the original references, so rerunning does not refresh injected secrets.
3. **Real-Time Stream Masking (`tacet run`):**
   - Secrets of length $\ge 4$ characters are registered into a thread-safe stream filter.
   - `stdout` and `stderr` streams of the child process are monitored line by line and matching secret tokens are redacted to `[TACET_MASKED]`. Register individual lines of multiline secrets as well as the full value, using the same minimum of four bytes per line.

---

## 6. Development & Verification Workflows

When implementing or modifying features:

```bash
# 1. Run all unit and integration tests
cargo test

# 2. Check clippy lints with warnings treated as errors
cargo clippy --all-targets -- -D warnings

# 3. Check code formatting
cargo fmt --check

# 4. Verify binary builds
cargo build --bin tacet --bin tacetd
```

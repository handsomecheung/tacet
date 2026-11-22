# Tacet

A fast, zero-knowledge CLI secret manager and environment injector compatible with **Bitwarden** and self-hosted **Vaultwarden** servers.

Inspired by the developer ergonomics of 1Password CLI (`op`), Tacet eliminates plaintext `.env` files on disk, avoids secret leakage into shell histories or process tables, and provides sub-5ms secret resolution via a local background daemon.

---

## Architecture

Tacet is built with a decoupled client-daemon architecture:

* **`tacetd` (Stateful Background Daemon):**
  An `axum`-powered HTTP/1.1 REST server listening exclusively over a Unix Domain Socket (`tacetd.sock`). It acts as the single secure custody point for OAuth tokens, encrypted vault cache, and decrypted symmetric keys in memory (with automatic idle auto-lock zeroization).
* **`tacet` (Stateless CLI Client):**
  A fast, lightweight CLI binary that parses templates and flags, communicates with `tacetd` over the Unix socket, injects resolved secrets directly into child process memory, and redacts sensitive strings from `stdout` and `stderr` streams in real time.

```
                      +-----------------------------+
                      | Upstream Bitwarden /        |
                      | Vaultwarden Server          |
                      +--------------+--------------+
                                     ^
                         HTTPS sync  |  OAuth login
                                     v
+------------------------------------+------------------------------------+
|  tacetd (Background Daemon)                                             |
|                                                                         |
|  [Unix Domain Socket: $XDG_RUNTIME_DIR/tacet/tacetd.sock (0600)]        |
|  - Peer UID verification via SO_PEERCRED                                |
|  - In-memory key custody (ZeroizeOnDrop, idle auto-lock timer)          |
|  - Local encrypted storage: ~/.config/tacet/ & ~/.cache/tacet/ (0600)   |
|  - RFC 6238 live TOTP generation & Type 2 / Type 4 decryption           |
+------------------------------------+------------------------------------+
                                     ^
                         HTTP / UDS  |  JSON RPC (<5ms)
                                     v
+------------------------------------+------------------------------------+
|  tacet (Stateless CLI Client)                                           |
|                                                                         |
|  tacet login  |  tacet unlock  |  tacet read  |  tacet inject           |
|  tacet run -- <cmd> (memory injection + real-time stream masking)       |
+-------------------------------------------------------------------------+
```

---

## Features

- **Zero-Knowledge Security:** All cryptographic operations follow Bitwarden's security model. Master passwords and keys are zeroized immediately after use.
- **Lightning Fast (<5ms):** Reads and injects secrets directly from the local daemon's decrypted memory cache without repeated network requests or decryption overhead.
- **Fail-Fast Guarantees:** Aborts process execution before launching child commands if any referenced secret cannot be resolved or is locked.
- **Real-Time Stream Masking:** Transparently monitors child process `stdout` and `stderr` in `tacet run`, masking sensitive values with `[TACET_MASKED]`.
- **Dynamic TOTP Generation:** Live RFC 6238 6-digit TOTP code calculation from Bitwarden authenticator keys.
- **Attachment Downloads:** Read authenticated, encrypted attachments by filename or ID and write their original bytes to stdout, with optional base64 or hex encoding.
- **Flexible `tacet://` URIs:** Expressive URI format supporting folders, organizations, collections, custom fields, and modifiers (e.g. `base64`, `json=<path>`, `trim`).

---

## Installation & Building

Prerequisites: Rust 1.80+ (Cargo).

```bash
# Option 1: Build release binaries via the helper script (does not install)
./scripts/build.sh

# Option 2: Build with cargo directly
cargo build --release

# The compiled binaries will be located at:
# target/release/tacet
# target/release/tacetd
```

---

## Quickstart

### 1. Authenticate & Initial Sync
Log in to your Bitwarden or Vaultwarden account. If `tacetd` is not already running, `tacet` will automatically spawn it in the background:

```bash
# Official Bitwarden Cloud
tacet login --email user@example.com

# Self-Hosted Vaultwarden
tacet login --server https://vault.example.com --email user@example.com

# API Key Login (Headless / CI/CD)
tacet login --apikey --client-id "user.xxxx" --client-secret "yyyy"
# Or with environment variables: TACET_CLIENT_ID, TACET_CLIENT_SECRET, TACET_PASSWORD
```

### 2. Check Daemon Status
Inspect authentication status, server endpoint, lock state, and cached item counts:

```bash
tacet status
```

### 3. List Vault Items
List items, folders, and URI prefixes in a formatted table or JSON:

```bash
# List all items
tacet list

# Filter by scope or search query
tacet list personal
tacet list -q "github"

# JSON output
tacet list --json
```

Listed URI prefixes preserve `/` in nested folder and collection paths. Append a field target such as `/password` to read a secret.

Empty items and items containing only attachments are included. If an item's name is empty or its name or item key cannot be decrypted, the list displays its UUID as the name and URI item target instead of omitting it. Organization items with unavailable organization keys are also retained; collection UUIDs stand in for unavailable collection names. Scope and search filters still apply. Listing an item does not guarantee that its contents can be decrypted.

Organization items appear once per collection membership, with a scope and URI prefix for each collection. Scope and search filters apply to each entry separately. JSON output uses the same entries, so an item in multiple collections has multiple records with the same `id`. The table footer reports both the number of entries and the number of unique items, for example `Total: 2 entries (1 unique item)`.

`list` and item/attachment lookup use the daemon's local vault cache; they do not automatically sync with the server. Search matches item names, UUIDs, folders, and scopes, not attachment filenames. Run `tacet sync` after changing items or attachments in another client.

### 4. Read a Secret or Attachment
Fetch a single secret field or attachment to standard output:

```bash
# Print password
tacet read "tacet://personal/GitHub/password"

# Generate live TOTP token
tacet read "tacet://personal/AWS/totp"

# Download an attachment; use files/ to select an attachment explicitly
tacet read "tacet://personal/Server/example.exe" > example.exe
tacet read "tacet://personal/Server/files/example.exe" > example.exe

# Encode the attachment's original bytes
tacet read "tacet://personal/Server/files/example.exe?encoding=base64" > example.exe.b64
```

All reads write the resolved value without appending a newline, including encoded reads. The former `--no-newline` (`-n`) option has been removed because this is now the default behavior. Field reads preserve original whitespace by default (`trim=false`); use `?trim=true` to remove leading and trailing whitespace. Attachment reads preserve all original whitespace and binary bytes. Diagnostics go to stderr. Redirected files are created or truncated by the shell before Tacet runs; their permissions follow your shell's `umask`. Parent directories must already exist.

Attachments require an unlocked vault and an online server. After upgrading from a version without attachment support, run `tacet sync` to refresh cached attachment metadata. Downloads are verified before any contents are returned. The initial implementation buffers encrypted files in memory, limits each encrypted download to 64 MiB, and supports authenticated Type 2 attachment payloads, including legacy attachments without a dedicated key and modern attachments using item keys. Larger files and other payload formats return an error.

If a newly added item is missing from `list`, or an attachment lookup returns 404, refresh the cache with `tacet sync`. Older cache files may contain items without their attachment metadata. If syncing fails with an upstream 401, repeat your usual `tacet login` command to obtain a valid session; unlocking alone does not renew an expired access token. Then retry syncing and reading the attachment. A successful sync does not resolve a 404 caused by an incorrect reference or an attachment that was deleted upstream.

### 5. Template Injection
Replace `{{ tacet://... }}` placeholders in configuration templates without writing secrets to disk:

```bash
# Render template file to destination
tacet inject -i config.template.json -o config.json

# Stdin / Stdout pipeline
cat template.env | tacet inject > .env

# Recursively render a directory into another directory
tacet inject --in-dir ./templates --out-dir ./rendered
```

Directory mode (`--in-dir` / `--out-dir`, which cannot be combined with `-i`/`-o`):

- Mirrors the input structure; only files containing placeholders are written. Add `--copy-all` to also copy all other files (including binary ones) unchanged.
- Symlinks are skipped, and non-UTF-8 files are skipped unless `--copy-all` is given.
- `--out-dir` must not be inside `--in-dir`.
- If any output file already exists the command fails before writing anything; pass `--force` to overwrite.
- All URIs are resolved in one batch first; any failure aborts without writing files.
- Output files are created with mode `0600` and new directories with `0700`.

### 6. Run Commands with Secret Injection
Pass secrets directly into environment variables with real-time output redaction:

```bash
# Inject secrets from a .env file containing tacet:// references
tacet run --env-file .env -- npm start

# Or execute commands directly
DATABASE_URL="tacet://personal/Database/uri" tacet run -- ./migrate.sh
```

### 7. Lock and Unlock
Lock key custody manually, or restore session using your Master Password:

```bash
# Lock in-memory keys
tacet lock

# Unlock session
tacet unlock
```

---

## `tacet://` URI Specification

Tacet uses a standardized URI format to reference secrets:

```text
tacet://<scope>/<item>/<target>[?<modifiers>]
```

### 1. `<scope>` Rules

| Scope | Target |
|---|---|
| `personal` | Personal vault (`organizationId == null`), ignoring folder hierarchy |
| `personal/<folder>` | Items inside a specific personal folder (nested paths like `folder/subfolder` use `/` directly) |
| `org/<org_name>/<collection>` | Shared items inside an Organization's collection (nested paths like `col1/col2` use `/` directly) |
| `*` | Search all accessible vaults (fails fast if ambiguous) |

### 2. `<item>` Rules

- Case-insensitive search by item `name` (e.g., `GitHub`, `Postgres DB`).
- Supports exact 36-character item `UUID` (e.g., `d3b07384-d113-46fb-9c88-e9f02c61e808`).
- Nested collection and folder paths use `/` directly, e.g. `tacet://org/Default/Network/Koishi/Infra/wireproxy/password`. Existing `%2F`-encoded paths remain supported.
- Paths are parsed from the end: `<item>/<target>`, `<item>/fields/<custom_field>`, or `<item>/files/<filename-or-id>`. The preceding path is the collection or folder. The literal `fields` and `files` segments immediately before the final segment introduce an explicit custom field or attachment, respectively.
- Spaces can be preserved inside quotes; slashes inside organization, item, and field names must be encoded as `%2F`.
- If multiple items match the query, Tacet returns a disambiguation error listing matching UUIDs and folders.

### 3. `<target>` Mapping

| Bitwarden Field | URI Target | Description |
|---|---|---|
| `login.username` | `username` | Plaintext username |
| `login.password` | `password` | Plaintext password |
| `login.totp` | `totp` | Live 6-digit RFC 6238 TOTP code |
| `login.totp` (raw) | `totp_secret` | Raw TOTP secret / `otpauth://` URI |
| `login.uris[0].uri` | `uri` / `uri.0` | Primary URL (`uri.<n>` for index `n`) |
| `notes` | `notes` | Secure note content |
| `fields[name == X]` | `fields/<X>` or `<X>` | Custom field matching name `X` (falls back if built-in not matched) |
| `attachments` | `files/<filename-or-id>` or `<filename-or-id>` | Attachment content; filenames are matched exactly and case-sensitively |

Unqualified targets match a built-in field first, then a custom field, then an attachment. An empty matching field is returned as empty; a decryption error stops resolution rather than selecting an attachment. Explicit `fields/` targets never select attachments, and explicit `files/` targets never select fields. Attachment IDs take priority over filenames; duplicate filenames return an error listing matching attachment IDs. Encode `/`, `?`, `#`, and `%` within filenames as `%2F`, `%3F`, `%23`, and `%25`.

`files` is now a reserved penultimate path segment, like `fields`. For example, `personal/Server/files/config.yml` selects an attachment on `Server`; it no longer addresses the field `config.yml` on an item named `files` inside folder `Server`. Use that item's UUID and an explicit `fields/` target to address such a field.

### 4. `[?<modifiers>]` (Optional Query Parameters)

- `encoding=base64`: Encode multi-line secrets or binary values into base64.
- `encoding=hex`: Encode value as lowercase hexadecimal string.
- `json=<dot.path>`: Parse JSON payload and extract field (e.g., `?json=credentials.client_secret`).
- `trim=true|false`: Strip leading/trailing whitespace and newlines when `true` (default: `false`).

For attachments, `encoding=base64` and `encoding=hex` operate on the original bytes. Trimming does not apply. Explicit `trim` and `json` modifiers are rejected. Attachment references are supported by `tacet read`; `inject` and `run` continue to accept text fields only.

---

## CLI Reference

### Global Options

```bash
tacet [--socket <path>] <subcommand>
```

### Session Management

```bash
tacet login [--server <url>] [--email <email>] [--apikey] [--client-id <id>] [--client-secret <secret>] [--password <pwd>]
tacet unlock [--password <pwd>]
tacet lock
tacet logout
tacet status
tacet sync
```

### Vault Exploration & Secret Consumption

```bash
# List vault items (table or json)
tacet list [scope] [-q <query>] [--json]

# Output a secret field or attachment bytes
tacet read <uri>

# Inject into file templates
tacet inject [-i <template_file>] [-o <output_file>]

# Execute process with injected environment variables
tacet run [--env-file <file>] [--no-mask] -- <command> [args...]
```

---

## Storage & Security Model

- **Configuration:** `~/.config/tacet/session.json` (mode `0600`) stores server URL, email, and user public/private key metadata.
- **Device ID:** `~/.config/tacet/device_id` (mode `0600`) stores a persistent UUIDv4 to identify the client installation to Vaultwarden and Bitwarden servers.
- **Cache:** `~/.cache/tacet/vault.cache` (mode `0600`) caches encrypted CipherStrings directly from Bitwarden.
- **Socket:** `$XDG_RUNTIME_DIR/tacet/tacetd.sock` (mode `0600`, directory `0700`) enforces local peer UID validation via `SO_PEERCRED`. No TCP sockets are bound, preventing DNS-rebinding and browser-based CSRF attacks.
- **Key Custody:** Symmetric keys reside strictly within `tacetd` memory inside zeroizing allocations (`ZeroizeOnDrop`) and are wiped on idle timeout (default: 30 minutes) or explicit lock/logout.

---

## Testing

Run all unit and integration test suites:

```bash
cargo test
```

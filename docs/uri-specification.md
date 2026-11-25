# Tacet URI Specification

In Tacet, all secret references follow the `tacet://` URI specification parsed in [parser.rs](../src/uri/parser.rs) and resolved in [vault_resolver.rs](../src/resolver/vault_resolver.rs).

The general format is:
```text
tacet://<scope>/<item>/<field>[?<modifiers>]
```

Below is a comprehensive breakdown of all supported patterns categorized by **Scope**, **Item identifiers**, **Field targets**, and **Query modifiers**, with practical examples for each.

---

### 1. Scope Patterns (`<scope>`)

The scope determines the boundary within which Tacet looks up items in your Bitwarden / Vaultwarden vault.

| Pattern | Description | Example |
|---|---|---|
| `personal/<item>/<field>` | Personal vault item (without folder restriction) | `tacet://personal/GitHub/password` |
| `personal/<folder>/<item>/<field>` | Items located inside a specific personal folder (nested paths like `folder/subfolder` use `/` directly) | `tacet://personal/Work/AWS/totp`<br>`tacet://personal/Dev/Frontend/Vercel/token` |
| `org/<org_name>/<collection>/<item>/<field>` | Items inside an Organization's collection (nested paths like `col1/col2` use `/` directly) | `tacet://org/AcmeCorp/Infrastructure/ProdDB/password`<br>`tacet://org/Default/DevOps/Infra/K8s/token` |
| `org/<org_name>/<UUID>/<field>` | Organization item by UUID, without collection restriction | `tacet://org/AcmeCorp/d3b07384-d113-46fb-9c88-e9f02c61e808/password` |

Wildcard scope (`*`, including `%2A`) is no longer supported and returns an explicit URI error. Migrate existing wildcard URIs to `personal` or `org/...`. For listing all cached items, omit the scope (`tacet list`); `tacet list '*'` is rejected.

Personal folders may be omitted. Organization collections may be omitted only when `<item>` is an exact 36-character UUID; name references still require a collection. Organization identifiers may be names or IDs. All item lookups remain within the specified scope, including UUID lookups.

For `personal` and `org` scopes, paths are parsed from the end: `<item>/<field>`, `<item>/fields/<custom_field>`, or `<item>/files/<filename-or-id>`. The preceding segments after the scope keyword (and organization identifier for `org`) form the optional folder or collection path. A `fields` or `files` segment immediately before the final segment introduces an explicit custom field or attachment when an item precedes it. Slashes within organization, item, field, and attachment names must use `%2F`; existing `%2F`-encoded folder and collection paths remain supported.

`tacet list` and `GET /v1/list` return item URI prefixes with `/` preserved in folder and collection paths, such as `tacet://org/Default/Network/Koishi/Infra/wireproxy`. Append `/password` or another field target to read a secret.

An organization item belonging to multiple collections produces one entry per collection, each with its own `scope` and `uri_prefix`. These entries share the same item `id`. Scope and search filters apply to each entry independently, so filtering by a collection returns only the matching membership. Results are sorted by item name, then scope, then item ID, independently of collection membership order.

`GET /v1/list` reports the number of returned entries in `total`, which can exceed the number of unique item IDs. `tacet list --json` outputs the entries as an array with the same repeated IDs. The table footer distinguishes the two counts, for example `Total: 2 entries (1 unique item)`.

> [!NOTE]
> Following the **"One Obvious Way"** principle, Tacet strictly uses canonical scope keywords (`personal`, `org`). Shorthand symbols like `_` are intentionally unsupported to prevent ambiguity in configuration files.

---

### 2. Item Identifier Patterns (`<item>`)

The `<item>` component matches a cipher item by either name or unique UUID.

| Pattern | Description | Example |
|---|---|---|
| Item Name (Case-insensitive) | Matches by item display name | `tacet://personal/github/password` |
| Exact 36-char UUID | Direct lookup by Bitwarden item UUID | `tacet://personal/d3b07384-d113-46fb-9c88-e9f02c61e808/password` |
| Percent-encoded Characters | Handles spaces (`%20`) or literal slashes (`%2F`) in item/folder names | `tacet://personal/prod%2Fcluster/k8s%20token/password` |

UUID references match IDs only, never item names. Name references that match multiple items return an ambiguity error. For production CI/CD, prefer an explicit scope and item UUID, omitting folder or collection paths when unnecessary. UUIDs pin the referenced item, not its value; secret updates and live TOTP can change the returned value.

Attachment discovery (`GET /v1/items/{item_id}/attachments`) returns `tacet://personal/<UUID>/files/<attachment-id>` or `tacet://org/<org-id>/<UUID>/files/<attachment-id>`, with URI components percent-encoded as needed. Organization attachment URIs do not depend on collection membership or organization names.

---

### 3. Field Target Patterns (`<field>`)

Bitwarden item fields are accessed strictly via standardized canonical names or custom field specifiers. No arbitrary abbreviations (`user`, `pass`, `otp`, `note`, `url`) are allowed, preventing collisions with custom fields.

| Bitwarden Field | URI Target | Description | Example |
|---|---|---|---|
| `login.username` | `username` | Plaintext username | `tacet://personal/GitHub/username` |
| `login.password` | `password` | Plaintext password | `tacet://personal/Postgres/password` |
| `login.totp` (Computed) | `totp` | Live 6-digit RFC 6238 TOTP code | `tacet://personal/AWS/totp` |
| `login.totp` (Raw seed) | `totp_secret` | Raw TOTP secret / `otpauth://` URI | `tacet://personal/AWS/totp_secret` |
| `notes` | `notes` | Secure note content | `tacet://personal/SSH_Key/notes` |
| Primary URL (`uris[0]`) | `uri` / `uri.0` | Primary URL | `tacet://personal/Portal/uri` |
| Indexed URL (`uris[n]`) | `uri.<n>` | Specific URL at index `n` | `tacet://personal/Portal/uri.1` |
| Explicit Custom Field | `fields/<field_name>` | Explicitly selects custom field `field_name` | `tacet://personal/OpenAI/fields/api_key` |
| Named Custom Field | `<field_name>` | Falls back to custom field if not matching canonical built-in fields | `tacet://personal/OpenAI/api_key`<br>`tacet://personal/DB/user` (maps to custom field `user`) |

---

### 4. Query Modifier Patterns (`?<modifiers>`)

Text field values preserve leading and trailing whitespace by default. `tacet read` writes the resolved value without appending a newline.

Modifiers allow on-the-fly transformations of the extracted secret. Modifiers can be combined using `&` (e.g. `?encoding=base64&trim=false`).

#### Pipeline Order:
1. `json` extraction
2. `trim` whitespace strip (only when explicitly enabled)
3. `encoding` transformation

| Modifier | Parameter Syntax | Description | Example |
|---|---|---|---|
| **JSON Extraction** | `json=<dot.path>` | Parses the secret as JSON and extracts the value at the specified dot-separated path | `tacet://personal/GCP_ServiceAccount/notes?json=private_key` |
| **Base64 Encoding** | `encoding=base64` | Encodes the resolved string to standard Base64 | `tacet://personal/K8s/cert?encoding=base64` |
| **Hex Encoding** | `encoding=hex` | Encodes the resolved string to lowercase hexadecimal | `tacet://personal/Auth/secret?encoding=hex` |
| **Whitespace Trim** | `trim=true` / `trim=1`<br>`trim=false` / `trim=0` | Strips leading/trailing whitespace and newlines when enabled (default is `false`) | `tacet://personal/TLS/ca.crt?trim=true` |

---

### 5. Composite Examples

* **Extracting a nested JSON key encoded as Base64:**
  ```text
  tacet://personal/Cloud/credentials?json=auth.client_secret&encoding=base64
  ```

* **Organization item with nested collection and explicit custom field:**
  ```text
  tacet://org/AcmeCorp/Engineering/Backend/Database/fields/replica_password
  ```

* **Multi-line certificate keeping original trailing newlines by default:**
  ```text
  tacet://personal/Certificates/RootCA/notes
  ```

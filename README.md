# vaultdotenv

Drop-in replacement for [dotenv](https://github.com/motdotla/dotenv). One key in your `.env`, all your secrets encrypted in the cloud.

```
Your .env file (the only secret you deploy):
  VAULT_KEY=vk_abc123_def456...

That's it. All other env vars load automatically from the vault.
```

## Why vaultdotenv?

Your `.env` file has 30 secrets. Every developer has a copy. Every server has a copy. When you rotate a key, you update it everywhere manually. If someone's laptop gets stolen, every secret is compromised.

**vaultdotenv** replaces all of that with a single key. Your secrets live encrypted on a remote server. The server never sees the decryption key. Clients decrypt locally. You rotate one secret instead of thirty.

| | dotenv | vaultdotenv |
|---|---|---|
| Secrets in `.env` | All of them | Just `VAULT_KEY` |
| Laptop stolen | Everything exposed | One key to rotate |
| Rotate an API key | Update every server | Push once, all servers get it |
| Version history | None | Full version history + rollback |
| Device control | None | Approve/revoke individual machines |
| Code changes to migrate | - | Zero |

---

## Table of Contents

- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Node.js Client](#nodejs-client)
- [Python Client](#python-client)
- [CLI Reference](#cli-reference)
- [Device Management](#device-management)
- [Environments](#environments)
- [Hot Reload](#hot-reload)
- [CI/CD & Servers](#cicd--servers)
- [Offline Fallback](#offline-fallback)
- [Security Model](#security-model)
- [Encryption Details](#encryption-details)
- [API Reference](#api-reference)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### 1. Install

```bash
# Node.js
npm install @vaultdotenv/cli

# Python — copy the vaultdotenv/ directory into your project
# (pip package coming soon)
```

### 2. Create a project

```bash
npx @vaultdotenv/cli init --name my-app
```

This does four things:
1. Creates the project on the vault server (assigns a UUID)
2. Generates your `VAULT_KEY` (embeds the project UUID + a random secret)
3. Writes `VAULT_KEY=vk_...` to your `.env` file
4. Registers your machine as the first device (auto-approved)

### 3. Push your secrets

```bash
npx @vaultdotenv/cli push --env production
```

Reads your `.env` file, encrypts every key-value pair (except `VAULT_KEY` itself), and uploads the encrypted blob. The server never sees the plaintext.

### 4. Replace dotenv

```diff
# Node.js
- require('dotenv').config()
+ require('@vaultdotenv/cli').config()

# Python
- from dotenv import load_dotenv
- load_dotenv()
+ from vaultdotenv import load_vault
+ load_vault()
```

Done. Your app now loads secrets from the vault. If there's no `VAULT_KEY` in the environment, it falls back to plain dotenv behavior — so the migration is completely safe.

---

## How It Works

```
┌──────────────────────────────────┐
│          Your Application        │
│                                  │
│  require('@vaultdotenv/cli').config()   │
│         or load_vault()          │
└──────────────┬───────────────────┘
               │
               │ 1. Read VAULT_KEY from .env or environment
               │ 2. Derive auth key via HKDF
               │ 3. Sign request with HMAC-SHA256
               ▼
┌──────────────────────────────────┐
│     api.vaultdotenv.io         │
│     (Cloudflare Worker + D1)     │
│                                  │
│  • Validates HMAC signature      │
│  • Validates device hash         │
│  • Returns encrypted blob        │
│  • Logs access in audit table    │
│  • NEVER sees the decryption key │
└──────────────┬───────────────────┘
               │
               │ 4. Encrypted blob returned
               ▼
┌──────────────────────────────────┐
│         Client (local)           │
│                                  │
│  • Derives decryption key from   │
│    VAULT_KEY + device secret     │
│  • Decrypts with AES-256-GCM    │
│  • Injects into process.env     │
│    (or os.environ in Python)     │
│  • Caches encrypted blob locally │
└──────────────────────────────────┘
```

The server is a dumb encrypted storage layer. All cryptography happens on the client. A full database breach reveals nothing — the blobs are encrypted with keys the server has never seen.

---

## Node.js Client

### Installation

```bash
npm install @vaultdotenv/cli
```

### Basic Usage

```js
// Async (recommended) — pulls fresh secrets from the vault
await require('@vaultdotenv/cli').config();

// Options
await require('@vaultdotenv/cli').config({
  path: '.env',               // Path to .env file (default: .env)
  environment: 'production',  // Environment name (default: NODE_ENV or 'development')
  vaultUrl: 'https://...',    // Vault server URL (default: api.vaultdotenv.io)
  override: false,            // Override existing env vars (default: false)
  cache: true,                // Cache secrets locally for offline fallback (default: true)
});
```

### Synchronous Mode

```js
// Sync — reads from local encrypted cache only (no network call)
// Useful for scripts or tools that can't be async
require('@vaultdotenv/cli').configSync();
```

`configSync()` tries the local `.vault-cache` file first. If no cache exists, it falls back to the plain `.env` file. This is useful for development or situations where async isn't possible.

### No VAULT_KEY? No problem.

If there's no `VAULT_KEY` in the environment or `.env` file, vaultdotenv behaves exactly like dotenv — reads the `.env` file and injects the values into `process.env`. This makes the migration completely backwards-compatible.

---

## Python Client

### Installation

Copy the `clients/python/vaultdotenv/` directory into your project. Requires `cryptography` and `httpx`:

```bash
pip install cryptography httpx
```

### Basic Usage

```python
from vaultdotenv import load_vault

# Pulls secrets from vault and injects into os.environ
load_vault()

# With options
load_vault(
    path=".env",               # Path to .env file
    environment="production",  # Environment name (default: ENVIRONMENT or NODE_ENV or 'development')
    vault_url="https://...",   # Vault server URL
    override=False,            # Override existing env vars
    cache=True,                # Enable local cache fallback
)
```

### Synchronous / Cache-Only Mode

```python
from vaultdotenv import load_vault_sync

# Reads from local encrypted cache only — no network call
load_vault_sync()
```

### Integration Example

Replace `python-dotenv` with a safe fallback:

```python
# config.py
try:
    from vaultdotenv import load_vault
    load_vault()
except Exception:
    from dotenv import load_dotenv
    load_dotenv()
```

---

## CLI Reference

All commands read `VAULT_KEY` from the `VAULT_KEY` environment variable or from the `.env` file in the current directory.

### Initialize a Project

```bash
npx @vaultdotenv/cli init [--name my-project]
```

Creates the project on the server, generates the vault key, registers your machine as the first device (auto-approved), and writes `VAULT_KEY` to `.env`.

### Push Secrets

```bash
npx @vaultdotenv/cli push [--env production] [--file .env.production]
```

Encrypts and uploads all key-value pairs from the specified file (default: `.env`). The `VAULT_KEY` itself is never pushed. Each push creates a new version.

### Pull Secrets

```bash
npx @vaultdotenv/cli pull [--env staging] [--output .env.staging]
```

Pulls and decrypts secrets from the vault. Without `--output`, prints masked values to stdout. With `--output`, writes the full `.env` file.

### List Versions

```bash
npx @vaultdotenv/cli versions [--env production]
```

Shows the version history for an environment, including timestamps and number of keys changed.

### Rollback

```bash
npx @vaultdotenv/cli rollback --version 3 [--env production]
```

Creates a new version with the contents of the specified old version. Non-destructive — the rollback itself is a new version, so you can always roll forward again.

### Device Management

```bash
npx @vaultdotenv/cli register-device [--name "CI Server"]
npx @vaultdotenv/cli approve-device --id <device-uuid>
npx @vaultdotenv/cli list-devices
npx @vaultdotenv/cli revoke-device --id <device-uuid>
```

See [Device Management](#device-management) for details.

### Global Options

| Flag | Description | Default |
|---|---|---|
| `--env <name>` | Environment name | `NODE_ENV` or `development` |
| `--url <url>` | Vault server URL | `https://api.vaultdotenv.io` |
| `--file <path>` | Source `.env` file (push only) | `.env` |
| `--output <path>` | Output file (pull only) | stdout |
| `--name <name>` | Project or device name | directory name / hostname |
| `--id <uuid>` | Device ID (approve/revoke) | — |

---

## Device Management

Devices add a second layer of security. Every machine that accesses your secrets must be registered and approved.

### How It Works

1. **Register**: A new machine runs `vaultdotenv register-device`. This generates a **device secret** (random 256-bit key), stores it locally at `~/.vault/<projectId>.key`, and sends the SHA-256 hash to the server.
2. **Approve**: The project owner runs `vaultdotenv approve-device --id <uuid>` to approve the new device.
3. **Access**: On every pull/push, the client sends the device hash. The server checks it against the `devices` table. Unregistered or revoked devices get a `403`.
4. **Revoke**: If a machine is compromised, run `vaultdotenv revoke-device --id <uuid>`. That machine can no longer access secrets.

### First Device = Owner

The first device registered for a project is automatically approved. All subsequent devices require explicit approval.

### Device Secret Storage

| Location | Used by |
|---|---|
| `~/.vault/<projectId>.key` | Local development machines (file permissions: `0600`) |
| `VAULT_DEVICE_SECRET` env var | CI/CD pipelines and servers |

### Dual-Key Encryption

The device secret isn't just for authentication — it's used in the encryption itself. The encryption key is derived from both pieces:

```
key_material = HMAC-SHA256(vault_key, device_secret)
encryption_key = HKDF(key_material, salt="vault-encrypt-v1")
```

This means:
- Stealing just the `VAULT_KEY` is not enough to decrypt secrets
- Stealing just the device secret is not enough to decrypt secrets
- Both are required — defense in depth

### Important: Device-Bound Encryption

Secrets are encrypted with a specific device's secret at push time. Only the device whose secret was used to encrypt can decrypt those secrets. If you need multiple devices to pull the same secrets, you must push the secrets using each device's secret.

In practice for server deployments: register a device for the server, push secrets using that device's secret, and pass the device secret via the `VAULT_DEVICE_SECRET` environment variable.

---

## Environments

Every project comes with three default environments: `development`, `staging`, and `production`. Custom environments are created automatically on first push.

```bash
# Push to different environments
npx @vaultdotenv/cli push --env development
npx @vaultdotenv/cli push --env staging
npx @vaultdotenv/cli push --env production

# Pull from a specific environment
npx @vaultdotenv/cli pull --env staging
```

### Environment Resolution

The client determines the environment from (in order):
1. The `--env` CLI flag
2. `NODE_ENV` environment variable (Node.js)
3. `ENVIRONMENT` environment variable (Python)
4. Default: `development`

---

## Hot Reload

Both clients support watching for secret changes and automatically updating the environment — no restart required.

### Node.js

```js
const vault = require('@vaultdotenv/cli');

// Load secrets first
await vault.config();

// Start watching (polls every 30s by default)
vault.watch({
  interval: 30000,          // Poll interval in ms
  environment: 'production',
  onChange(changed, allSecrets) {
    console.log('Secrets updated:', Object.keys(changed));
    // Reconnect services, refresh configs, etc.
  },
  onError(err) {
    console.error('Watch error:', err);
  },
});

// Stop watching when done
vault.unwatch();
```

### Python

```python
import vaultdotenv

vaultdotenv.load_vault()

vaultdotenv.watch(
    interval=30.0,  # seconds
    on_change=lambda changed, all_secrets: print("Updated:", list(changed.keys())),
    on_error=lambda err: print(f"Error: {err}"),
)

# Stop watching
vaultdotenv.unwatch()
```

### How Watching Works

1. Polls `/api/v1/secrets/current-version` at the configured interval (lightweight — no secrets transferred)
2. If the version number changed, does a full pull
3. Diffs the new secrets against `process.env` / `os.environ`
4. Updates changed values in-place
5. Calls `onChange` / `on_change` with the diff

The watcher runs on a background thread (Python) or unref'd timer (Node.js) — it won't keep your process alive.

---

## CI/CD & Servers

For non-interactive environments (CI pipelines, Docker containers, production servers), pass the vault key and device secret as environment variables:

```bash
# Docker
docker run -e VAULT_KEY=vk_... -e VAULT_DEVICE_SECRET=abc123... -e ENVIRONMENT=production myapp

# GitHub Actions
env:
  VAULT_KEY: ${{ secrets.VAULT_KEY }}
  VAULT_DEVICE_SECRET: ${{ secrets.VAULT_DEVICE_SECRET }}

# Any CI/CD
export VAULT_KEY=vk_...
export VAULT_DEVICE_SECRET=abc123...
export ENVIRONMENT=production
```

### Setting Up a Server

1. **Register a device** for the server (from any machine with the vault key):
   ```bash
   npx @vaultdotenv/cli register-device --name "production-server"
   ```
   This outputs the device ID and saves the device secret to `~/.vault/`.

2. **Approve the device**:
   ```bash
   npx @vaultdotenv/cli approve-device --id <device-uuid>
   ```

3. **Push secrets** using the server's device secret (it's now in your `~/.vault/` file):
   ```bash
   npx @vaultdotenv/cli push --env production
   ```

4. **Copy the device secret** to the server as the `VAULT_DEVICE_SECRET` env var. The device secret is in `~/.vault/<projectId>.key`.

5. **Deploy** your app with just two env vars: `VAULT_KEY` and `VAULT_DEVICE_SECRET`.

---

## Offline Fallback

When the vault server is unreachable, the client automatically falls back to a local encrypted cache:

1. After every successful pull, secrets are cached to `.vault-cache` in the project directory
2. The cache is encrypted with the same key (vault key + device secret) — it's not readable without both
3. If the server is down on next startup, the client decrypts and uses the cache
4. A warning is printed: `[vaultdotenv] Remote fetch failed, using cached secrets`

Add `.vault-cache` to your `.gitignore`:

```
.vault-cache
```

---

## Security Model

### What the server knows

- Project metadata (name, UUID, created date)
- Environment names
- Encrypted blobs (opaque — server cannot decrypt)
- Device hashes (SHA-256 of device secrets — server never sees the raw secrets)
- Auth key hash (derived from vault key via HKDF — server never sees the vault key)
- Audit log (who accessed what, from which IP, when)

### What the server does NOT know

- Your vault key
- Your device secrets
- Your decrypted secrets
- The encryption key

### Threat model

| Scenario | Impact |
|---|---|
| Server database breached | Attacker gets encrypted blobs. Useless without vault key + device secret. |
| `.env` file leaked (with VAULT_KEY) | Attacker has vault key but not device secret. Cannot decrypt. Cannot pull (device hash check fails). |
| `~/.vault/` directory leaked | Attacker has device secret but not vault key. Cannot decrypt. |
| Both vault key AND device secret leaked | Attacker can pull and decrypt. Revoke the device, rotate the vault key. |
| Network MITM | HMAC signatures prevent replay attacks. Secrets are encrypted end-to-end. HTTPS provides transport security. |

### Key rotation

If a vault key is compromised, generate a new one and re-push secrets. The old key becomes useless because the server's auth key hash no longer matches.

---

## Encryption Details

### Key Derivation

```
Input Key Material (IKM):
  If device secret exists:  HMAC-SHA256(vault_key, device_secret)
  If no device secret:      vault_key (raw bytes)

Derived Keys:
  Encryption key = HKDF-SHA256(IKM, salt="vault-encrypt-v1", info="", length=32)
  Auth key       = HKDF-SHA256(IKM, salt="vault-auth-v1",    info="", length=32)
  Device hash    = SHA-256(device_secret)
```

### Encryption (Push)

```
1. Derive 256-bit encryption key (see above)
2. Generate random 96-bit IV
3. Encrypt: AES-256-GCM(key, iv, plaintext_json)
4. Pack: base64(iv || auth_tag || ciphertext)
5. Send packed blob to server
```

### Decryption (Pull)

```
1. Derive 256-bit encryption key (same derivation)
2. Unpack: base64 decode → iv (12 bytes) || auth_tag (16 bytes) || ciphertext
3. Decrypt: AES-256-GCM(key, iv, ciphertext, auth_tag)
4. Parse JSON → key-value pairs
```

### Request Signing

```
1. Derive auth key: HKDF(vault_key, salt="vault-auth-v1")
2. Compute: HMAC-SHA256(auth_key, request_body + timestamp)
3. Header: X-Vault-Signature: v=<timestamp>,d=<hex_digest>
4. Server verifies against stored auth_key_hash (max age: 5 minutes)
```

---

## API Reference

All endpoints are at `https://api.vaultdotenv.io/api/v1/`. All requests use `POST` with JSON bodies. Authenticated endpoints require the `X-Vault-Signature` header.

### `POST /project/create`

Create a new project. No authentication required.

```json
// Request
{ "project_name": "my-app" }

// Response
{ "project_id": "uuid", "environments": ["development", "staging", "production"] }
```

### `POST /project/set-key`

Set the auth key hash for a project. One-time operation — cannot be overwritten.

```json
// Request
{ "project_id": "uuid", "auth_key_hash": "hex" }

// Response
{ "ok": true }
```

### `POST /secrets/push` (authenticated)

Push encrypted secrets.

```json
// Request
{ "project_id": "uuid", "environment": "production", "secrets": "<base64_encrypted_blob>", "device_hash": "hex" }

// Response
{ "version": 1 }
```

### `POST /secrets/pull` (authenticated)

Pull encrypted secrets.

```json
// Request
{ "project_id": "uuid", "environment": "production", "device_hash": "hex" }

// Response
{ "secrets": "<base64_encrypted_blob>", "version": 1 }
```

### `POST /secrets/current-version` (authenticated)

Lightweight version check — no secrets transferred.

```json
// Request
{ "project_id": "uuid", "environment": "production" }

// Response
{ "version": 1, "updated_at": "2026-03-23T10:54:10.872Z" }
```

### `POST /secrets/versions` (authenticated)

List version history.

```json
// Request
{ "project_id": "uuid", "environment": "production" }

// Response
{ "versions": [{ "version": 1, "created_at": "...", "changed_keys": [...] }] }
```

### `POST /secrets/rollback` (authenticated)

Rollback to a previous version (creates a new version with old content).

```json
// Request
{ "project_id": "uuid", "environment": "production", "version": 1 }

// Response
{ "version": 3 }
```

### `POST /devices/register` (authenticated)

Register a new device.

```json
// Request
{ "project_id": "uuid", "device_name": "my-laptop", "device_hash": "hex" }

// Response
{ "device_id": "uuid", "status": "pending" }
```

### `POST /devices/approve` (authenticated)

Approve a pending device.

```json
// Request
{ "project_id": "uuid", "device_id": "uuid" }

// Response
{ "device_id": "uuid", "status": "approved" }
```

### `POST /devices/list` (authenticated)

List all devices for a project.

```json
// Request
{ "project_id": "uuid" }

// Response
{ "devices": [{ "id": "uuid", "device_name": "...", "status": "approved", "last_seen_at": "..." }] }
```

### `POST /devices/revoke` (authenticated)

Revoke a device's access.

```json
// Request
{ "project_id": "uuid", "device_id": "uuid" }

// Response
{ "device_id": "uuid", "status": "revoked" }
```

### `GET /health`

Health check. No authentication.

```json
{ "status": "ok", "ts": 1711187650872 }
```

---

## Architecture

### Server

- **Runtime**: Cloudflare Worker (edge, globally distributed)
- **Database**: Cloudflare D1 (SQLite at the edge)
- **Domain**: `api.vaultdotenv.io`

### Database Schema

```
projects
  id          TEXT (UUID, primary key)
  name        TEXT
  key_hash    TEXT (hex-encoded auth key hash)
  created_at  DATETIME

environments
  id          TEXT (UUID, primary key)
  project_id  TEXT (FK → projects)
  name        TEXT (development/staging/production/custom)
  created_at  DATETIME

secret_versions
  id              INTEGER (auto-increment)
  environment_id  TEXT (FK → environments)
  version         INTEGER
  encrypted_blob  TEXT (base64-encoded AES-256-GCM ciphertext)
  changed_keys    TEXT (JSON array of key names — not values)
  created_at      DATETIME

devices
  id            TEXT (UUID, primary key)
  project_id    TEXT (FK → projects)
  device_name   TEXT
  device_hash   TEXT (SHA-256 of device secret)
  status        TEXT (pending/approved/revoked)
  created_at    DATETIME
  approved_at   DATETIME
  last_seen_at  DATETIME

audit_log
  id              INTEGER (auto-increment)
  project_id      TEXT
  environment_id  TEXT
  action          TEXT (pull/push/rollback/device_register)
  ip              TEXT
  user_agent      TEXT
  created_at      DATETIME
```

### Node.js Client

- Zero external dependencies (uses Node.js built-in `crypto`)
- CommonJS module (`require('@vaultdotenv/cli')`)
- CLI built into the package (`npx @vaultdotenv/cli`)

### Python Client

- Dependencies: `cryptography`, `httpx`
- Drop-in replacement for `python-dotenv`
- Thread-based watcher for hot reload

---

## Troubleshooting

### "Device not registered. Run: vaultdotenv register-device"

Your machine isn't registered for this project. Run:
```bash
npx @vaultdotenv/cli register-device
```
Then ask the project owner to approve it.

### "Device not yet approved"

Your device is registered but pending approval. The project owner needs to run:
```bash
npx @vaultdotenv/cli list-devices          # Find the device ID
npx @vaultdotenv/cli approve-device --id <uuid>
```

### "Failed to fetch secrets and no cache available"

The vault server is unreachable and there's no local cache. This happens on first run with no network. Make sure you can reach `api.vaultdotenv.io` and run a successful pull first to populate the cache.

### "VAULT_KEY not found in environment or .env file"

The CLI can't find your vault key. Either:
- Set the `VAULT_KEY` environment variable, or
- Make sure your `.env` file contains `VAULT_KEY=vk_...`

### Decryption fails after registering a new device

Secrets are encrypted with a specific device's secret. If you registered a new device, the local `~/.vault/<projectId>.key` file was overwritten with the new device's secret. You need to re-push secrets using the new device's secret for that device to decrypt them.

### .vault-cache in .gitignore

Always add `.vault-cache` to your `.gitignore`. While the cache is encrypted, there's no reason to commit it.

```
# .gitignore
.vault-cache
```

---

## License

MIT

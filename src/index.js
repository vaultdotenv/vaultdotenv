'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { encrypt, decrypt, sign, parseVaultKey, generateDeviceSecret, hashDeviceSecret } = require('./crypto');

const DEFAULT_VAULT_URL = 'https://api.vaultdotenv.io';
const CACHE_FILE = '.vault-cache';
const DEVICE_DIR = path.join(os.homedir(), '.vault');
const DEVICE_KEY_FILE = 'device.key';

/**
 * Parse a dotenv-style string into key-value pairs.
 */
function parseDotenv(src) {
  const result = {};
  for (const line of src.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const idx = trimmed.indexOf('=');
    if (idx === -1) continue;
    const key = trimmed.slice(0, idx).trim();
    let val = trimmed.slice(idx + 1).trim();
    // Strip surrounding quotes
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    result[key] = val;
  }
  return result;
}

/**
 * Serialize secrets object to dotenv-style string.
 */
function serializeDotenv(secrets) {
  return Object.entries(secrets)
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');
}

/**
 * Get the device secret file path for a given project.
 * Stored at ~/.vault/<projectId>.key to support multiple projects.
 */
function getDeviceKeyPath(projectId) {
  return path.join(DEVICE_DIR, `${projectId}.key`);
}

/**
 * Load the device secret for a project. Returns null if not found.
 */
function loadDeviceSecret(projectId) {
  // Also check VAULT_DEVICE_SECRET env var (for CI/CD)
  if (process.env.VAULT_DEVICE_SECRET) return process.env.VAULT_DEVICE_SECRET;

  const keyPath = getDeviceKeyPath(projectId);
  if (!fs.existsSync(keyPath)) return null;
  return fs.readFileSync(keyPath, 'utf8').trim();
}

/**
 * Save a device secret for a project to ~/.vault/<projectId>.key
 */
function saveDeviceSecret(projectId, deviceSecret) {
  if (!fs.existsSync(DEVICE_DIR)) {
    fs.mkdirSync(DEVICE_DIR, { mode: 0o700, recursive: true });
  }
  const keyPath = getDeviceKeyPath(projectId);
  fs.writeFileSync(keyPath, deviceSecret + '\n', { mode: 0o600 });
}

/**
 * Register this device with the vault server.
 * Generates a device secret, stores it locally, and sends the hash to the server.
 * Returns { deviceId, deviceSecret, status: 'pending' }
 */
async function registerDevice(vaultKey, vaultUrl, deviceName) {
  const parsed = parseVaultKey(vaultKey);
  if (!parsed) throw new Error('Invalid VAULT_KEY format');

  const deviceSecret = generateDeviceSecret();
  const deviceHash = hashDeviceSecret(deviceSecret);

  const body = JSON.stringify({
    project_id: parsed.projectId,
    device_name: deviceName || os.hostname(),
    device_hash: deviceHash,
  });

  // Sign with vault key only (no device secret yet — this is registration)
  const { signature } = sign(vaultKey, body);

  const resp = await fetch(`${vaultUrl}/api/v1/devices/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Vault-Signature': signature,
    },
    body,
  });

  if (!resp.ok) {
    const err = await resp.text().catch(() => '');
    throw new Error(`Device registration failed (${resp.status}): ${err}`);
  }

  const data = await resp.json();

  // Save device secret locally
  saveDeviceSecret(parsed.projectId, deviceSecret);

  return { deviceId: data.device_id, deviceSecret, status: data.status };
}

/**
 * Pull secrets from the vault server.
 */
async function pullSecrets(vaultKey, environment, vaultUrl, deviceSecret) {
  const parsed = parseVaultKey(vaultKey);
  if (!parsed) throw new Error('Invalid VAULT_KEY format. Expected: vk_<projectId>_<secret>');

  // Load device secret if not provided (undefined = auto-load, null/false = skip)
  if (deviceSecret === undefined) deviceSecret = loadDeviceSecret(parsed.projectId);

  const body = JSON.stringify({
    project_id: parsed.projectId,
    environment,
    device_hash: deviceSecret ? hashDeviceSecret(deviceSecret) : undefined,
  });
  // Sign with vault key only — server verifies against stored auth key
  // Device auth is handled via device_hash in the body
  const { signature } = sign(vaultKey, body);

  const resp = await fetch(`${vaultUrl}/api/v1/secrets/pull`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Vault-Signature': signature,
    },
    body,
  });

  if (!resp.ok) {
    const err = await resp.text().catch(() => '');
    if (resp.status === 403) {
      const msg = err.includes('pending')
        ? 'Device not yet approved. Ask the project owner to run: vaultdotenv approve-device'
        : 'Device not registered. Run: vaultdotenv register-device';
      throw new Error(`[vaultdotenv] ${msg}`);
    }
    throw new Error(`Vault pull failed (${resp.status}): ${err}`);
  }

  const data = await resp.json();
  const decrypted = decrypt(data.secrets, vaultKey, deviceSecret);
  return { secrets: JSON.parse(decrypted), version: data.version };
}

/**
 * Push secrets to the vault server.
 */
async function pushSecrets(vaultKey, environment, secrets, vaultUrl, deviceSecret) {
  const parsed = parseVaultKey(vaultKey);
  if (!parsed) throw new Error('Invalid VAULT_KEY format. Expected: vk_<projectId>_<secret>');

  // Load device secret if not provided (undefined = auto-load, null/false = skip)
  if (deviceSecret === undefined) deviceSecret = loadDeviceSecret(parsed.projectId);

  const encryptedSecrets = encrypt(JSON.stringify(secrets), vaultKey, deviceSecret);
  const body = JSON.stringify({
    project_id: parsed.projectId,
    environment,
    secrets: encryptedSecrets,
    device_hash: deviceSecret ? hashDeviceSecret(deviceSecret) : undefined,
  });
  const { signature } = sign(vaultKey, body);

  const resp = await fetch(`${vaultUrl}/api/v1/secrets/push`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Vault-Signature': signature,
    },
    body,
  });

  if (!resp.ok) {
    const err = await resp.text().catch(() => '');
    throw new Error(`Vault push failed (${resp.status}): ${err}`);
  }

  return resp.json();
}

/**
 * Load cached secrets from local encrypted file.
 */
function loadCache(vaultKey, cacheDir, deviceSecret) {
  const cachePath = path.join(cacheDir, CACHE_FILE);
  if (!fs.existsSync(cachePath)) return null;
  try {
    const encrypted = fs.readFileSync(cachePath, 'utf8');
    const decrypted = decrypt(encrypted, vaultKey, deviceSecret);
    return JSON.parse(decrypted);
  } catch {
    return null;
  }
}

/**
 * Save secrets to local encrypted cache.
 */
function saveCache(vaultKey, secrets, cacheDir, deviceSecret) {
  const cachePath = path.join(cacheDir, CACHE_FILE);
  const encrypted = encrypt(JSON.stringify(secrets), vaultKey, deviceSecret);
  fs.writeFileSync(cachePath, encrypted, 'utf8');
}

/**
 * Drop-in replacement for require('dotenv').config()
 *
 * Reads VAULT_KEY from .env, pulls secrets from vault server,
 * injects into process.env.
 *
 * @param {Object} [options]
 * @param {string} [options.path] - Path to .env file (default: .env)
 * @param {string} [options.environment] - Environment name (default: NODE_ENV or 'development')
 * @param {string} [options.vaultUrl] - Vault server URL
 * @param {boolean} [options.override] - Override existing env vars (default: false)
 * @param {boolean} [options.cache] - Use local cache as fallback (default: true)
 * @returns {Promise<{ parsed: Object, version?: number }>}
 */
async function config(options = {}) {
  const {
    path: envPath = path.resolve(process.cwd(), '.env'),
    environment = process.env.NODE_ENV || 'development',
    vaultUrl = process.env.VAULT_URL || DEFAULT_VAULT_URL,
    override = false,
    cache = true,
  } = options;

  // Step 1: Read .env for VAULT_KEY
  let vaultKey = process.env.VAULT_KEY;

  if (!vaultKey && fs.existsSync(envPath)) {
    const envContent = fs.readFileSync(envPath, 'utf8');
    const localEnv = parseDotenv(envContent);
    vaultKey = localEnv.VAULT_KEY;

    // Also load any other local vars (non-vault vars stay local)
    for (const [key, val] of Object.entries(localEnv)) {
      if (key === 'VAULT_KEY') continue;
      if (!override && process.env[key] !== undefined) continue;
      process.env[key] = val;
    }
  }

  // If no VAULT_KEY, fall back to plain dotenv behavior
  if (!vaultKey) {
    if (fs.existsSync(envPath)) {
      const envContent = fs.readFileSync(envPath, 'utf8');
      const parsed = parseDotenv(envContent);
      for (const [key, val] of Object.entries(parsed)) {
        if (!override && process.env[key] !== undefined) continue;
        process.env[key] = val;
      }
      return { parsed };
    }
    return { parsed: {} };
  }

  // Step 2: Load device secret
  const parsed = parseVaultKey(vaultKey);
  const deviceSecret = parsed ? loadDeviceSecret(parsed.projectId) : null;

  // Step 3: Pull from vault
  let secrets;
  let version;

  try {
    const result = await pullSecrets(vaultKey, environment, vaultUrl, deviceSecret);
    secrets = result.secrets;
    version = result.version;

    // Cache for offline fallback
    if (cache) {
      try { saveCache(vaultKey, secrets, path.dirname(envPath), deviceSecret); } catch { /* ignore */ }
    }
  } catch (err) {
    // Fallback to cache
    if (cache) {
      secrets = loadCache(vaultKey, path.dirname(envPath), deviceSecret);
      if (secrets) {
        console.warn('[vaultdotenv] Remote fetch failed, using cached secrets');
      } else {
        throw new Error(`[vaultdotenv] Failed to fetch secrets and no cache available: ${err.message}`);
      }
    } else {
      throw err;
    }
  }

  // Step 3: Inject into process.env
  for (const [key, val] of Object.entries(secrets)) {
    if (!override && process.env[key] !== undefined) continue;
    process.env[key] = String(val);
  }

  return { parsed: secrets, version };
}

/**
 * Synchronous config — reads from cache only (for compatibility with dotenv.config() sync pattern).
 * Falls back to plain .env if no VAULT_KEY or no cache.
 */
function configSync(options = {}) {
  const {
    path: envPath = path.resolve(process.cwd(), '.env'),
    override = false,
  } = options;

  // Read .env
  if (!fs.existsSync(envPath)) return { parsed: {} };

  const envContent = fs.readFileSync(envPath, 'utf8');
  const localEnv = parseDotenv(envContent);
  const vaultKey = localEnv.VAULT_KEY;

  // No vault key — plain dotenv behavior
  if (!vaultKey) {
    for (const [key, val] of Object.entries(localEnv)) {
      if (!override && process.env[key] !== undefined) continue;
      process.env[key] = val;
    }
    return { parsed: localEnv };
  }

  // Load device secret
  const parsed = parseVaultKey(vaultKey);
  const deviceSecret = parsed ? loadDeviceSecret(parsed.projectId) : null;

  // Try cache
  const cached = loadCache(vaultKey, path.dirname(envPath), deviceSecret);
  if (cached) {
    for (const [key, val] of Object.entries(cached)) {
      if (!override && process.env[key] !== undefined) continue;
      process.env[key] = String(val);
    }
    return { parsed: cached };
  }

  // No cache — load local .env as fallback
  console.warn('[vaultdotenv] No cache available, falling back to local .env');
  for (const [key, val] of Object.entries(localEnv)) {
    if (!override && process.env[key] !== undefined) continue;
    process.env[key] = val;
  }
  return { parsed: localEnv };
}

/**
 * Check the current version on the server without pulling the full blob.
 */
async function checkVersion(vaultKey, environment, vaultUrl) {
  const parsed = parseVaultKey(vaultKey);
  if (!parsed) throw new Error('Invalid VAULT_KEY format');

  const body = JSON.stringify({ project_id: parsed.projectId, environment });
  const { signature } = sign(vaultKey, body);

  const resp = await fetch(`${vaultUrl}/api/v1/secrets/current-version`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Vault-Signature': signature,
    },
    body,
  });

  if (!resp.ok) throw new Error(`Version check failed (${resp.status})`);
  return resp.json();
}

// Active watcher state
let _watcher = null;

/**
 * Watch for secret changes and hot-reload into process.env.
 *
 * @param {Object} [options]
 * @param {number} [options.interval=30000] - Poll interval in ms (default 30s)
 * @param {string} [options.environment] - Environment name
 * @param {string} [options.vaultUrl] - Vault server URL
 * @param {Function} [options.onChange] - Callback: (changedKeys: Record<string, string>, allSecrets: Record<string, string>) => void
 * @param {Function} [options.onError] - Callback: (error: Error) => void
 * @returns {{ stop: Function }} Watcher handle with stop()
 */
function watch(options = {}) {
  const {
    interval = 30_000,
    environment = process.env.NODE_ENV || 'development',
    vaultUrl = process.env.VAULT_URL || DEFAULT_VAULT_URL,
    onChange,
    onError,
  } = options;

  // Need VAULT_KEY to be loaded already (config() must have been called)
  const vaultKey = process.env.VAULT_KEY;
  if (!vaultKey) {
    throw new Error('[vaultdotenv] watch() requires VAULT_KEY — call config() first');
  }

  const parsed = parseVaultKey(vaultKey);
  const deviceSecret = parsed ? loadDeviceSecret(parsed.projectId) : null;

  let currentVersion = null;
  let stopped = false;

  // Get initial version from last config() call if available
  // Otherwise we'll pick it up on first poll
  async function poll() {
    if (stopped) return;

    try {
      const { version } = await checkVersion(vaultKey, environment, vaultUrl);

      if (currentVersion === null) {
        // First poll — just record the version
        currentVersion = version;
        return;
      }

      if (version === currentVersion) return; // No change

      // Version changed — do a full pull
      const result = await pullSecrets(vaultKey, environment, vaultUrl, deviceSecret);
      const oldVersion = currentVersion;
      currentVersion = result.version;

      // Diff: find what changed
      const changed = {};
      for (const [key, val] of Object.entries(result.secrets)) {
        const strVal = String(val);
        if (process.env[key] !== strVal) {
          changed[key] = strVal;
          process.env[key] = strVal;
        }
      }

      if (Object.keys(changed).length > 0 && onChange) {
        onChange(changed, result.secrets);
      }
    } catch (err) {
      if (onError) {
        onError(err);
      } else {
        console.warn(`[vaultdotenv] Watch poll failed: ${err.message}`);
      }
    }
  }

  const timer = setInterval(poll, interval);
  // Don't hold the process open just for watching
  if (timer.unref) timer.unref();

  // Run first poll immediately
  poll();

  _watcher = {
    stop() {
      stopped = true;
      clearInterval(timer);
      _watcher = null;
    },
  };

  return _watcher;
}

/**
 * Stop the active watcher if one is running.
 */
function unwatch() {
  if (_watcher) _watcher.stop();
}

module.exports = {
  config,
  configSync,
  watch,
  unwatch,
  checkVersion,
  pullSecrets,
  pushSecrets,
  parseDotenv,
  serializeDotenv,
  registerDevice,
  loadDeviceSecret,
  saveDeviceSecret,
  encrypt,
  decrypt,
};

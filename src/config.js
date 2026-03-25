'use strict';

/**
 * Shared configuration for the vaultdotenv CLI.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const DEFAULT_VAULT_URL = 'https://api.vaultdotenv.io';
const VAULT_DIR = path.join(os.homedir(), '.vault');
const KEYS_DIR = path.join(VAULT_DIR, 'keys');
const AUTH_PATH = path.join(VAULT_DIR, 'auth.json');

/**
 * Parse CLI flags from process.argv.
 */
function getFlag(args, name) {
  const idx = args.indexOf(`--${name}`);
  if (idx === -1) return undefined;
  return args[idx + 1];
}

/**
 * Resolve the vault key from --project flag, VAULT_KEY env, or .env file.
 */
function getVaultKey(args) {
  const { parseDotenv } = require('./index');

  // --project flag: look for saved key
  const projectName = getFlag(args, 'project');
  if (projectName) {
    const keyPath = path.join(KEYS_DIR, `${projectName}.key`);
    if (fs.existsSync(keyPath)) {
      return fs.readFileSync(keyPath, 'utf8').trim();
    }
    console.error(`Error: No vault key found for project "${projectName}". Expected at ${keyPath}`);
    console.error('Save it with: vde key save --project myapp --key vk_...');
    process.exit(1);
  }

  let key = process.env.VAULT_KEY;
  if (!key) {
    const envPath = path.resolve(process.cwd(), '.env');
    if (fs.existsSync(envPath)) {
      const parsed = parseDotenv(fs.readFileSync(envPath, 'utf8'));
      key = parsed.VAULT_KEY;
    }
  }
  if (!key) {
    console.error('Error: VAULT_KEY not found in environment or .env file');
    console.error('Tip: Use --project <name> if you saved the key with: vde key save');
    process.exit(1);
  }
  return key;
}

function getVaultUrl(args) {
  return getFlag(args, 'url') || process.env.VAULT_URL || DEFAULT_VAULT_URL;
}

function getEnvironment(args) {
  return getFlag(args, 'env') || process.env.NODE_ENV || 'development';
}

/**
 * Load CLI auth token from ~/.vault/auth.json.
 */
function getAuth() {
  if (!fs.existsSync(AUTH_PATH)) return null;
  try {
    return JSON.parse(fs.readFileSync(AUTH_PATH, 'utf8'));
  } catch {
    return null;
  }
}

/**
 * Save CLI auth token to ~/.vault/auth.json.
 */
function saveAuth(data) {
  if (!fs.existsSync(VAULT_DIR)) {
    fs.mkdirSync(VAULT_DIR, { mode: 0o700, recursive: true });
  }
  fs.writeFileSync(AUTH_PATH, JSON.stringify(data, null, 2), { mode: 0o600 });
}

/**
 * Remove CLI auth token.
 */
function removeAuth() {
  if (fs.existsSync(AUTH_PATH)) {
    fs.unlinkSync(AUTH_PATH);
    return true;
  }
  return false;
}

module.exports = {
  DEFAULT_VAULT_URL,
  VAULT_DIR,
  KEYS_DIR,
  AUTH_PATH,
  getFlag,
  getVaultKey,
  getVaultUrl,
  getEnvironment,
  getAuth,
  saveAuth,
  removeAuth,
};

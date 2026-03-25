'use strict';

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const SALT_ENCRYPT = 'vault-encrypt-v1';
const SALT_AUTH = 'vault-auth-v1';
/**
 * Derive a 256-bit key from the vault key using HKDF.
 * When deviceSecret is provided, the key material is HMAC(vaultKey, deviceSecret)
 * so both pieces are required to derive the same encryption/auth keys.
 *
 * @param {string} vaultKey - The master vault key
 * @param {string} salt - Purpose-specific salt
 * @param {string} [deviceSecret] - Device-bound secret (from ~/.vault/device.key)
 * @returns {Buffer} 32-byte derived key
 */
function deriveKey(vaultKey, salt, deviceSecret) {
  const ikm = deviceSecret
    ? crypto.createHmac('sha256', vaultKey).update(deviceSecret).digest()
    : vaultKey;
  return crypto.hkdfSync('sha256', ikm, salt, '', 32);
}

/**
 * Generate a random device secret.
 * @returns {string} 64-char hex string
 */
function generateDeviceSecret() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Hash a device secret for server-side storage (server never sees the raw secret).
 * @param {string} deviceSecret - The raw device secret
 * @returns {string} hex-encoded SHA-256 hash
 */
function hashDeviceSecret(deviceSecret) {
  return crypto.createHash('sha256').update(deviceSecret).digest('hex');
}

/**
 * Encrypt a plaintext string with AES-256-GCM.
 * @param {string} plaintext - Data to encrypt
 * @param {string} vaultKey - Master vault key
 * @param {string} [deviceSecret] - Device-bound secret
 * @returns {string} Base64-encoded iv:tag:ciphertext
 */
function encrypt(plaintext, vaultKey, deviceSecret) {
  const key = deriveKey(vaultKey, SALT_ENCRYPT, deviceSecret);
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(plaintext, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const tag = cipher.getAuthTag();

  // Pack as: iv + tag + ciphertext (all base64)
  const packed = Buffer.concat([iv, tag, encrypted]);
  return packed.toString('base64');
}

/**
 * Decrypt an AES-256-GCM encrypted string.
 * @param {string} encryptedBase64 - Base64-encoded iv:tag:ciphertext
 * @param {string} vaultKey - Master vault key
 * @param {string} [deviceSecret] - Device-bound secret
 * @returns {string} Decrypted plaintext
 */
function decrypt(encryptedBase64, vaultKey, deviceSecret) {
  const key = deriveKey(vaultKey, SALT_ENCRYPT, deviceSecret);
  const packed = Buffer.from(encryptedBase64, 'base64');

  const iv = packed.subarray(0, IV_LENGTH);
  const tag = packed.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const ciphertext = packed.subarray(IV_LENGTH + TAG_LENGTH);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(ciphertext);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString('utf8');
}

/**
 * Generate HMAC signature for API authentication.
 * @param {string} vaultKey - Master vault key
 * @param {string} body - Request body string
 * @param {string} [deviceSecret] - Device-bound secret
 * @returns {{ signature: string, timestamp: string }}
 */
function sign(vaultKey, body, deviceSecret) {
  const authKey = deriveKey(vaultKey, SALT_AUTH, deviceSecret);
  const timestamp = String(Date.now());
  const input = body + timestamp;
  const digest = crypto.createHmac('sha256', authKey).update(input, 'utf8').digest('hex');
  return { signature: `v=${timestamp},d=${digest}`, timestamp };
}

/**
 * Verify an HMAC signature.
 * @param {string} vaultKey - Master vault key
 * @param {string} body - Request body string
 * @param {string} sigHeader - Signature header value
 * @param {number} [maxAgeMs=300000] - Maximum age in ms (default 5 min)
 * @param {string} [deviceSecret] - Device-bound secret
 * @returns {{ valid: boolean, reason?: string }}
 */
function verify(vaultKey, body, sigHeader, maxAgeMs = 300_000, deviceSecret) {
  if (!vaultKey || !body || !sigHeader) return { valid: false, reason: 'missing_params' };

  const parts = {};
  for (const part of sigHeader.split(',')) {
    const idx = part.indexOf('=');
    if (idx !== -1) parts[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
  }

  const timestamp = parts['v'];
  const providedDigest = parts['d'];
  if (!timestamp || !providedDigest) return { valid: false, reason: 'malformed_signature' };

  const age = Date.now() - parseInt(timestamp, 10);
  if (isNaN(age) || age < -60_000 || age > maxAgeMs) return { valid: false, reason: 'timestamp_stale' };

  const authKey = deriveKey(vaultKey, SALT_AUTH, deviceSecret);
  const input = body + timestamp;
  const computed = crypto.createHmac('sha256', authKey).update(input, 'utf8').digest('hex');

  const valid = crypto.timingSafeEqual(
    Buffer.from(computed, 'hex'),
    Buffer.from(providedDigest, 'hex'),
  );

  return { valid };
}

/**
 * Parse a vault key into its components.
 * Format: vk_<projectId>_<secret>
 * @param {string} vaultKey
 * @returns {{ projectId: string, secret: string } | null}
 */
function parseVaultKey(vaultKey) {
  if (!vaultKey || !vaultKey.startsWith('vk_')) return null;
  const parts = vaultKey.split('_');
  if (parts.length < 3) return null;
  return {
    projectId: parts[1],
    secret: parts.slice(2).join('_'),
  };
}

/**
 * Generate a new vault key for a project.
 * @param {string} projectId
 * @returns {string} vk_<projectId>_<random>
 */
function generateVaultKey(projectId) {
  const secret = crypto.randomBytes(32).toString('hex');
  return `vk_${projectId}_${secret}`;
}

module.exports = {
  encrypt,
  decrypt,
  sign,
  verify,
  parseVaultKey,
  generateVaultKey,
  generateDeviceSecret,
  hashDeviceSecret,
  deriveKey,
};

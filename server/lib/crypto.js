/**
 * Cryptographic helpers for the vault server.
 * Password hashing (PBKDF2) and HMAC signature verification.
 */

import { HMAC_MAX_AGE_MS, PBKDF2_ITERATIONS } from './config.js';

// ── Hex/Buffer Utilities ───────────────────────────────────────────────────

export function bufferToHex(buf) {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToUint8(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function hexToArrayBuffer(hex) {
  return hexToUint8(hex).buffer;
}

// ── Password Hashing ───────────────────────────────────────────────────────

export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial, 256
  );
  const hash = new Uint8Array(bits);
  return `pbkdf2:${PBKDF2_ITERATIONS}:${bufferToHex(salt)}:${bufferToHex(hash)}`;
}

export async function verifyPassword(password, stored) {
  const [, iterStr, saltHex, hashHex] = stored.split(':');
  const iterations = parseInt(iterStr, 10);
  const salt = hexToUint8(saltHex);
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return bufferToHex(new Uint8Array(bits)) === hashHex;
}

// ── HMAC Signature Verification ────────────────────────────────────────────

export async function verifySignature(body, sigHeader, keyHash) {
  if (!body || !sigHeader || !keyHash) return { valid: false, reason: 'missing_params' };

  const parts = {};
  for (const part of sigHeader.split(',')) {
    const idx = part.indexOf('=');
    if (idx !== -1) parts[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
  }

  const timestamp = parts['v'];
  const providedDigest = parts['d'];
  if (!timestamp || !providedDigest) return { valid: false, reason: 'malformed' };

  const age = Date.now() - parseInt(timestamp, 10);
  if (isNaN(age) || age < -60_000 || age > HMAC_MAX_AGE_MS) return { valid: false, reason: 'stale' };

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', hexToArrayBuffer(keyHash), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
  );

  const input = encoder.encode(body + timestamp);
  const sigBuffer = hexToArrayBuffer(providedDigest);
  const valid = await crypto.subtle.verify('HMAC', key, sigBuffer, input);

  return { valid };
}

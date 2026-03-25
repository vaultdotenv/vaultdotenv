'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  encrypt, decrypt, sign, verify,
  generateVaultKey, parseVaultKey,
  generateDeviceSecret, hashDeviceSecret,
  deriveKey,
} = require('../../src/crypto');

describe('generateVaultKey', () => {
  it('creates key with correct prefix', () => {
    const key = generateVaultKey('myproject');
    assert.ok(key.startsWith('vk_myproject_'));
  });

  it('generates unique keys', () => {
    const a = generateVaultKey('proj');
    const b = generateVaultKey('proj');
    assert.notEqual(a, b);
  });

  it('secret portion is 64 hex chars', () => {
    const key = generateVaultKey('proj');
    const secret = key.split('_').slice(2).join('_');
    assert.equal(secret.length, 64);
    assert.match(secret, /^[0-9a-f]+$/);
  });
});

describe('parseVaultKey', () => {
  it('parses valid key', () => {
    const key = generateVaultKey('test-project');
    const parsed = parseVaultKey(key);
    assert.equal(parsed.projectId, 'test-project');
    assert.equal(parsed.secret.length, 64);
  });

  it('returns null for invalid key', () => {
    assert.equal(parseVaultKey('invalid'), null);
    assert.equal(parseVaultKey(''), null);
    assert.equal(parseVaultKey(null), null);
    assert.equal(parseVaultKey(undefined), null);
  });

  it('returns null for key without vk_ prefix', () => {
    assert.equal(parseVaultKey('xx_proj_secret'), null);
  });

  it('returns null for key with too few parts', () => {
    assert.equal(parseVaultKey('vk_onlyprefix'), null);
  });
});

describe('encrypt / decrypt', () => {
  const key = generateVaultKey('enctest');
  const plaintext = '{"SECRET":"value","DB":"postgres://localhost"}';

  it('encrypts to different value', () => {
    const encrypted = encrypt(plaintext, key);
    assert.notEqual(encrypted, plaintext);
  });

  it('decrypts back to original', () => {
    const encrypted = encrypt(plaintext, key);
    assert.equal(decrypt(encrypted, key), plaintext);
  });

  it('produces different ciphertext each time (random IV)', () => {
    const a = encrypt(plaintext, key);
    const b = encrypt(plaintext, key);
    assert.notEqual(a, b);
    assert.equal(decrypt(a, key), decrypt(b, key));
  });

  it('wrong key fails to decrypt', () => {
    const encrypted = encrypt(plaintext, key);
    const wrongKey = generateVaultKey('other');
    assert.throws(() => decrypt(encrypted, wrongKey));
  });

  it('handles empty string', () => {
    const encrypted = encrypt('', key);
    assert.equal(decrypt(encrypted, key), '');
  });

  it('handles unicode content', () => {
    const unicode = '{"emoji":"🔐","japanese":"テスト"}';
    const encrypted = encrypt(unicode, key);
    assert.equal(decrypt(encrypted, key), unicode);
  });

  it('handles large payloads', () => {
    const large = JSON.stringify(Object.fromEntries(
      Array.from({ length: 100 }, (_, i) => [`KEY_${i}`, `value_${'x'.repeat(100)}_${i}`])
    ));
    const encrypted = encrypt(large, key);
    assert.equal(decrypt(encrypted, key), large);
  });
});

describe('dual-key encrypt / decrypt (device secret)', () => {
  const key = generateVaultKey('dualtest');
  const deviceSecret = generateDeviceSecret();
  const deviceSecret2 = generateDeviceSecret();
  const plaintext = '{"API_KEY":"sk_live_test"}';

  it('encrypts and decrypts with both keys', () => {
    const encrypted = encrypt(plaintext, key, deviceSecret);
    assert.equal(decrypt(encrypted, key, deviceSecret), plaintext);
  });

  it('fails without device secret', () => {
    const encrypted = encrypt(plaintext, key, deviceSecret);
    assert.throws(() => decrypt(encrypted, key));
  });

  it('fails with wrong device secret', () => {
    const encrypted = encrypt(plaintext, key, deviceSecret);
    assert.throws(() => decrypt(encrypted, key, deviceSecret2));
  });

  it('fails with wrong vault key', () => {
    const encrypted = encrypt(plaintext, key, deviceSecret);
    const wrongKey = generateVaultKey('wrong');
    assert.throws(() => decrypt(encrypted, wrongKey, deviceSecret));
  });

  it('single-key and dual-key ciphertexts are incompatible', () => {
    const singleEnc = encrypt(plaintext, key);
    const dualEnc = encrypt(plaintext, key, deviceSecret);
    assert.throws(() => decrypt(singleEnc, key, deviceSecret));
    assert.throws(() => decrypt(dualEnc, key));
  });
});

describe('sign / verify', () => {
  const key = generateVaultKey('sigtest');
  const body = '{"project_id":"test","environment":"prod"}';

  it('produces valid signature format', () => {
    const { signature } = sign(key, body);
    assert.match(signature, /^v=\d+,d=[0-9a-f]+$/);
  });

  it('verifies valid signature', () => {
    const { signature } = sign(key, body);
    const { valid } = verify(key, body, signature);
    assert.equal(valid, true);
  });

  it('rejects tampered body', () => {
    const { signature } = sign(key, body);
    const { valid } = verify(key, body + 'x', signature);
    assert.equal(valid, false);
  });

  it('rejects wrong key', () => {
    const { signature } = sign(key, body);
    const wrongKey = generateVaultKey('wrong');
    const { valid } = verify(wrongKey, body, signature);
    assert.equal(valid, false);
  });

  it('rejects stale signature', async () => {
    const { signature } = sign(key, body);
    // Wait just enough for the timestamp to be stale
    await new Promise(r => setTimeout(r, 10));
    const { valid } = verify(key, body, signature, 1); // 1ms max age
    assert.equal(valid, false);
  });

  it('rejects malformed signature', () => {
    assert.deepEqual(verify(key, body, 'garbage'), { valid: false, reason: 'malformed_signature' });
    assert.deepEqual(verify(key, body, ''), { valid: false, reason: 'missing_params' });
    assert.deepEqual(verify(key, body, null), { valid: false, reason: 'missing_params' });
  });

  it('rejects missing params', () => {
    assert.deepEqual(verify(null, body, 'v=1,d=abc'), { valid: false, reason: 'missing_params' });
    assert.deepEqual(verify(key, null, 'v=1,d=abc'), { valid: false, reason: 'missing_params' });
  });
});

describe('dual-key sign / verify', () => {
  const key = generateVaultKey('dualsig');
  const deviceSecret = generateDeviceSecret();
  const deviceSecret2 = generateDeviceSecret();
  const body = '{"data":"test"}';

  it('verifies with correct keys', () => {
    const { signature } = sign(key, body, deviceSecret);
    const { valid } = verify(key, body, signature, 300_000, deviceSecret);
    assert.equal(valid, true);
  });

  it('fails without device secret', () => {
    const { signature } = sign(key, body, deviceSecret);
    const { valid } = verify(key, body, signature);
    assert.equal(valid, false);
  });

  it('fails with wrong device secret', () => {
    const { signature } = sign(key, body, deviceSecret);
    const { valid } = verify(key, body, signature, 300_000, deviceSecret2);
    assert.equal(valid, false);
  });

  it('single-key sig fails with device secret added', () => {
    const { signature } = sign(key, body);
    const { valid } = verify(key, body, signature, 300_000, deviceSecret);
    assert.equal(valid, false);
  });
});

describe('generateDeviceSecret', () => {
  it('generates 64-char hex string', () => {
    const secret = generateDeviceSecret();
    assert.equal(secret.length, 64);
    assert.match(secret, /^[0-9a-f]+$/);
  });

  it('generates unique secrets', () => {
    const secrets = new Set(Array.from({ length: 10 }, () => generateDeviceSecret()));
    assert.equal(secrets.size, 10);
  });
});

describe('hashDeviceSecret', () => {
  it('produces consistent hash', () => {
    const secret = generateDeviceSecret();
    assert.equal(hashDeviceSecret(secret), hashDeviceSecret(secret));
  });

  it('produces 64-char hex hash', () => {
    const hash = hashDeviceSecret(generateDeviceSecret());
    assert.equal(hash.length, 64);
    assert.match(hash, /^[0-9a-f]+$/);
  });

  it('different secrets produce different hashes', () => {
    const a = hashDeviceSecret(generateDeviceSecret());
    const b = hashDeviceSecret(generateDeviceSecret());
    assert.notEqual(a, b);
  });
});

describe('deriveKey', () => {
  it('produces 32-byte buffer', () => {
    const key = generateVaultKey('test');
    const derived = deriveKey(key, 'test-salt');
    assert.equal(derived.byteLength, 32);
  });

  it('same inputs produce same output', () => {
    const key = generateVaultKey('test');
    const a = Buffer.from(deriveKey(key, 'salt')).toString('hex');
    const b = Buffer.from(deriveKey(key, 'salt')).toString('hex');
    assert.equal(a, b);
  });

  it('different salts produce different keys', () => {
    const key = generateVaultKey('test');
    const a = Buffer.from(deriveKey(key, 'salt-a')).toString('hex');
    const b = Buffer.from(deriveKey(key, 'salt-b')).toString('hex');
    assert.notEqual(a, b);
  });

  it('with device secret differs from without', () => {
    const key = generateVaultKey('test');
    const secret = generateDeviceSecret();
    const a = Buffer.from(deriveKey(key, 'salt')).toString('hex');
    const b = Buffer.from(deriveKey(key, 'salt', secret)).toString('hex');
    assert.notEqual(a, b);
  });
});

'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { parseDotenv, serializeDotenv, loadDeviceSecret, saveDeviceSecret } = require('../../src/index');

describe('parseDotenv', () => {
  it('parses key=value pairs', () => {
    const result = parseDotenv('KEY1=value1\nKEY2=value2');
    assert.deepEqual(result, { KEY1: 'value1', KEY2: 'value2' });
  });

  it('ignores comments', () => {
    const result = parseDotenv('# comment\nKEY=value\n# another');
    assert.deepEqual(result, { KEY: 'value' });
  });

  it('ignores empty lines', () => {
    const result = parseDotenv('\n\nKEY=value\n\n');
    assert.deepEqual(result, { KEY: 'value' });
  });

  it('strips double quotes', () => {
    const result = parseDotenv('KEY="quoted value"');
    assert.deepEqual(result, { KEY: 'quoted value' });
  });

  it('strips single quotes', () => {
    const result = parseDotenv("KEY='quoted value'");
    assert.deepEqual(result, { KEY: 'quoted value' });
  });

  it('handles values with equals signs', () => {
    const result = parseDotenv('URL=postgres://user:pass@host:5432/db?ssl=true');
    assert.deepEqual(result, { URL: 'postgres://user:pass@host:5432/db?ssl=true' });
  });

  it('handles empty values', () => {
    const result = parseDotenv('EMPTY=\nKEY=value');
    assert.deepEqual(result, { EMPTY: '', KEY: 'value' });
  });

  it('ignores lines without equals', () => {
    const result = parseDotenv('no_equals_here\nKEY=value');
    assert.deepEqual(result, { KEY: 'value' });
  });

  it('trims whitespace', () => {
    const result = parseDotenv('  KEY  =  value  ');
    assert.deepEqual(result, { KEY: 'value' });
  });

  it('handles empty input', () => {
    assert.deepEqual(parseDotenv(''), {});
  });
});

describe('serializeDotenv', () => {
  it('serializes to key=value format', () => {
    const result = serializeDotenv({ A: '1', B: '2' });
    assert.equal(result, 'A=1\nB=2');
  });

  it('handles empty object', () => {
    assert.equal(serializeDotenv({}), '');
  });
});

describe('device secret management', () => {
  const testDir = path.join(os.tmpdir(), `vault-device-test-${Date.now()}`);
  const testProjectId = 'test-device-project';

  beforeEach(() => {
    fs.mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  it('loadDeviceSecret returns VAULT_DEVICE_SECRET env var', () => {
    const original = process.env.VAULT_DEVICE_SECRET;
    process.env.VAULT_DEVICE_SECRET = 'test-secret-from-env';
    const result = loadDeviceSecret('any-project');
    assert.equal(result, 'test-secret-from-env');
    if (original) process.env.VAULT_DEVICE_SECRET = original;
    else delete process.env.VAULT_DEVICE_SECRET;
  });

  it('loadDeviceSecret returns null for missing file', () => {
    const original = process.env.VAULT_DEVICE_SECRET;
    delete process.env.VAULT_DEVICE_SECRET;
    const result = loadDeviceSecret('nonexistent-project-xyz');
    assert.equal(result, null);
    if (original) process.env.VAULT_DEVICE_SECRET = original;
  });
});

describe('config / configSync', () => {
  const { config, configSync } = require('../../src/index');
  const testDir = path.join(os.tmpdir(), `vault-config-test-${Date.now()}`);
  const envPath = path.join(testDir, '.env');

  beforeEach(() => {
    fs.mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
    // Clean up process.env
    delete process.env.TEST_CONFIG_KEY;
  });

  it('configSync loads .env without VAULT_KEY as plain dotenv', () => {
    fs.writeFileSync(envPath, 'TEST_CONFIG_KEY=plain_value\n');
    const result = configSync({ path: envPath });
    assert.equal(result.parsed.TEST_CONFIG_KEY, 'plain_value');
    assert.equal(process.env.TEST_CONFIG_KEY, 'plain_value');
  });

  it('configSync does not override existing env vars', () => {
    process.env.TEST_CONFIG_KEY = 'existing';
    fs.writeFileSync(envPath, 'TEST_CONFIG_KEY=new_value\n');
    configSync({ path: envPath });
    assert.equal(process.env.TEST_CONFIG_KEY, 'existing');
  });

  it('configSync with override replaces existing env vars', () => {
    process.env.TEST_CONFIG_KEY = 'existing';
    fs.writeFileSync(envPath, 'TEST_CONFIG_KEY=overridden\n');
    configSync({ path: envPath, override: true });
    assert.equal(process.env.TEST_CONFIG_KEY, 'overridden');
  });

  it('configSync returns empty for missing file', () => {
    const result = configSync({ path: path.join(testDir, 'missing.env') });
    assert.deepEqual(result, { parsed: {} });
  });

  it('async config loads plain .env when no VAULT_KEY', async () => {
    fs.writeFileSync(envPath, 'TEST_CONFIG_KEY=async_value\n');
    const result = await config({ path: envPath });
    assert.equal(result.parsed.TEST_CONFIG_KEY, 'async_value');
  });
});

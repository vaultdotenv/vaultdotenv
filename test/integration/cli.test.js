'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const CLI = path.resolve(__dirname, '../../src/cli.js');

function run(cmd, opts = {}) {
  try {
    return execSync(`node ${CLI} ${cmd}`, {
      encoding: 'utf8',
      timeout: 15000,
      ...opts,
    }).trim();
  } catch (err) {
    return { error: true, stderr: err.stderr?.trim(), stdout: err.stdout?.trim(), status: err.status };
  }
}

describe('CLI integration', () => {
  describe('help', () => {
    it('shows help with no arguments', () => {
      const output = run('');
      assert.ok(output.includes('vaultdotenv'));
      assert.ok(output.includes('vde login'));
      assert.ok(output.includes('vde push'));
    });

    it('shows help for unknown command', () => {
      const output = run('unknown-command');
      assert.ok(output.includes('vaultdotenv'));
    });
  });

  describe('whoami', () => {
    it('shows login status', () => {
      const output = run('whoami');
      // Either "Logged in as..." or "Not logged in"
      assert.ok(
        output.includes('Logged in as') || output.includes('Not logged in'),
        `Expected login status, got: ${output}`
      );
    });
  });

  describe('key management', () => {
    const testDir = path.join(os.tmpdir(), `vault-cli-keys-${Date.now()}`);
    const origHome = process.env.HOME;

    // Note: key commands use ~/.vault/keys/ which is the real home dir
    // We test with unique project names to avoid conflicts

    it('key help shows usage', () => {
      const output = run('key');
      assert.ok(output.includes('Key management'));
      assert.ok(output.includes('key save'));
    });

    it('key list shows saved keys or empty', () => {
      const output = run('key list');
      assert.ok(
        output.includes('Saved project keys') || output.includes('No saved keys'),
        `Expected key list output, got: ${output}`
      );
    });

    it('key save requires --project and --key', () => {
      const output = run('key save');
      assert.ok(output.error);
      assert.ok(output.stderr.includes('Usage'));
    });

    it('key save + list + remove cycle', () => {
      const testProject = `test-cli-${Date.now()}`;

      // Save
      const saveOutput = run(`key save --project ${testProject} --key vk_test_abc123`);
      assert.ok(saveOutput.includes('Saved vault key'));

      // List
      const listOutput = run('key list');
      assert.ok(listOutput.includes(testProject));

      // Remove
      const removeOutput = run(`key remove --project ${testProject}`);
      assert.ok(removeOutput.includes('Removed'));
    });
  });

  describe('vault operations (require VAULT_KEY)', () => {
    it('push without VAULT_KEY shows error', () => {
      const output = run('push', {
        env: { ...process.env, VAULT_KEY: undefined },
        cwd: os.tmpdir(),
      });
      assert.ok(output.error);
      assert.ok(output.stderr.includes('VAULT_KEY'));
    });

    it('pull without VAULT_KEY shows error', () => {
      const output = run('pull', {
        env: { ...process.env, VAULT_KEY: undefined },
        cwd: os.tmpdir(),
      });
      assert.ok(output.error);
      assert.ok(output.stderr.includes('VAULT_KEY'));
    });

    it('versions without VAULT_KEY shows error', () => {
      const output = run('versions', {
        env: { ...process.env, VAULT_KEY: undefined },
        cwd: os.tmpdir(),
      });
      assert.ok(output.error);
      assert.ok(output.stderr.includes('VAULT_KEY'));
    });

    it('set without args shows usage', () => {
      const output = run('set', {
        env: { ...process.env, VAULT_KEY: 'vk_test_abc123' },
      });
      assert.ok(output.error);
      assert.ok(output.stderr.includes('Usage'));
    });

    it('delete without args shows usage', () => {
      const output = run('delete', {
        env: { ...process.env, VAULT_KEY: 'vk_test_abc123' },
      });
      assert.ok(output.error);
      assert.ok(output.stderr.includes('Usage'));
    });

    it('get without args shows usage', () => {
      const output = run('get', {
        env: { ...process.env, VAULT_KEY: 'vk_test_abc123' },
      });
      assert.ok(output.error);
      assert.ok(output.stderr.includes('Usage'));
    });
  });

  describe('device commands (require VAULT_KEY)', () => {
    it('approve-device without --id shows error', () => {
      const output = run('approve-device', {
        env: { ...process.env, VAULT_KEY: 'vk_test_abc123' },
      });
      assert.ok(output.error);
      assert.ok(output.stderr.includes('--id'));
    });

    it('revoke-device without --id shows error', () => {
      const output = run('revoke-device', {
        env: { ...process.env, VAULT_KEY: 'vk_test_abc123' },
      });
      assert.ok(output.error);
      assert.ok(output.stderr.includes('--id'));
    });
  });
});

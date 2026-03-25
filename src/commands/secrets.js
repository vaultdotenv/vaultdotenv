'use strict';

/**
 * CLI secret commands: push, pull, set, delete, get.
 */

const fs = require('fs');
const path = require('path');
const { sign, parseVaultKey } = require('../crypto');
const { parseDotenv, serializeDotenv, pullSecrets, pushSecrets } = require('../index');
const { getFlag, getVaultKey, getVaultUrl, getEnvironment } = require('../config');

async function push(args) {
  const vaultKey = getVaultKey(args);
  const env = getEnvironment(args);
  const vaultUrl = getVaultUrl(args);
  const envPath = path.resolve(process.cwd(), getFlag(args, 'file') || '.env');

  if (!fs.existsSync(envPath)) {
    console.error(`Error: ${envPath} not found`);
    process.exit(1);
  }

  const envContent = fs.readFileSync(envPath, 'utf8');
  const secrets = parseDotenv(envContent);
  delete secrets.VAULT_KEY;

  const keyCount = Object.keys(secrets).length;
  if (keyCount === 0) {
    console.error('Error: No secrets to push (only VAULT_KEY found)');
    process.exit(1);
  }

  // Diff against previous version
  let changedKeys = null;
  try {
    const prev = await pullSecrets(vaultKey, env, vaultUrl);
    const prevSecrets = prev.secrets;
    const diff = [];
    for (const key of Object.keys(secrets)) {
      if (!(key in prevSecrets)) diff.push(`+${key}`);
      else if (String(prevSecrets[key]) !== String(secrets[key])) diff.push(`~${key}`);
    }
    for (const key of Object.keys(prevSecrets)) {
      if (!(key in secrets)) diff.push(`-${key}`);
    }
    if (diff.length > 0) changedKeys = diff;
  } catch {
    changedKeys = Object.keys(secrets).map(k => `+${k}`);
  }

  console.log(`Pushing ${keyCount} secrets to ${env}...`);
  const result = await pushSecrets(vaultKey, env, secrets, vaultUrl, undefined, changedKeys);

  if (changedKeys) {
    const added = changedKeys.filter(k => k.startsWith('+')).length;
    const modified = changedKeys.filter(k => k.startsWith('~')).length;
    const removed = changedKeys.filter(k => k.startsWith('-')).length;
    const parts = [];
    if (added) parts.push(`${added} added`);
    if (modified) parts.push(`${modified} modified`);
    if (removed) parts.push(`${removed} removed`);
    console.log(`Pushed. Version: ${result.version} (${parts.join(', ')})`);
  } else {
    console.log(`Pushed. Version: ${result.version} (no changes)`);
  }
}

async function pull(args) {
  const vaultKey = getVaultKey(args);
  const env = getEnvironment(args);
  const vaultUrl = getVaultUrl(args);
  const output = getFlag(args, 'output');

  console.log(`Pulling secrets from ${env}...`);
  const { secrets, version } = await pullSecrets(vaultKey, env, vaultUrl);
  const keyCount = Object.keys(secrets).length;

  if (output) {
    fs.writeFileSync(output, serializeDotenv(secrets) + '\n');
    console.log(`Wrote ${keyCount} secrets to ${output} (version ${version})`);
  } else {
    console.log(`\n# vaultdotenv pull (${env}, version ${version})`);
    console.log(`# ${keyCount} secrets\n`);
    for (const [key, val] of Object.entries(secrets)) {
      const masked = String(val).length > 8
        ? String(val).slice(0, 4) + '...' + String(val).slice(-4)
        : '****';
      console.log(`${key}=${masked}`);
    }
  }
}

async function set(args) {
  const vaultKey = getVaultKey(args);
  const env = getEnvironment(args);
  const vaultUrl = getVaultUrl(args);
  const secretName = args[1];
  const secretValue = args[2];

  if (!secretName || secretValue === undefined) {
    console.error('Usage: vaultdotenv set SECRET_NAME "value" [--env production]');
    process.exit(1);
  }

  console.log(`Setting ${secretName} in ${env}...`);
  let secrets;
  try {
    const result = await pullSecrets(vaultKey, env, vaultUrl);
    secrets = result.secrets;
  } catch {
    secrets = {};
  }

  const isNew = !(secretName in secrets);
  secrets[secretName] = secretValue;

  const pushResult = await pushSecrets(vaultKey, env, secrets, vaultUrl, undefined, [`${isNew ? '+' : '~'}${secretName}`]);
  console.log(`Set ${secretName}. Version: ${pushResult.version} (${Object.keys(secrets).length} total secrets)`);
}

async function del(args) {
  const vaultKey = getVaultKey(args);
  const env = getEnvironment(args);
  const vaultUrl = getVaultUrl(args);
  const secretName = args[1];

  if (!secretName) {
    console.error('Usage: vaultdotenv delete SECRET_NAME [--env production]');
    process.exit(1);
  }

  const { secrets } = await pullSecrets(vaultKey, env, vaultUrl);

  if (!(secretName in secrets)) {
    console.error(`Error: ${secretName} not found in ${env}`);
    process.exit(1);
  }

  // Confirmation
  if (!args.includes('--confirm')) {
    const readline = require('readline');
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const answer = await new Promise(resolve => {
      rl.question(`\n  WARNING: This will permanently delete ${secretName} from ${env}.\n  This creates a new version without the key. You can rollback if needed.\n\n  Type the secret name to confirm: `, resolve);
    });
    rl.close();
    if (answer.trim() !== secretName) {
      console.log('Aborted.');
      process.exit(0);
    }
  }

  delete secrets[secretName];
  const pushResult = await pushSecrets(vaultKey, env, secrets, vaultUrl, undefined, [`-${secretName}`]);
  console.log(`Deleted ${secretName}. Version: ${pushResult.version} (${Object.keys(secrets).length} secrets remaining)`);
}

async function get(args) {
  const vaultKey = getVaultKey(args);
  const env = getEnvironment(args);
  const vaultUrl = getVaultUrl(args);
  const secretName = args[1];
  const raw = args.includes('--raw');
  const token = getFlag(args, 'token');

  if (!secretName) {
    console.error('Usage: vaultdotenv get SECRET_NAME [--env production] [--raw --token TOKEN]');
    process.exit(1);
  }

  const { secrets } = await pullSecrets(vaultKey, env, vaultUrl);

  if (!(secretName in secrets)) {
    console.error(`Error: ${secretName} not found in ${env}`);
    process.exit(1);
  }

  if (raw) {
    if (!token) {
      console.error('Error: --raw requires --token. Generate one from the dashboard.');
      process.exit(1);
    }

    const parsed = parseVaultKey(vaultKey);
    const body = JSON.stringify({ project_id: parsed.projectId, token });
    const { signature } = sign(vaultKey, body);

    const resp = await fetch(`${vaultUrl}/api/v1/reveal-token/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Vault-Signature': signature },
      body,
    });

    if (!resp.ok) {
      console.error(`Error: token validation failed (${resp.status})`);
      process.exit(1);
    }

    const result = await resp.json();
    if (!result.valid) {
      console.error(`Error: reveal token ${result.reason || 'invalid'}. Generate a new one from the dashboard.`);
      process.exit(1);
    }

    process.stdout.write(String(secrets[secretName]));
  } else {
    const val = String(secrets[secretName]);
    const masked = val.length > 8 ? val.slice(0, 4) + '...' + val.slice(-4) : '****';
    console.log(`${secretName}=${masked}`);
  }
}

module.exports = { push, pull, set, del, get };

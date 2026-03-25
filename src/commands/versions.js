'use strict';

/**
 * CLI version commands: versions, rollback.
 */

const { sign, parseVaultKey } = require('../crypto');
const { getFlag, getVaultKey, getVaultUrl, getEnvironment } = require('../config');

async function versions(args) {
  const vaultKey = getVaultKey(args);
  const env = getEnvironment(args);
  const vaultUrl = getVaultUrl(args);
  const parsed = parseVaultKey(vaultKey);

  const body = JSON.stringify({ project_id: parsed.projectId, environment: env });
  const { signature } = sign(vaultKey, body);

  const resp = await fetch(`${vaultUrl}/api/v1/secrets/versions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Vault-Signature': signature },
    body,
  });

  if (!resp.ok) { console.error(`Error: ${resp.status}`); process.exit(1); }
  const data = await resp.json();

  console.log(`Versions for ${env}:\n`);
  for (const v of data.versions) {
    const keys = v.changed_keys
      ? (typeof v.changed_keys === 'string' ? JSON.parse(v.changed_keys) : v.changed_keys)
      : null;
    console.log(`  v${v.version}  ${v.created_at}  ${keys ? keys.length + ' keys' : '?'}`);
  }
}

async function rollback(args) {
  const vaultKey = getVaultKey(args);
  const env = getEnvironment(args);
  const vaultUrl = getVaultUrl(args);
  const version = parseInt(getFlag(args, 'version'), 10);
  const parsed = parseVaultKey(vaultKey);

  if (!version) { console.error('Error: --version required'); process.exit(1); }

  const body = JSON.stringify({ project_id: parsed.projectId, environment: env, version });
  const { signature } = sign(vaultKey, body);

  const resp = await fetch(`${vaultUrl}/api/v1/secrets/rollback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Vault-Signature': signature },
    body,
  });

  if (!resp.ok) { console.error(`Error: ${resp.status}`); process.exit(1); }
  const data = await resp.json();
  console.log(`Rolled back to version ${version}. New version: ${data.version}`);
}

module.exports = { versions, rollback };

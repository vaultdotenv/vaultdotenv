'use strict';

/**
 * CLI device commands: register, approve, list, revoke.
 */

const os = require('os');
const { sign, parseVaultKey } = require('../crypto');
const { registerDevice } = require('../index');
const { getFlag, getVaultKey, getVaultUrl } = require('../config');

async function register(args) {
  const vaultKey = getVaultKey(args);
  const vaultUrl = getVaultUrl(args);
  const deviceName = getFlag(args, 'name') || os.hostname();

  console.log(`Registering device "${deviceName}"...`);
  const result = await registerDevice(vaultKey, vaultUrl, deviceName);

  if (result.status === 'approved') {
    console.log('Device registered and auto-approved (first device = owner).');
    console.log(`Device ID: ${result.deviceId}`);
    console.log('\nDevice secret saved to ~/.vault/');
  } else {
    console.log('Device registered (pending approval).');
    console.log(`Device ID: ${result.deviceId}`);
    console.log(`\nAsk the project owner to approve: vaultdotenv approve-device --id ${result.deviceId}`);
  }
}

async function approve(args) {
  const vaultKey = getVaultKey(args);
  const vaultUrl = getVaultUrl(args);
  const parsed = parseVaultKey(vaultKey);
  const deviceId = getFlag(args, 'id');

  if (!deviceId) { console.error('Error: --id <device-id> required'); process.exit(1); }

  const body = JSON.stringify({ project_id: parsed.projectId, device_id: deviceId });
  const { signature } = sign(vaultKey, body);

  const resp = await fetch(`${vaultUrl}/api/v1/devices/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Vault-Signature': signature },
    body,
  });

  if (!resp.ok) { console.error(`Error: ${resp.status} ${await resp.text()}`); process.exit(1); }
  console.log(`Device ${deviceId} approved.`);
}

async function list(args) {
  const vaultKey = getVaultKey(args);
  const vaultUrl = getVaultUrl(args);
  const parsed = parseVaultKey(vaultKey);

  const body = JSON.stringify({ project_id: parsed.projectId });
  const { signature } = sign(vaultKey, body);

  const resp = await fetch(`${vaultUrl}/api/v1/devices/list`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Vault-Signature': signature },
    body,
  });

  if (!resp.ok) { console.error(`Error: ${resp.status}`); process.exit(1); }
  const data = await resp.json();

  console.log('Registered devices:\n');
  for (const d of data.devices) {
    const status = d.status === 'approved' ? '✓' : d.status === 'pending' ? '⏳' : '✗';
    const lastSeen = d.last_seen_at ? ` (last seen: ${d.last_seen_at})` : '';
    console.log(`  ${status} ${d.device_name}  [${d.id}]  ${d.status}${lastSeen}`);
  }
}

async function revoke(args) {
  const vaultKey = getVaultKey(args);
  const vaultUrl = getVaultUrl(args);
  const parsed = parseVaultKey(vaultKey);
  const deviceId = getFlag(args, 'id');

  if (!deviceId) { console.error('Error: --id <device-id> required'); process.exit(1); }

  const body = JSON.stringify({ project_id: parsed.projectId, device_id: deviceId });
  const { signature } = sign(vaultKey, body);

  const resp = await fetch(`${vaultUrl}/api/v1/devices/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Vault-Signature': signature },
    body,
  });

  if (!resp.ok) { console.error(`Error: ${resp.status} ${await resp.text()}`); process.exit(1); }
  console.log(`Device ${deviceId} revoked.`);
}

module.exports = { register, approve, list, revoke };

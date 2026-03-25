'use strict';

/**
 * CLI init command: create a new vault project.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { generateVaultKey, deriveKey } = require('../crypto');
const { registerDevice } = require('../index');
const { getFlag, getVaultUrl, getAuth } = require('../config');

async function init(args) {
  const projectName = getFlag(args, 'name') || path.basename(process.cwd());
  const vaultUrl = getVaultUrl(args);

  const envPath = path.resolve(process.cwd(), '.env');
  let existing = '';
  if (fs.existsSync(envPath)) {
    existing = fs.readFileSync(envPath, 'utf8');
    if (existing.includes('VAULT_KEY=')) {
      console.error('Error: VAULT_KEY already exists in .env');
      process.exit(1);
    }
  }

  console.log(`Creating project "${projectName}" on ${vaultUrl}...`);

  // Create project on server
  const createResp = await fetch(`${vaultUrl}/api/v1/project/create`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ project_name: projectName }),
  });

  if (!createResp.ok) {
    const err = await createResp.text().catch(() => '');
    console.error(`Error creating project (${createResp.status}): ${err}`);
    process.exit(1);
  }

  const { project_id: serverId, environments } = await createResp.json();

  // Generate vault key
  const vaultKey = generateVaultKey(serverId);

  // Set auth key hash
  const authKey = deriveKey(vaultKey, 'vault-auth-v1');
  const authKeyHash = Buffer.from(authKey).toString('hex');

  const updateResp = await fetch(`${vaultUrl}/api/v1/project/set-key`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ project_id: serverId, auth_key_hash: authKeyHash }),
  });

  if (!updateResp.ok) {
    const err = await updateResp.text().catch(() => '');
    console.error(`Error setting auth key (${updateResp.status}): ${err}`);
    process.exit(1);
  }

  // Write VAULT_KEY to .env
  fs.writeFileSync(envPath, `${existing ? existing.trimEnd() + '\n' : ''}VAULT_KEY=${vaultKey}\n`);

  // Register device
  console.log('Registering this device...');
  const deviceResult = await registerDevice(vaultKey, vaultUrl, os.hostname());

  // Link to dashboard account if logged in
  const auth = getAuth();
  let linked = false;
  if (auth?.token) {
    try {
      const linkResp = await fetch(`${vaultUrl}/api/v1/dashboard/projects/link`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${auth.token}`,
        },
        body: JSON.stringify({ project_id: serverId }),
      });
      if (linkResp.ok) {
        linked = true;
        console.log(`Linked to dashboard account (${auth.email})`);
      }
    } catch {
      // Link failed — not critical, continue
    }
  }

  console.log(`\n✓ Project created: ${projectName} (${serverId})`);
  console.log(`  Environments: ${environments.join(', ')}`);
  console.log(`  Device: ${deviceResult.status} (${deviceResult.deviceId})`);
  console.log('  VAULT_KEY added to .env');
  console.log('  Device secret saved to ~/.vault/');
  if (!linked) {
    console.log('\n  Tip: Run "vde login" to link this project to your dashboard');
  }
  console.log('\nIMPORTANT: Add .vault-cache to your .gitignore');
}

module.exports = { init };

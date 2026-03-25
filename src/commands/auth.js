'use strict';

/**
 * CLI auth commands: login, logout, whoami.
 */

const path = require('path');
const { getVaultUrl, getAuth, saveAuth, removeAuth, VAULT_DIR } = require('../config');

async function login(args) {
  const vaultUrl = getVaultUrl(args);

  console.log('Authenticating with vaultdotenv...\n');

  const startResp = await fetch(`${vaultUrl}/api/v1/cli/auth/start`, { method: 'POST' });
  if (!startResp.ok) {
    console.error('Error: Failed to start auth flow');
    process.exit(1);
  }
  const { code, auth_url } = await startResp.json();

  console.log('Open this URL in your browser to authorize:\n');
  console.log(`  ${auth_url}\n`);
  console.log(`Your code: ${code}\n`);

  // Try to open browser automatically
  const open = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
  require('child_process').exec(`${open} "${auth_url}"`);

  console.log('Waiting for approval...');

  const maxAttempts = 120;
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise(r => setTimeout(r, 5000));

    const pollResp = await fetch(`${vaultUrl}/api/v1/cli/auth/poll?code=${code}`);
    if (!pollResp.ok) continue;

    const pollData = await pollResp.json();

    if (pollData.status === 'approved') {
      saveAuth({
        token: pollData.token,
        email: pollData.user?.email,
        api_url: vaultUrl,
      });

      console.log(`\n✓ Logged in as ${pollData.user?.email}`);
      console.log('  Token saved to ~/.vault/auth.json');
      return;
    }

    if (pollData.status === 'expired') {
      console.error('\nAuth code expired. Run vde login again.');
      process.exit(1);
    }

    process.stdout.write('.');
  }

  console.error('\nTimed out waiting for approval.');
  process.exit(1);
}

function logout() {
  if (removeAuth()) {
    console.log('Logged out. Auth token removed.');
  } else {
    console.log('Not logged in.');
  }
}

function whoami() {
  const auth = getAuth();
  if (!auth) {
    console.log('Not logged in. Run: vde login');
    return;
  }
  console.log(`Logged in as ${auth.email}`);
  console.log(`API: ${auth.api_url}`);
}

module.exports = { login, logout, whoami };

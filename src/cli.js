#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { encrypt, decrypt, sign, parseVaultKey, generateVaultKey, hashDeviceSecret, deriveKey } = require('./crypto');
const { parseDotenv, serializeDotenv, pullSecrets, pushSecrets, registerDevice, loadDeviceSecret } = require('./index');

const DEFAULT_VAULT_URL = 'https://api.vaultdotenv.io';

const args = process.argv.slice(2);
const command = args[0];

function getFlag(name) {
  const idx = args.indexOf(`--${name}`);
  if (idx === -1) return undefined;
  return args[idx + 1];
}

function getVaultKey() {
  // --project flag: look for key in ~/.vault/keys/<project>.key
  const projectName = getFlag('project');
  if (projectName) {
    const keyPath = path.join(os.homedir(), '.vault', 'keys', `${projectName}.key`);
    if (fs.existsSync(keyPath)) {
      return fs.readFileSync(keyPath, 'utf8').trim();
    }
    console.error(`Error: No vault key found for project "${projectName}". Expected at ${keyPath}`);
    console.error('Save it with: vde key save --project myapp --key vk_...');
    process.exit(1);
  }

  let key = process.env.VAULT_KEY;
  if (!key) {
    const envPath = path.resolve(process.cwd(), '.env');
    if (fs.existsSync(envPath)) {
      const parsed = parseDotenv(fs.readFileSync(envPath, 'utf8'));
      key = parsed.VAULT_KEY;
    }
  }
  if (!key) {
    console.error('Error: VAULT_KEY not found in environment or .env file');
    console.error('Tip: Use --project <name> if you saved the key with: vde key save');
    process.exit(1);
  }
  return key;
}

function getVaultUrl() {
  return getFlag('url') || process.env.VAULT_URL || DEFAULT_VAULT_URL;
}

function getEnvironment() {
  return getFlag('env') || process.env.NODE_ENV || 'development';
}

async function main() {
  // MCP server mode — hand off to dedicated MCP handler
  if (command === 'mcp') {
    require('./mcp');
    return;
  }

  switch (command) {
    case 'login': {
      const vaultUrl = getVaultUrl();

      // Step 1: Start auth flow
      console.log('Authenticating with vaultdotenv...\n');
      const startResp = await fetch(`${vaultUrl}/api/v1/cli/auth/start`, { method: 'POST' });
      if (!startResp.ok) {
        console.error('Error: Failed to start auth flow');
        process.exit(1);
      }
      const { code, auth_url } = await startResp.json();

      // Step 2: Open browser
      console.log(`Open this URL in your browser to authorize:\n`);
      console.log(`  ${auth_url}\n`);
      console.log(`Your code: ${code}\n`);

      // Try to open browser automatically
      const open = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
      require('child_process').exec(`${open} "${auth_url}"`);

      console.log('Waiting for approval...');

      // Step 3: Poll for approval
      const maxAttempts = 120; // 10 minutes at 5s intervals
      for (let i = 0; i < maxAttempts; i++) {
        await new Promise(r => setTimeout(r, 5000));

        const pollResp = await fetch(`${vaultUrl}/api/v1/cli/auth/poll?code=${code}`);
        if (!pollResp.ok) continue;

        const pollData = await pollResp.json();

        if (pollData.status === 'approved') {
          // Save auth token
          const authDir = path.join(os.homedir(), '.vault');
          if (!fs.existsSync(authDir)) fs.mkdirSync(authDir, { mode: 0o700, recursive: true });
          const authPath = path.join(authDir, 'auth.json');
          fs.writeFileSync(authPath, JSON.stringify({
            token: pollData.token,
            email: pollData.user?.email,
            api_url: vaultUrl,
          }, null, 2), { mode: 0o600 });

          console.log(`\n✓ Logged in as ${pollData.user?.email}`);
          console.log(`  Token saved to ~/.vault/auth.json`);
          break;
        }

        if (pollData.status === 'expired') {
          console.error('\nAuth code expired. Run vde login again.');
          process.exit(1);
        }

        // Still pending — show a dot
        process.stdout.write('.');
      }
      break;
    }

    case 'logout': {
      const authPath = path.join(os.homedir(), '.vault', 'auth.json');
      if (fs.existsSync(authPath)) {
        fs.unlinkSync(authPath);
        console.log('Logged out. Auth token removed.');
      } else {
        console.log('Not logged in.');
      }
      break;
    }

    case 'whoami': {
      const authPath = path.join(os.homedir(), '.vault', 'auth.json');
      if (!fs.existsSync(authPath)) {
        console.log('Not logged in. Run: vde login');
        break;
      }
      const auth = JSON.parse(fs.readFileSync(authPath, 'utf8'));
      console.log(`Logged in as ${auth.email}`);
      console.log(`API: ${auth.api_url}`);
      break;
    }

    case 'key': {
      const subCmd = args[1];
      const keysDir = path.join(os.homedir(), '.vault', 'keys');

      if (subCmd === 'save') {
        const projectName = getFlag('project');
        const vaultKey = getFlag('key');
        if (!projectName || !vaultKey) {
          console.error('Usage: vaultdotenv key save --project myapp --key vk_...');
          process.exit(1);
        }
        if (!fs.existsSync(keysDir)) {
          fs.mkdirSync(keysDir, { mode: 0o700, recursive: true });
        }
        fs.writeFileSync(path.join(keysDir, `${projectName}.key`), vaultKey + '\n', { mode: 0o600 });
        console.log(`Saved vault key for "${projectName}" to ~/.vault/keys/${projectName}.key`);
      } else if (subCmd === 'list') {
        if (!fs.existsSync(keysDir)) {
          console.log('No saved keys.');
          break;
        }
        const files = fs.readdirSync(keysDir).filter(f => f.endsWith('.key'));
        if (files.length === 0) {
          console.log('No saved keys.');
        } else {
          console.log('Saved project keys:\n');
          for (const f of files) {
            console.log(`  ${f.replace('.key', '')}`);
          }
        }
      } else if (subCmd === 'remove') {
        const projectName = getFlag('project');
        if (!projectName) {
          console.error('Usage: vaultdotenv key remove --project myapp');
          process.exit(1);
        }
        const keyPath = path.join(keysDir, `${projectName}.key`);
        if (fs.existsSync(keyPath)) {
          fs.unlinkSync(keyPath);
          console.log(`Removed vault key for "${projectName}".`);
        } else {
          console.error(`No saved key for "${projectName}".`);
        }
      } else {
        console.log(`
Key management:
  vaultdotenv key save --project myapp --key vk_...   Save a vault key
  vaultdotenv key list                                 List saved keys
  vaultdotenv key remove --project myapp               Remove a saved key

Once saved, use --project to target:
  vaultdotenv pull --project myapp --env production
`);
      }
      break;
    }

    case 'init': {
      const projectName = getFlag('name') || path.basename(process.cwd());
      const vaultUrl = getVaultUrl();

      const envPath = path.resolve(process.cwd(), '.env');
      let existing = '';
      if (fs.existsSync(envPath)) {
        existing = fs.readFileSync(envPath, 'utf8');
        if (existing.includes('VAULT_KEY=')) {
          console.error('Error: VAULT_KEY already exists in .env');
          process.exit(1);
        }
      }

      // 1. Create project on server first to get the UUID
      //    We need a temporary key to derive the auth hash, but the project ID
      //    must match what the server stores. So we create project first,
      //    then generate the vault key with the server-assigned UUID.
      console.log(`Creating project "${projectName}" on ${vaultUrl}...`);

      // Generate a temporary key to get the auth hash format right
      // We'll regenerate with the real server ID after
      const tempId = 'pending';
      const tempKey = generateVaultKey(tempId);

      // Create project — server assigns the UUID
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

      // 2. Generate vault key using the server-assigned UUID
      const vaultKey = generateVaultKey(serverId);

      // 3. Derive auth key hash and update the project with it
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

      // 4. Write VAULT_KEY to .env
      fs.writeFileSync(envPath, `${existing ? existing.trimEnd() + '\n' : ''}VAULT_KEY=${vaultKey}\n`);

      // 5. Register this device (first device = auto-approved)
      console.log('Registering this device...');
      const deviceResult = await registerDevice(vaultKey, vaultUrl, require('os').hostname());

      // 6. Link to dashboard account if logged in
      const authPath = path.join(os.homedir(), '.vault', 'auth.json');
      let linked = false;
      if (fs.existsSync(authPath)) {
        try {
          const auth = JSON.parse(fs.readFileSync(authPath, 'utf8'));
          if (auth.token) {
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
          }
        } catch {}
      }

      console.log(`\n✓ Project created: ${projectName} (${serverId})`);
      console.log(`  Environments: ${environments.join(', ')}`);
      console.log(`  Device: ${deviceResult.status} (${deviceResult.deviceId})`);
      console.log(`  VAULT_KEY added to .env`);
      console.log(`  Device secret saved to ~/.vault/`);
      if (!linked) {
        console.log(`\n  Tip: Run "vde login" to link this project to your dashboard`);
      }
      console.log(`\nIMPORTANT: Add .vault-cache to your .gitignore`);
      break;
    }

    case 'push': {
      const vaultKey = getVaultKey();
      const env = getEnvironment();
      const vaultUrl = getVaultUrl();
      const envPath = path.resolve(process.cwd(), getFlag('file') || '.env');

      if (!fs.existsSync(envPath)) {
        console.error(`Error: ${envPath} not found`);
        process.exit(1);
      }

      const envContent = fs.readFileSync(envPath, 'utf8');
      const secrets = parseDotenv(envContent);
      delete secrets.VAULT_KEY; // Never push the vault key itself

      const keyCount = Object.keys(secrets).length;
      if (keyCount === 0) {
        console.error('Error: No secrets to push (only VAULT_KEY found)');
        process.exit(1);
      }

      // Diff against previous version to track actual changes
      let changedKeys = null;
      try {
        const prev = await pullSecrets(vaultKey, env, vaultUrl);
        const prevSecrets = prev.secrets;
        const diff = [];
        // Added or modified
        for (const key of Object.keys(secrets)) {
          if (!(key in prevSecrets)) {
            diff.push(`+${key}`);
          } else if (String(prevSecrets[key]) !== String(secrets[key])) {
            diff.push(`~${key}`);
          }
        }
        // Deleted
        for (const key of Object.keys(prevSecrets)) {
          if (!(key in secrets)) {
            diff.push(`-${key}`);
          }
        }
        if (diff.length > 0) changedKeys = diff;
      } catch {
        // No previous version — all keys are new
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
      break;
    }

    case 'pull': {
      const vaultKey = getVaultKey();
      const env = getEnvironment();
      const vaultUrl = getVaultUrl();

      console.log(`Pulling secrets from ${env}...`);
      const { secrets, version } = await pullSecrets(vaultKey, env, vaultUrl);
      const keyCount = Object.keys(secrets).length;

      if (getFlag('output')) {
        const outPath = getFlag('output');
        fs.writeFileSync(outPath, serializeDotenv(secrets) + '\n');
        console.log(`Wrote ${keyCount} secrets to ${outPath} (version ${version})`);
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
      break;
    }

    case 'get': {
      const vaultKey = getVaultKey();
      const env = getEnvironment();
      const vaultUrl = getVaultUrl();
      const secretName = args[1];
      const raw = args.includes('--raw');
      const token = getFlag('token');

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

        // Validate reveal token with the server
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
      break;
    }

    case 'set': {
      const vaultKey = getVaultKey();
      const env = getEnvironment();
      const vaultUrl = getVaultUrl();
      const secretName = args[1];
      const secretValue = args[2];

      if (!secretName || secretValue === undefined) {
        console.error('Usage: vaultdotenv set SECRET_NAME "value" [--env production]');
        process.exit(1);
      }

      // Pull existing secrets, update the one key, push back
      console.log(`Setting ${secretName} in ${env}...`);
      let secrets;
      try {
        const result = await pullSecrets(vaultKey, env, vaultUrl);
        secrets = result.secrets;
      } catch {
        // No secrets yet — start fresh
        secrets = {};
      }

      const isNew = !(secretName in secrets);
      secrets[secretName] = secretValue;

      const pushResult = await pushSecrets(vaultKey, env, secrets, vaultUrl, undefined, [`${isNew ? '+' : '~'}${secretName}`]);
      console.log(`Set ${secretName}. Version: ${pushResult.version} (${Object.keys(secrets).length} total secrets)`);
      break;
    }

    case 'delete': {
      const vaultKey = getVaultKey();
      const env = getEnvironment();
      const vaultUrl = getVaultUrl();
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

      // Require --confirm flag or interactive confirmation
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
      break;
    }

    case 'versions': {
      const vaultKey = getVaultKey();
      const env = getEnvironment();
      const vaultUrl = getVaultUrl();
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
        const keys = v.changed_keys ? (typeof v.changed_keys === 'string' ? JSON.parse(v.changed_keys) : v.changed_keys) : null;
        console.log(`  v${v.version}  ${v.created_at}  ${keys ? keys.length + ' keys' : '?'}`);

      }
      break;
    }

    case 'rollback': {
      const vaultKey = getVaultKey();
      const env = getEnvironment();
      const vaultUrl = getVaultUrl();
      const version = parseInt(getFlag('version'), 10);
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
      break;
    }

    case 'register-device': {
      const vaultKey = getVaultKey();
      const vaultUrl = getVaultUrl();
      const deviceName = getFlag('name') || require('os').hostname();

      console.log(`Registering device "${deviceName}"...`);
      const result = await registerDevice(vaultKey, vaultUrl, deviceName);

      if (result.status === 'approved') {
        console.log(`Device registered and auto-approved (first device = owner).`);
        console.log(`Device ID: ${result.deviceId}`);
        console.log(`\nDevice secret saved to ~/.vault/`);
      } else {
        console.log(`Device registered (pending approval).`);
        console.log(`Device ID: ${result.deviceId}`);
        console.log(`\nAsk the project owner to approve: vaultdotenv approve-device --id ${result.deviceId}`);
      }
      break;
    }

    case 'approve-device': {
      const vaultKey = getVaultKey();
      const vaultUrl = getVaultUrl();
      const parsed = parseVaultKey(vaultKey);
      const deviceId = getFlag('id');

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
      break;
    }

    case 'list-devices': {
      const vaultKey = getVaultKey();
      const vaultUrl = getVaultUrl();
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
      break;
    }

    case 'revoke-device': {
      const vaultKey = getVaultKey();
      const vaultUrl = getVaultUrl();
      const parsed = parseVaultKey(vaultKey);
      const deviceId = getFlag('id');

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
      break;
    }

    default:
      console.log(`
vaultdotenv — Remote secrets manager, drop-in dotenv replacement

Auth:
  vaultdotenv login                    Log in via browser (links CLI to dashboard)
  vaultdotenv logout                   Remove saved auth token
  vaultdotenv whoami                   Show current logged-in user

Usage:
  vaultdotenv init [--name project]   Initialize a new vault project
  vaultdotenv push [--env production] Push .env secrets to vault
  vaultdotenv pull [--env staging]    Pull secrets from vault
  vaultdotenv set KEY "value"          Set a single secret
  vaultdotenv delete KEY               Remove a secret
  vaultdotenv get KEY [--env prod]     Get a single secret (masked)
  vaultdotenv get KEY --raw --token T  Reveal cleartext (requires token)
  vaultdotenv versions [--env prod]    List secret versions
  vaultdotenv rollback --version 5     Rollback to a specific version

Device management:
  vaultdotenv register-device         Register this machine with the vault
  vaultdotenv approve-device --id X   Approve a pending device
  vaultdotenv list-devices            List all registered devices
  vaultdotenv revoke-device --id X    Revoke a device's access

Key management:
  vaultdotenv key save --project X --key vk_...  Save a vault key locally
  vaultdotenv key list                            List saved project keys
  vaultdotenv key remove --project X              Remove a saved key

MCP server:
  vaultdotenv mcp                    Start MCP server (stdio) for Claude Code

Options:
  --project <name>  Use saved key for project (from key save)
  --env <name>      Environment (default: NODE_ENV or development)
  --url <url>       Vault server URL (default: api.vaultdotenv.io)
  --file <path>     Source .env file for push (default: .env)
  --output <path>   Output file for pull (default: stdout)
  --name <name>     Device or project name
  --id <id>         Device ID (for approve/revoke)
`);
  }
}

main().catch(err => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});

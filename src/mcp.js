#!/usr/bin/env node
'use strict';

/**
 * vaultdotenv MCP Server — stdio transport for Claude Code integration.
 *
 * Reads VAULT_KEY from .env in the current directory and device secret
 * from ~/.vault/<projectId>.key. Same credentials as the CLI.
 *
 * Security: secret values are masked by default. Use reveal-secret
 * to expose a specific key's value.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const {
  parseDotenv,
  pullSecrets,
  pushSecrets,
  registerDevice,
  loadDeviceSecret,
} = require('./index');
const { parseVaultKey, sign, hashDeviceSecret } = require('./crypto');

const DEFAULT_VAULT_URL = 'https://api.vaultdotenv.io';

// ── Helpers ─────────────────────────────────────────────────────────────

function getVaultKey() {
  let key = process.env.VAULT_KEY;
  if (!key) {
    const envPath = path.resolve(process.cwd(), '.env');
    if (fs.existsSync(envPath)) {
      const parsed = parseDotenv(fs.readFileSync(envPath, 'utf8'));
      key = parsed.VAULT_KEY;
    }
  }
  return key || null;
}

function getVaultUrl() {
  return process.env.VAULT_URL || DEFAULT_VAULT_URL;
}

function mask(value) {
  const s = String(value);
  if (s.length <= 8) return '****';
  return s.slice(0, 4) + '****' + s.slice(-4);
}

// ── Tool definitions ────────────────────────────────────────────────────

const TOOLS = [
  {
    name: 'pull-secrets',
    description: 'Pull secrets from the vault. Returns key names with masked values for safety. Use reveal-secret to see a specific value.',
    inputSchema: {
      type: 'object',
      properties: {
        environment: { type: 'string', description: 'Environment name (default: development)' },
      },
    },
  },
  {
    name: 'reveal-secret',
    description: 'Reveal the full unmasked value of a specific secret. Use sparingly — values appear in the conversation context.',
    inputSchema: {
      type: 'object',
      properties: {
        key: { type: 'string', description: 'The secret key name to reveal (e.g. DATABASE_URL)' },
        environment: { type: 'string', description: 'Environment name (default: development)' },
      },
      required: ['key'],
    },
  },
  {
    name: 'push-secrets',
    description: 'Push one or more secrets to the vault. Merges with existing secrets — only updates the keys you specify.',
    inputSchema: {
      type: 'object',
      properties: {
        environment: { type: 'string', description: 'Environment name (default: development)' },
        secrets: {
          type: 'object',
          description: 'Key-value pairs to push (e.g. {"STRIPE_KEY": "sk_live_..."})',
          additionalProperties: { type: 'string' },
        },
      },
      required: ['secrets'],
    },
  },
  {
    name: 'list-versions',
    description: 'List the version history for an environment, showing when secrets were changed.',
    inputSchema: {
      type: 'object',
      properties: {
        environment: { type: 'string', description: 'Environment name (default: development)' },
      },
    },
  },
  {
    name: 'rollback',
    description: 'Rollback secrets to a previous version. Creates a new version with the old content (non-destructive).',
    inputSchema: {
      type: 'object',
      properties: {
        environment: { type: 'string', description: 'Environment name (default: development)' },
        version: { type: 'integer', description: 'Version number to rollback to' },
      },
      required: ['version'],
    },
  },
  {
    name: 'list-devices',
    description: 'List all registered devices for this project with their approval status.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'approve-device',
    description: 'Approve a pending device, granting it access to pull and push secrets.',
    inputSchema: {
      type: 'object',
      properties: {
        device_id: { type: 'string', description: 'The device UUID to approve' },
      },
      required: ['device_id'],
    },
  },
  {
    name: 'revoke-device',
    description: 'Revoke a device, permanently removing its access to secrets. This cannot be undone.',
    inputSchema: {
      type: 'object',
      properties: {
        device_id: { type: 'string', description: 'The device UUID to revoke' },
      },
      required: ['device_id'],
    },
  },
];

// ── Tool handlers ───────────────────────────────────────────────────────

async function handleTool(name, args) {
  const vaultKey = getVaultKey();
  if (!vaultKey) {
    return { error: 'VAULT_KEY not found. Make sure .env contains VAULT_KEY or set it in the environment.' };
  }

  const vaultUrl = getVaultUrl();
  const parsed = parseVaultKey(vaultKey);
  if (!parsed) {
    return { error: 'Invalid VAULT_KEY format. Expected: vk_<projectId>_<secret>' };
  }

  const env = args.environment || process.env.NODE_ENV || 'development';

  switch (name) {
    case 'pull-secrets': {
      const { secrets, version } = await pullSecrets(vaultKey, env, vaultUrl);
      const masked = {};
      for (const [k, v] of Object.entries(secrets)) {
        masked[k] = mask(v);
      }
      return {
        environment: env,
        version,
        secret_count: Object.keys(secrets).length,
        secrets: masked,
        note: 'Values are masked. Use reveal-secret to see a specific value.',
      };
    }

    case 'reveal-secret': {
      const { secrets } = await pullSecrets(vaultKey, env, vaultUrl);
      const key = args.key;
      if (!(key in secrets)) {
        return { error: `Secret "${key}" not found in ${env}. Available keys: ${Object.keys(secrets).join(', ')}` };
      }
      return {
        key,
        value: String(secrets[key]),
        environment: env,
      };
    }

    case 'push-secrets': {
      // Pull existing, merge, push
      let existing = {};
      try {
        const result = await pullSecrets(vaultKey, env, vaultUrl);
        existing = result.secrets;
      } catch {
        // No existing secrets — that's fine for first push
      }

      const merged = { ...existing, ...args.secrets };
      const result = await pushSecrets(vaultKey, env, merged, vaultUrl);

      return {
        environment: env,
        version: result.version,
        keys_updated: Object.keys(args.secrets),
        total_secrets: Object.keys(merged).length,
      };
    }

    case 'list-versions': {
      const body = JSON.stringify({ project_id: parsed.projectId, environment: env });
      const { signature } = sign(vaultKey, body);

      const resp = await fetch(`${vaultUrl}/api/v1/secrets/versions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Vault-Signature': signature },
        body,
      });

      if (!resp.ok) return { error: `Failed to list versions (${resp.status})` };
      const data = await resp.json();

      return {
        environment: env,
        versions: data.versions,
      };
    }

    case 'rollback': {
      const body = JSON.stringify({
        project_id: parsed.projectId,
        environment: env,
        version: args.version,
      });
      const { signature } = sign(vaultKey, body);

      const resp = await fetch(`${vaultUrl}/api/v1/secrets/rollback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Vault-Signature': signature },
        body,
      });

      if (!resp.ok) return { error: `Rollback failed (${resp.status})` };
      const data = await resp.json();

      return {
        environment: env,
        rolled_back_to: args.version,
        new_version: data.version,
      };
    }

    case 'list-devices': {
      const body = JSON.stringify({ project_id: parsed.projectId });
      const { signature } = sign(vaultKey, body);

      const resp = await fetch(`${vaultUrl}/api/v1/devices/list`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Vault-Signature': signature },
        body,
      });

      if (!resp.ok) return { error: `Failed to list devices (${resp.status})` };
      const data = await resp.json();

      return { devices: data.devices };
    }

    case 'approve-device': {
      const body = JSON.stringify({ project_id: parsed.projectId, device_id: args.device_id });
      const { signature } = sign(vaultKey, body);

      const resp = await fetch(`${vaultUrl}/api/v1/devices/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Vault-Signature': signature },
        body,
      });

      if (!resp.ok) {
        const err = await resp.text().catch(() => '');
        return { error: `Failed to approve device (${resp.status}): ${err}` };
      }

      return { device_id: args.device_id, status: 'approved' };
    }

    case 'revoke-device': {
      const body = JSON.stringify({ project_id: parsed.projectId, device_id: args.device_id });
      const { signature } = sign(vaultKey, body);

      const resp = await fetch(`${vaultUrl}/api/v1/devices/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Vault-Signature': signature },
        body,
      });

      if (!resp.ok) {
        const err = await resp.text().catch(() => '');
        return { error: `Failed to revoke device (${resp.status}): ${err}` };
      }

      return { device_id: args.device_id, status: 'revoked' };
    }

    default:
      return { error: `Unknown tool: ${name}` };
  }
}

// ── JSON-RPC stdio transport ────────────────────────────────────────────

let buffer = '';

process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffer += chunk;

  // MCP uses newline-delimited JSON-RPC
  let newlineIdx;
  while ((newlineIdx = buffer.indexOf('\n')) !== -1) {
    const line = buffer.slice(0, newlineIdx).trim();
    buffer = buffer.slice(newlineIdx + 1);
    if (line) handleMessage(line);
  }
});

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

async function handleMessage(line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return; // Ignore malformed JSON
  }

  const { id, method, params } = msg;

  switch (method) {
    case 'initialize':
      send({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          serverInfo: { name: 'vaultdotenv', version: '0.1.0' },
          capabilities: { tools: {} },
        },
      });
      break;

    case 'notifications/initialized':
      // Client acknowledged — no response needed
      break;

    case 'tools/list':
      send({
        jsonrpc: '2.0',
        id,
        result: { tools: TOOLS },
      });
      break;

    case 'tools/call': {
      const { name, arguments: args } = params;
      try {
        const result = await handleTool(name, args || {});
        send({
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
          },
        });
      } catch (err) {
        send({
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text: JSON.stringify({ error: err.message }) }],
            isError: true,
          },
        });
      }
      break;
    }

    default:
      if (id) {
        send({
          jsonrpc: '2.0',
          id,
          error: { code: -32601, message: `Method not found: ${method}` },
        });
      }
  }
}

// Handle clean shutdown
process.stdin.on('end', () => process.exit(0));

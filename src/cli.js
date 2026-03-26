#!/usr/bin/env node
'use strict';

/**
 * vaultdotenv CLI — remote secrets manager, drop-in dotenv replacement.
 *
 * Commands are implemented in src/commands/*.js.
 * Shared config in src/config.js.
 */

const args = process.argv.slice(2);
const command = args[0];

async function main() {
  // MCP server mode
  if (command === 'mcp') {
    require('./mcp');
    return;
  }

  switch (command) {
    // Auth
    case 'login':    return (await r('./commands/auth')).login(args);
    case 'logout':   return (await r('./commands/auth')).logout();
    case 'whoami':   return (await r('./commands/auth')).whoami();

    // Project
    case 'init':       return (await r('./commands/init')).init(args);
    case 'projects':   return (await r('./commands/projects')).list(args);

    // Secrets
    case 'push':     return (await r('./commands/secrets')).push(args);
    case 'pull':     return (await r('./commands/secrets')).pull(args);
    case 'set':      return (await r('./commands/secrets')).set(args);
    case 'delete':   return (await r('./commands/secrets')).del(args);
    case 'get':      return (await r('./commands/secrets')).get(args);

    // Versions
    case 'versions': return (await r('./commands/versions')).versions(args);
    case 'rollback': return (await r('./commands/versions')).rollback(args);

    // Devices
    case 'register-device': return (await r('./commands/devices')).register(args);
    case 'approve-device':  return (await r('./commands/devices')).approve(args);
    case 'list-devices':    return (await r('./commands/devices')).list(args);
    case 'revoke-device':   return (await r('./commands/devices')).revoke(args);

    // Key management
    case 'key': {
      const keys = require('./commands/keys');
      const sub = args[1];
      if (sub === 'save')   return keys.save(args);
      if (sub === 'list')   return keys.list();
      if (sub === 'remove') return keys.remove(args);
      return keys.help();
    }

    default:
      printHelp();
  }
}

// Lazy require — only load the command module when needed
function r(mod) { return Promise.resolve(require(mod)); }

function printHelp() {
  console.log(`
vaultdotenv — Remote secrets manager, drop-in dotenv replacement

Auth:
  vde login                            Log in via browser (links CLI to dashboard)
  vde logout                           Remove saved auth token
  vde whoami                           Show current logged-in user

Usage:
  vde projects                         List all your projects
  vde init [--name project]            Initialize a new vault project
  vde push [--env production]          Push .env secrets to vault
  vde pull [--env staging]             Pull secrets from vault
  vde set KEY "value" [--env prod]     Set a single secret
  vde delete KEY [--env prod]          Remove a secret (with confirmation)
  vde get KEY [--env prod]             Get a single secret (masked)
  vde get KEY --raw --token T          Reveal cleartext (requires token)
  vde versions [--env prod]            List secret versions
  vde rollback --version 5             Rollback to a specific version

Device management:
  vde register-device [--name X]       Register this machine with the vault
  vde approve-device --id X            Approve a pending device
  vde list-devices                     List all registered devices
  vde revoke-device --id X             Revoke a device's access

Key management:
  vde key save --project X --key vk_...  Save a vault key locally
  vde key list                           List saved project keys
  vde key remove --project X             Remove a saved key

MCP server:
  vde mcp                              Start MCP server (stdio)

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

main().catch(err => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});

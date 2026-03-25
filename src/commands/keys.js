'use strict';

/**
 * CLI key management: save, list, remove vault keys by project name.
 */

const fs = require('fs');
const path = require('path');
const { getFlag, KEYS_DIR } = require('../config');

function save(args) {
  const projectName = getFlag(args, 'project');
  const vaultKey = getFlag(args, 'key');
  if (!projectName || !vaultKey) {
    console.error('Usage: vaultdotenv key save --project myapp --key vk_...');
    process.exit(1);
  }
  if (!fs.existsSync(KEYS_DIR)) {
    fs.mkdirSync(KEYS_DIR, { mode: 0o700, recursive: true });
  }
  fs.writeFileSync(path.join(KEYS_DIR, `${projectName}.key`), vaultKey + '\n', { mode: 0o600 });
  console.log(`Saved vault key for "${projectName}" to ~/.vault/keys/${projectName}.key`);
}

function list() {
  if (!fs.existsSync(KEYS_DIR)) {
    console.log('No saved keys.');
    return;
  }
  const files = fs.readdirSync(KEYS_DIR).filter(f => f.endsWith('.key'));
  if (files.length === 0) {
    console.log('No saved keys.');
  } else {
    console.log('Saved project keys:\n');
    for (const f of files) {
      console.log(`  ${f.replace('.key', '')}`);
    }
  }
}

function remove(args) {
  const projectName = getFlag(args, 'project');
  if (!projectName) {
    console.error('Usage: vaultdotenv key remove --project myapp');
    process.exit(1);
  }
  const keyPath = path.join(KEYS_DIR, `${projectName}.key`);
  if (fs.existsSync(keyPath)) {
    fs.unlinkSync(keyPath);
    console.log(`Removed vault key for "${projectName}".`);
  } else {
    console.error(`No saved key for "${projectName}".`);
  }
}

function help() {
  console.log(`
Key management:
  vaultdotenv key save --project myapp --key vk_...   Save a vault key
  vaultdotenv key list                                 List saved keys
  vaultdotenv key remove --project myapp               Remove a saved key

Once saved, use --project to target:
  vaultdotenv pull --project myapp --env production
`);
}

module.exports = { save, list, remove, help };

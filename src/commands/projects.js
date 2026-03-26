'use strict';

const { getAuth, getVaultUrl } = require('../config');

async function list(args) {
  const auth = getAuth();
  if (!auth || !auth.token) {
    console.error('Not logged in. Run: vde login');
    process.exit(1);
  }

  const vaultUrl = getVaultUrl(args);

  const resp = await fetch(`${vaultUrl}/api/v1/dashboard/projects`, {
    headers: { 'Authorization': `Bearer ${auth.token}` },
  });

  if (resp.status === 401) {
    console.error('Session expired. Run: vde login');
    process.exit(1);
  }

  if (!resp.ok) {
    console.error(`Error: ${resp.status} ${await resp.text()}`);
    process.exit(1);
  }

  const { projects } = await resp.json();

  if (!projects || projects.length === 0) {
    console.log('No projects found. Create one with: vde init');
    return;
  }

  console.log(`\nProjects (${projects.length}):\n`);
  for (const p of projects) {
    const envs = (p.environments || []).map(e => e.name).join(', ');
    console.log(`  ${p.name}`);
    console.log(`    ID: ${p.id}`);
    if (envs) console.log(`    Environments: ${envs}`);
    console.log();
  }
}

module.exports = { list };

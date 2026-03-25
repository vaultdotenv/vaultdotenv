/**
 * CLI secret endpoints: push, pull, versions, rollback, current-version.
 * Authenticated via HMAC signature (vault key).
 */

import { verifySignature } from '../lib/crypto.js';
import { validateDevice, projectHasDevices } from '../lib/middleware.js';

export async function handleCurrentVersion(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, environment } = JSON.parse(body);

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  const envRow = await env.DB.prepare(
    'SELECT * FROM environments WHERE project_id = ? AND name = ?'
  ).bind(project_id, environment).first();
  if (!envRow) return Response.json({ error: 'Environment not found' }, { status: 404, headers: corsHeaders });

  const latest = await env.DB.prepare(
    'SELECT version, created_at FROM secret_versions WHERE environment_id = ? ORDER BY version DESC LIMIT 1'
  ).bind(envRow.id).first();

  return Response.json({
    version: latest?.version || 0,
    updated_at: latest?.created_at || null,
  }, { headers: corsHeaders });
}

export async function handlePull(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, environment, device_hash } = JSON.parse(body);

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  const hasDevices = await projectHasDevices(env, project_id);
  if (hasDevices) {
    const deviceCheck = await validateDevice(env, project_id, device_hash);
    if (!deviceCheck.valid) {
      const msg = deviceCheck.reason === 'pending'
        ? 'Device pending approval'
        : 'Device not registered or revoked';
      return Response.json({ error: msg }, { status: 403, headers: corsHeaders });
    }
  }

  const envRow = await env.DB.prepare(
    'SELECT * FROM environments WHERE project_id = ? AND name = ?'
  ).bind(project_id, environment).first();
  if (!envRow) return Response.json({ error: 'Environment not found' }, { status: 404, headers: corsHeaders });

  const latest = await env.DB.prepare(
    'SELECT * FROM secret_versions WHERE environment_id = ? ORDER BY version DESC LIMIT 1'
  ).bind(envRow.id).first();

  if (!latest) return Response.json({ error: 'No secrets stored yet' }, { status: 404, headers: corsHeaders });

  await env.DB.prepare(
    'INSERT INTO audit_log (project_id, environment_id, action, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(project_id, envRow.id, 'pull', request.headers.get('CF-Connecting-IP'), request.headers.get('User-Agent'), new Date().toISOString()).run();

  return Response.json({
    secrets: latest.encrypted_blob,
    version: latest.version,
  }, { headers: corsHeaders });
}

export async function handlePush(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, environment, secrets, key_names, device_hash } = JSON.parse(body);

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  const hasDevices = await projectHasDevices(env, project_id);
  if (hasDevices) {
    const deviceCheck = await validateDevice(env, project_id, device_hash);
    if (!deviceCheck.valid) {
      const msg = deviceCheck.reason === 'pending'
        ? 'Device pending approval'
        : 'Device not registered or revoked';
      return Response.json({ error: msg }, { status: 403, headers: corsHeaders });
    }
  }

  let envRow = await env.DB.prepare(
    'SELECT * FROM environments WHERE project_id = ? AND name = ?'
  ).bind(project_id, environment).first();

  if (!envRow) {
    const envId = crypto.randomUUID();
    await env.DB.prepare(
      'INSERT INTO environments (id, project_id, name, created_at) VALUES (?, ?, ?, ?)'
    ).bind(envId, project_id, environment, new Date().toISOString()).run();
    envRow = { id: envId };
  }

  const latest = await env.DB.prepare(
    'SELECT MAX(version) as max_version FROM secret_versions WHERE environment_id = ?'
  ).bind(envRow.id).first();
  const nextVersion = (latest?.max_version || 0) + 1;

  const changedKeys = key_names ? JSON.stringify(key_names) : null;
  await env.DB.prepare(
    'INSERT INTO secret_versions (environment_id, version, encrypted_blob, changed_keys, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(envRow.id, nextVersion, secrets, changedKeys, new Date().toISOString()).run();

  await env.DB.prepare(
    'INSERT INTO audit_log (project_id, environment_id, action, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(project_id, envRow.id, 'push', request.headers.get('CF-Connecting-IP'), request.headers.get('User-Agent'), new Date().toISOString()).run();

  return Response.json({ version: nextVersion }, { headers: corsHeaders });
}

export async function handleVersions(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, environment } = JSON.parse(body);

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  const envRow = await env.DB.prepare(
    'SELECT * FROM environments WHERE project_id = ? AND name = ?'
  ).bind(project_id, environment).first();
  if (!envRow) return Response.json({ error: 'Environment not found' }, { status: 404, headers: corsHeaders });

  const versions = await env.DB.prepare(
    'SELECT version, changed_keys, created_at FROM secret_versions WHERE environment_id = ? ORDER BY version DESC LIMIT 50'
  ).bind(envRow.id).all();

  return Response.json({ versions: versions.results }, { headers: corsHeaders });
}

export async function handleRollback(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, environment, version } = JSON.parse(body);

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  const envRow = await env.DB.prepare(
    'SELECT * FROM environments WHERE project_id = ? AND name = ?'
  ).bind(project_id, environment).first();
  if (!envRow) return Response.json({ error: 'Environment not found' }, { status: 404, headers: corsHeaders });

  const target = await env.DB.prepare(
    'SELECT * FROM secret_versions WHERE environment_id = ? AND version = ?'
  ).bind(envRow.id, version).first();
  if (!target) return Response.json({ error: 'Version not found' }, { status: 404, headers: corsHeaders });

  const latest = await env.DB.prepare(
    'SELECT MAX(version) as max_version FROM secret_versions WHERE environment_id = ?'
  ).bind(envRow.id).first();
  const nextVersion = (latest?.max_version || 0) + 1;

  await env.DB.prepare(
    'INSERT INTO secret_versions (environment_id, version, encrypted_blob, changed_keys, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(envRow.id, nextVersion, target.encrypted_blob, `["rollback_from_v${version}"]`, new Date().toISOString()).run();

  await env.DB.prepare(
    'INSERT INTO audit_log (project_id, environment_id, action, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(project_id, envRow.id, 'rollback', request.headers.get('CF-Connecting-IP'), request.headers.get('User-Agent'), new Date().toISOString()).run();

  return Response.json({ version: nextVersion }, { headers: corsHeaders });
}

/**
 * CLI device endpoints: register, approve, list, revoke.
 * Dashboard device endpoints: list, approve, revoke.
 * CLI endpoints use HMAC signature auth; dashboard endpoints use session auth.
 */

import { verifySignature } from '../lib/crypto.js';
import { validateDevice, projectHasDevices } from '../lib/middleware.js';

// ── CLI Endpoints (HMAC auth) ──────────────────────────────────────────────

export async function handleDeviceRegister(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, device_name, device_hash } = JSON.parse(body);

  if (!project_id || !device_name || !device_hash) {
    return Response.json({ error: 'project_id, device_name, and device_hash required' }, { status: 400, headers: corsHeaders });
  }

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  // Check if device already registered
  const existing = await env.DB.prepare(
    'SELECT * FROM devices WHERE project_id = ? AND device_hash = ?'
  ).bind(project_id, device_hash).first();

  if (existing) {
    return Response.json({ device_id: existing.id, status: existing.status }, { headers: corsHeaders });
  }

  // First device for a project is auto-approved (it's the owner)
  const hasDevices = await projectHasDevices(env, project_id);
  const status = hasDevices ? 'pending' : 'approved';
  const now = new Date().toISOString();

  const id = crypto.randomUUID();
  await env.DB.prepare(
    'INSERT INTO devices (id, project_id, device_name, device_hash, status, created_at, approved_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, project_id, device_name, device_hash, status, now, status === 'approved' ? now : null).run();

  // Audit
  await env.DB.prepare(
    'INSERT INTO audit_log (project_id, environment_id, action, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(project_id, null, 'device_register', request.headers.get('CF-Connecting-IP'), request.headers.get('User-Agent'), now).run();

  return Response.json({ device_id: id, status }, { headers: corsHeaders });
}

export async function handleDeviceApprove(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, device_id } = JSON.parse(body);

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  const device = await env.DB.prepare('SELECT * FROM devices WHERE id = ? AND project_id = ?').bind(device_id, project_id).first();
  if (!device) return Response.json({ error: 'Device not found' }, { status: 404, headers: corsHeaders });

  await env.DB.prepare(
    'UPDATE devices SET status = ?, approved_at = ? WHERE id = ?'
  ).bind('approved', new Date().toISOString(), device_id).run();

  return Response.json({ device_id, status: 'approved' }, { headers: corsHeaders });
}

export async function handleDeviceList(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id } = JSON.parse(body);

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  const devices = await env.DB.prepare(
    'SELECT id, device_name, status, created_at, approved_at, last_seen_at FROM devices WHERE project_id = ? ORDER BY created_at DESC'
  ).bind(project_id).all();

  return Response.json({ devices: devices.results }, { headers: corsHeaders });
}

export async function handleDeviceRevoke(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, device_id } = JSON.parse(body);

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  const device = await env.DB.prepare('SELECT * FROM devices WHERE id = ? AND project_id = ?').bind(device_id, project_id).first();
  if (!device) return Response.json({ error: 'Device not found' }, { status: 404, headers: corsHeaders });

  await env.DB.prepare('UPDATE devices SET status = ? WHERE id = ?').bind('revoked', device_id).run();

  return Response.json({ device_id, status: 'revoked' }, { headers: corsHeaders });
}

// ── Dashboard Endpoints (session auth) ─────────────────────────────────────

export async function dashboardListDevices(env, projectId, corsHeaders) {
  const devices = await env.DB.prepare(
    'SELECT id, device_name, status, created_at, approved_at, last_seen_at FROM devices WHERE project_id = ? ORDER BY created_at DESC'
  ).bind(projectId).all();
  return Response.json({ devices: devices.results }, { headers: corsHeaders });
}

export async function dashboardApproveDevice(env, projectId, deviceId, corsHeaders) {
  const device = await env.DB.prepare(
    'SELECT * FROM devices WHERE id = ? AND project_id = ?'
  ).bind(deviceId, projectId).first();
  if (!device) return Response.json({ error: 'Device not found' }, { status: 404, headers: corsHeaders });

  await env.DB.prepare(
    'UPDATE devices SET status = ?, approved_at = ? WHERE id = ?'
  ).bind('approved', new Date().toISOString(), deviceId).run();

  return Response.json({ device_id: deviceId, status: 'approved' }, { headers: corsHeaders });
}

export async function dashboardRevokeDevice(env, projectId, deviceId, corsHeaders) {
  const device = await env.DB.prepare(
    'SELECT * FROM devices WHERE id = ? AND project_id = ?'
  ).bind(deviceId, projectId).first();
  if (!device) return Response.json({ error: 'Device not found' }, { status: 404, headers: corsHeaders });

  await env.DB.prepare('UPDATE devices SET status = ? WHERE id = ?').bind('revoked', deviceId).run();

  return Response.json({ device_id: deviceId, status: 'revoked' }, { headers: corsHeaders });
}

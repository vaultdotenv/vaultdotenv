/**
 * Auth middleware and access control helpers.
 */

import { SESSION_MAX_AGE_MS, PLAN_LIMITS } from './config.js';

// ── Sessions ───────────────────────────────────────────────────────────────

export async function createSession(env, userId) {
  const id = crypto.randomUUID();
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_MAX_AGE_MS);
  await env.DB.prepare(
    'INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)'
  ).bind(id, userId, expires.toISOString(), now.toISOString()).run();
  return id;
}

export async function validateSession(env, request) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;

  const session = await env.DB.prepare(
    'SELECT s.*, u.id as uid, u.email, u.plan, u.is_superadmin FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = ?'
  ).bind(token).first();

  if (!session) return null;
  if (new Date(session.expires_at) < new Date()) {
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(token).run();
    return null;
  }

  return {
    id: session.uid,
    email: session.email,
    plan: session.plan || 'free',
    is_superadmin: !!session.is_superadmin,
  };
}

export async function requireSession(env, request, corsHeaders) {
  const user = await validateSession(env, request);
  if (!user) {
    return { user: null, error: Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders }) };
  }
  return { user, error: null };
}

// ── Access Control ─────────────────────────────────────────────────────────

const PERMISSION_LEVELS = { read: 0, write: 1, admin: 2 };

export async function requireProjectAccess(env, userId, projectId, corsHeaders, minPermission) {
  const row = await env.DB.prepare(
    'SELECT * FROM user_projects WHERE user_id = ? AND project_id = ?'
  ).bind(userId, projectId).first();

  if (!row) {
    return { ok: false, error: Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders }) };
  }

  if (minPermission) {
    const userLevel = PERMISSION_LEVELS[row.permission] ?? 0;
    const requiredLevel = PERMISSION_LEVELS[minPermission] ?? 0;
    if (userLevel < requiredLevel) {
      return { ok: false, error: Response.json({ error: `Requires ${minPermission} permission` }, { status: 403, headers: corsHeaders }) };
    }
  }

  const envScope = row.env_scope ? JSON.parse(row.env_scope) : null;
  return { ok: true, role: row.role, permission: row.permission || 'admin', envScope, error: null };
}

export async function requireOrgAccess(env, userId, orgId, corsHeaders) {
  const row = await env.DB.prepare(
    'SELECT * FROM org_members WHERE user_id = ? AND org_id = ?'
  ).bind(userId, orgId).first();

  if (!row) {
    return { ok: false, error: Response.json({ error: 'Organization not found' }, { status: 404, headers: corsHeaders }) };
  }
  return { ok: true, role: row.role, error: null };
}

// ── Helpers ────────────────────────────────────────────────────────────────

export async function getPersonalOrg(env, userId) {
  return env.DB.prepare(
    'SELECT o.* FROM orgs o JOIN org_members om ON o.id = om.org_id WHERE om.user_id = ? AND o.personal = 1'
  ).bind(userId).first();
}

export function slugify(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

// ── Device Helpers ─────────────────────────────────────────────────────────

export async function validateDevice(env, projectId, deviceHash) {
  if (!deviceHash) return { valid: false, reason: 'no_device_hash' };

  const device = await env.DB.prepare(
    'SELECT * FROM devices WHERE project_id = ? AND device_hash = ?'
  ).bind(projectId, deviceHash).first();

  if (!device) return { valid: false, reason: 'unregistered' };
  if (device.status === 'pending') return { valid: false, reason: 'pending' };
  if (device.status === 'revoked') return { valid: false, reason: 'revoked' };

  await env.DB.prepare(
    'UPDATE devices SET last_seen_at = ? WHERE id = ?'
  ).bind(new Date().toISOString(), device.id).run();

  return { valid: true, device };
}

export async function projectHasDevices(env, projectId) {
  const count = await env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM devices WHERE project_id = ?'
  ).bind(projectId).first();
  return count.cnt > 0;
}

// ── Plan Usage ─────────────────────────────────────────────────────────────

export async function getUserPlanUsage(env, userId) {
  const user = await env.DB.prepare('SELECT plan FROM users WHERE id = ?').bind(userId).first();
  const plan = user?.plan || 'free';
  const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.free;

  const projectCount = await env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM user_projects WHERE user_id = ?'
  ).bind(userId).first();

  const envCount = await env.DB.prepare(`
    SELECT COUNT(*) as cnt FROM environments e
    JOIN user_projects up ON e.project_id = up.project_id
    WHERE up.user_id = ?
  `).bind(userId).first();

  const deviceCount = await env.DB.prepare(`
    SELECT COUNT(*) as cnt FROM devices d
    JOIN user_projects up ON d.project_id = up.project_id
    WHERE up.user_id = ? AND d.status != 'revoked'
  `).bind(userId).first();

  const maxSecrets = await env.DB.prepare(`
    SELECT MAX(key_count) as max_keys FROM (
      SELECT CASE WHEN sv.changed_keys IS NOT NULL THEN json_array_length(sv.changed_keys) ELSE 0 END as key_count
      FROM secret_versions sv
      JOIN environments e ON sv.environment_id = e.id
      JOIN user_projects up ON e.project_id = up.project_id
      WHERE up.user_id = ?
        AND sv.version = (SELECT MAX(version) FROM secret_versions WHERE environment_id = sv.environment_id)
    )
  `).bind(userId).first();

  const envSecrets = await env.DB.prepare(`
    SELECT p.name || ' / ' || e.name as env_name, COALESCE(sv.key_count, 0) as secret_count
    FROM environments e
    JOIN projects p ON e.project_id = p.id
    JOIN user_projects up ON e.project_id = up.project_id
    LEFT JOIN secret_versions sv ON sv.environment_id = e.id
      AND sv.version = (SELECT MAX(version) FROM secret_versions WHERE environment_id = e.id)
    WHERE up.user_id = ?
    ORDER BY p.name, e.name
  `).bind(userId).all();

  const secretsByEnv = (envSecrets?.results || []).map(r => ({ name: r.env_name, count: r.secret_count }));
  const maxSecretCount = Math.max(0, ...secretsByEnv.map(e => e.count));

  return {
    plan, limits,
    projectCount: projectCount?.cnt || 0,
    environmentCount: envCount?.cnt || 0,
    deviceCount: deviceCount?.cnt || 0,
    secretCount: maxSecretCount,
    secretsByEnv,
  };
}

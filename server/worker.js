/**
 * Vault Server — Cloudflare Worker
 *
 * Stores encrypted secret blobs in D1.
 * Never sees decryption keys — all encryption is client-side.
 *
 * D1 Tables:
 *   projects(id, name, key_hash, created_at)
 *   environments(id, project_id, name, created_at)
 *   secret_versions(id, environment_id, version, encrypted_blob, changed_keys, created_at)
 *   devices(id, project_id, device_name, device_hash, status, created_at, approved_at, last_seen_at)
 *   audit_log(id, project_id, action, ip, user_agent, created_at)
 *   users(id, email, password_hash, created_at)
 *   sessions(id, user_id, expires_at, created_at)
 *   user_projects(user_id, project_id, role, created_at)
 *   reveal_tokens(id, project_id, user_id, expires_at, used_at, created_at)
 */

const HMAC_MAX_AGE_MS = 300_000; // 5 minutes

// ── Signature Verification ───────────────────────────────────────────────────

async function verifySignature(body, sigHeader, keyHash) {
  if (!body || !sigHeader || !keyHash) return { valid: false, reason: 'missing_params' };

  const parts = {};
  for (const part of sigHeader.split(',')) {
    const idx = part.indexOf('=');
    if (idx !== -1) parts[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
  }

  const timestamp = parts['v'];
  const providedDigest = parts['d'];
  if (!timestamp || !providedDigest) return { valid: false, reason: 'malformed' };

  const age = Date.now() - parseInt(timestamp, 10);
  if (isNaN(age) || age < -60_000 || age > HMAC_MAX_AGE_MS) return { valid: false, reason: 'stale' };

  // We verify against the stored key hash
  // The client signs with HKDF(vault_key, "vault-auth-v1")
  // We store that derived auth key hash at project creation
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', hexToBuffer(keyHash), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
  );

  const input = encoder.encode(body + timestamp);
  const sigBuffer = hexToBuffer(providedDigest);
  const valid = await crypto.subtle.verify('HMAC', key, sigBuffer, input);

  return { valid };
}

function hexToBuffer(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes.buffer;
}

// ── Request Router ───────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, X-Vault-Signature, Authorization',
        },
      });
    }

    const corsHeaders = { 'Access-Control-Allow-Origin': '*' };

    try {
      if (path === '/api/v1/project/create' && request.method === 'POST') {
        return handleCreateProject(request, env, corsHeaders);
      }
      if (path === '/api/v1/project/set-key' && request.method === 'POST') {
        return handleSetKey(request, env, corsHeaders);
      }
      if (path === '/api/v1/devices/register' && request.method === 'POST') {
        return handleDeviceRegister(request, env, corsHeaders);
      }
      if (path === '/api/v1/devices/approve' && request.method === 'POST') {
        return handleDeviceApprove(request, env, corsHeaders);
      }
      if (path === '/api/v1/devices/list' && request.method === 'POST') {
        return handleDeviceList(request, env, corsHeaders);
      }
      if (path === '/api/v1/devices/revoke' && request.method === 'POST') {
        return handleDeviceRevoke(request, env, corsHeaders);
      }
      if (path === '/api/v1/secrets/current-version' && request.method === 'POST') {
        return handleCurrentVersion(request, env, corsHeaders);
      }
      if (path === '/api/v1/secrets/pull' && request.method === 'POST') {
        return handlePull(request, env, corsHeaders);
      }
      if (path === '/api/v1/secrets/push' && request.method === 'POST') {
        return handlePush(request, env, corsHeaders);
      }
      if (path === '/api/v1/secrets/versions' && request.method === 'POST') {
        return handleVersions(request, env, corsHeaders);
      }
      if (path === '/api/v1/secrets/rollback' && request.method === 'POST') {
        return handleRollback(request, env, corsHeaders);
      }
      if (path === '/api/v1/reveal-token/validate' && request.method === 'POST') {
        return handleRevealTokenValidate(request, env, corsHeaders);
      }
      if (path === '/health') {
        return Response.json({ status: 'ok', ts: Date.now() }, { headers: corsHeaders });
      }

      // ── Dashboard API ───────────────────────────────────────────────────────
      if (path.startsWith('/api/v1/dashboard/')) {
        return handleDashboard(request, env, corsHeaders, path);
      }

      return Response.json({ error: 'Not found' }, { status: 404, headers: corsHeaders });
    } catch (err) {
      return Response.json({ error: err.message }, { status: 500, headers: corsHeaders });
    }
  },
};

// ── Handlers ─────────────────────────────────────────────────────────────────

async function handleCreateProject(request, env, corsHeaders) {
  const body = await request.text();
  const { project_name } = JSON.parse(body);

  if (!project_name) {
    return Response.json({ error: 'project_name required' }, { status: 400, headers: corsHeaders });
  }

  const id = crypto.randomUUID();
  // key_hash is set in a follow-up /project/set-key call (client needs the UUID first to generate the vault key)
  await env.DB.prepare(
    'INSERT INTO projects (id, name, key_hash, created_at) VALUES (?, ?, ?, ?)'
  ).bind(id, project_name, '', new Date().toISOString()).run();

  // Create default environments
  for (const envName of ['development', 'staging', 'production']) {
    await env.DB.prepare(
      'INSERT INTO environments (id, project_id, name, created_at) VALUES (?, ?, ?, ?)'
    ).bind(crypto.randomUUID(), id, envName, new Date().toISOString()).run();
  }

  return Response.json({ project_id: id, environments: ['development', 'staging', 'production'] }, { headers: corsHeaders });
}

async function handleSetKey(request, env, corsHeaders) {
  const body = await request.text();
  const { project_id, auth_key_hash } = JSON.parse(body);

  if (!project_id || !auth_key_hash) {
    return Response.json({ error: 'project_id and auth_key_hash required' }, { status: 400, headers: corsHeaders });
  }

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  // Only allow setting key if not already set (one-time operation)
  if (project.key_hash) {
    return Response.json({ error: 'Auth key already set' }, { status: 409, headers: corsHeaders });
  }

  await env.DB.prepare('UPDATE projects SET key_hash = ? WHERE id = ?').bind(auth_key_hash, project_id).run();

  return Response.json({ ok: true }, { headers: corsHeaders });
}

// ── Device Helpers ────────────────────────────────────────────────────────────

async function validateDevice(env, projectId, deviceHash) {
  if (!deviceHash) return { valid: false, reason: 'no_device_hash' };

  const device = await env.DB.prepare(
    'SELECT * FROM devices WHERE project_id = ? AND device_hash = ?'
  ).bind(projectId, deviceHash).first();

  if (!device) return { valid: false, reason: 'unregistered' };
  if (device.status === 'pending') return { valid: false, reason: 'pending' };
  if (device.status === 'revoked') return { valid: false, reason: 'revoked' };

  // Update last_seen
  await env.DB.prepare(
    'UPDATE devices SET last_seen_at = ? WHERE id = ?'
  ).bind(new Date().toISOString(), device.id).run();

  return { valid: true, device };
}

async function projectHasDevices(env, projectId) {
  const count = await env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM devices WHERE project_id = ?'
  ).bind(projectId).first();
  return count.cnt > 0;
}

// ── Device Handlers ──────────────────────────────────────────────────────────

async function handleDeviceRegister(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, device_name, device_hash } = JSON.parse(body);

  if (!project_id || !device_name || !device_hash) {
    return Response.json({ error: 'project_id, device_name, and device_hash required' }, { status: 400, headers: corsHeaders });
  }

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  // Verify signature (signed with vault key only, no device secret yet)
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

async function handleDeviceApprove(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, device_id } = JSON.parse(body);

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  // Must be signed by an approved device (the owner)
  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  const device = await env.DB.prepare('SELECT * FROM devices WHERE id = ? AND project_id = ?').bind(device_id, project_id).first();
  if (!device) return Response.json({ error: 'Device not found' }, { status: 404, headers: corsHeaders });

  await env.DB.prepare(
    'UPDATE devices SET status = ?, approved_at = ? WHERE id = ?'
  ).bind('approved', new Date().toISOString(), device_id).run();

  return Response.json({ device_id, status: 'approved' }, { headers: corsHeaders });
}

async function handleDeviceList(request, env, corsHeaders) {
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

async function handleDeviceRevoke(request, env, corsHeaders) {
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

// ── Secret Handlers ──────────────────────────────────────────────────────────

async function handleCurrentVersion(request, env, corsHeaders) {
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

async function handlePull(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, environment, device_hash } = JSON.parse(body);

  // Get project
  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  // Verify signature
  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  // Validate device if project has registered devices
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

  // Get environment
  const envRow = await env.DB.prepare(
    'SELECT * FROM environments WHERE project_id = ? AND name = ?'
  ).bind(project_id, environment).first();
  if (!envRow) return Response.json({ error: 'Environment not found' }, { status: 404, headers: corsHeaders });

  // Get latest version
  const latest = await env.DB.prepare(
    'SELECT * FROM secret_versions WHERE environment_id = ? ORDER BY version DESC LIMIT 1'
  ).bind(envRow.id).first();

  if (!latest) return Response.json({ error: 'No secrets stored yet' }, { status: 404, headers: corsHeaders });

  // Audit log
  await env.DB.prepare(
    'INSERT INTO audit_log (project_id, environment_id, action, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(project_id, envRow.id, 'pull', request.headers.get('CF-Connecting-IP'), request.headers.get('User-Agent'), new Date().toISOString()).run();

  return Response.json({
    secrets: latest.encrypted_blob,
    version: latest.version,
  }, { headers: corsHeaders });
}

async function handlePush(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, environment, secrets, key_names, device_hash } = JSON.parse(body);

  // Get project
  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  // Verify signature
  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  // Validate device if project has registered devices
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

  // Enforce secret count limit
  if (key_names) {
    const ownerRow = await env.DB.prepare(
      'SELECT user_id FROM user_projects WHERE project_id = ? AND role = ?'
    ).bind(project_id, 'owner').first();
    if (ownerRow) {
      const userRow = await env.DB.prepare('SELECT plan FROM users WHERE id = ?').bind(ownerRow.user_id).first();
      const plan = userRow?.plan || 'free';
      const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.free;
      if (limits.secrets !== -1 && key_names.length > limits.secrets) {
        return Response.json(
          { error: `Secret limit exceeded: ${key_names.length} secrets, plan allows ${limits.secrets}. Upgrade at app.vaultdotenv.io` },
          { status: 403, headers: corsHeaders }
        );
      }
    }
  }

  // Get or create environment
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

  // Get next version number
  const latest = await env.DB.prepare(
    'SELECT MAX(version) as max_version FROM secret_versions WHERE environment_id = ?'
  ).bind(envRow.id).first();
  const nextVersion = (latest?.max_version || 0) + 1;

  // Store encrypted blob + key names + count
  const changedKeys = key_names ? JSON.stringify(key_names) : null;
  const keyCount = key_names ? key_names.length : 0;
  await env.DB.prepare(
    'INSERT INTO secret_versions (environment_id, version, encrypted_blob, changed_keys, key_count, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(envRow.id, nextVersion, secrets, changedKeys, keyCount, new Date().toISOString()).run();

  // Audit log
  await env.DB.prepare(
    'INSERT INTO audit_log (project_id, environment_id, action, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(project_id, envRow.id, 'push', request.headers.get('CF-Connecting-IP'), request.headers.get('User-Agent'), new Date().toISOString()).run();

  return Response.json({ version: nextVersion }, { headers: corsHeaders });
}

async function handleVersions(request, env, corsHeaders) {
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

async function handleRollback(request, env, corsHeaders) {
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

  // Get the target version
  const target = await env.DB.prepare(
    'SELECT * FROM secret_versions WHERE environment_id = ? AND version = ?'
  ).bind(envRow.id, version).first();
  if (!target) return Response.json({ error: 'Version not found' }, { status: 404, headers: corsHeaders });

  // Create new version with old content
  const latest = await env.DB.prepare(
    'SELECT MAX(version) as max_version FROM secret_versions WHERE environment_id = ?'
  ).bind(envRow.id).first();
  const nextVersion = (latest?.max_version || 0) + 1;

  await env.DB.prepare(
    'INSERT INTO secret_versions (environment_id, version, encrypted_blob, changed_keys, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(envRow.id, nextVersion, target.encrypted_blob, `["rollback_from_v${version}"]`, new Date().toISOString()).run();

  // Audit
  await env.DB.prepare(
    'INSERT INTO audit_log (project_id, environment_id, action, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(project_id, envRow.id, 'rollback', request.headers.get('CF-Connecting-IP'), request.headers.get('User-Agent'), new Date().toISOString()).run();

  return Response.json({ version: nextVersion }, { headers: corsHeaders });
}

// ── Password Hashing (PBKDF2 via Web Crypto) ──────────────────────────────

const PBKDF2_ITERATIONS = 100_000;

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial, 256
  );
  const hash = new Uint8Array(bits);
  const saltHex = bufferToHex(salt);
  const hashHex = bufferToHex(hash);
  return `pbkdf2:${PBKDF2_ITERATIONS}:${saltHex}:${hashHex}`;
}

async function verifyPassword(password, stored) {
  const [, iterStr, saltHex, hashHex] = stored.split(':');
  const iterations = parseInt(iterStr, 10);
  const salt = hexToUint8(saltHex);
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return bufferToHex(new Uint8Array(bits)) === hashHex;
}

function bufferToHex(buf) {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToUint8(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

// ── Session Helpers ────────────────────────────────────────────────────────

const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

async function createSession(env, userId) {
  const id = crypto.randomUUID();
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_MAX_AGE_MS);
  await env.DB.prepare(
    'INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)'
  ).bind(id, userId, expires.toISOString(), now.toISOString()).run();
  return id;
}

async function validateSession(env, request) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;

  const session = await env.DB.prepare(
    'SELECT s.*, u.id as uid, u.email, u.plan FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = ?'
  ).bind(token).first();

  if (!session) return null;
  if (new Date(session.expires_at) < new Date()) {
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(token).run();
    return null;
  }

  return { id: session.uid, email: session.email, plan: session.plan || 'free' };
}

async function requireSession(env, request, corsHeaders) {
  const user = await validateSession(env, request);
  if (!user) {
    return { user: null, error: Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders }) };
  }
  return { user, error: null };
}

async function requireProjectAccess(env, userId, projectId, corsHeaders) {
  const row = await env.DB.prepare(
    'SELECT * FROM user_projects WHERE user_id = ? AND project_id = ?'
  ).bind(userId, projectId).first();
  if (!row) {
    return { ok: false, error: Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders }) };
  }
  return { ok: true, role: row.role, error: null };
}

// ── Dashboard Router ───────────────────────────────────────────────────────

async function handleDashboard(request, env, corsHeaders, path) {
  const method = request.method;

  // ── Auth (no session required) ──────────────────────────────────────────

  if (path === '/api/v1/dashboard/signup' && method === 'POST') {
    return dashboardSignup(request, env, corsHeaders);
  }
  if (path === '/api/v1/dashboard/login' && method === 'POST') {
    return dashboardLogin(request, env, corsHeaders);
  }

  // ── Everything below requires a valid session ──────────────────────────

  const { user, error } = await requireSession(env, request, corsHeaders);
  if (error) return error;

  if (path === '/api/v1/dashboard/me' && method === 'GET') {
    return Response.json(user, { headers: corsHeaders });
  }

  if (path === '/api/v1/dashboard/plan' && method === 'GET') {
    return dashboardGetPlan(env, user, corsHeaders);
  }

  if (path === '/api/v1/dashboard/plan/upgrade' && method === 'POST') {
    return dashboardUpgradePlan(request, env, user, corsHeaders);
  }

  // Accept invite (by token — user must be logged in)
  if (path === '/api/v1/dashboard/invites/accept' && method === 'POST') {
    return dashboardAcceptInvite(request, env, user, corsHeaders);
  }

  // List invites received by current user
  if (path === '/api/v1/dashboard/invites' && method === 'GET') {
    return dashboardListMyInvites(env, user, corsHeaders);
  }

  if (path === '/api/v1/dashboard/logout' && method === 'POST') {
    const token = (request.headers.get('Authorization') || '').slice(7);
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(token).run();
    return Response.json({ ok: true }, { headers: corsHeaders });
  }

  if (path === '/api/v1/dashboard/projects' && method === 'GET') {
    return dashboardListProjects(env, user, corsHeaders);
  }

  if (path === '/api/v1/dashboard/projects/create' && method === 'POST') {
    return dashboardCreateProject(request, env, user, corsHeaders);
  }

  // ── Project-scoped routes ──────────────────────────────────────────────

  const projectMatch = path.match(/^\/api\/v1\/dashboard\/projects\/([^/]+)(.*)$/);
  if (projectMatch) {
    const projectId = projectMatch[1];
    const sub = projectMatch[2];

    // Skip access check for "create" (already handled above)
    if (projectId === 'create') {
      return Response.json({ error: 'Not found' }, { status: 404, headers: corsHeaders });
    }

    const access = await requireProjectAccess(env, user.id, projectId, corsHeaders);
    if (!access.ok) return access.error;

    if (sub === '' && method === 'GET') {
      return dashboardGetProject(env, projectId, corsHeaders);
    }
    if (sub === '/environments' && method === 'GET') {
      return dashboardListEnvironments(env, projectId, corsHeaders);
    }
    if (sub === '/devices' && method === 'GET') {
      return dashboardListDevices(env, projectId, corsHeaders);
    }
    if (sub === '/audit' && method === 'GET') {
      return dashboardListAudit(request, env, projectId, corsHeaders);
    }

    // Invites
    if (sub === '/invites' && method === 'GET') {
      return dashboardListInvites(env, projectId, corsHeaders);
    }
    if (sub === '/invites' && method === 'POST') {
      return dashboardCreateInvite(request, env, user, projectId, access.role, corsHeaders);
    }

    // /projects/:id/invites/:inviteId/revoke
    const revokeInviteMatch = sub.match(/^\/invites\/([^/]+)\/revoke$/);
    if (revokeInviteMatch && method === 'POST') {
      return dashboardRevokeInvite(env, projectId, revokeInviteMatch[1], corsHeaders);
    }

    // Members
    if (sub === '/members' && method === 'GET') {
      return dashboardListMembers(env, projectId, corsHeaders);
    }

    // /projects/:id/members/:userId/remove
    const removeMemberMatch = sub.match(/^\/members\/([^/]+)\/remove$/);
    if (removeMemberMatch && method === 'POST') {
      return dashboardRemoveMember(env, projectId, removeMemberMatch[1], user.id, corsHeaders);
    }

    // /projects/:id/environments/:env/versions
    const versionsMatch = sub.match(/^\/environments\/([^/]+)\/versions$/);
    if (versionsMatch && method === 'GET') {
      return dashboardListVersions(env, projectId, versionsMatch[1], corsHeaders);
    }

    // /projects/:id/devices/:deviceId/approve
    const approveMatch = sub.match(/^\/devices\/([^/]+)\/approve$/);
    if (approveMatch && method === 'POST') {
      return dashboardApproveDevice(env, projectId, approveMatch[1], corsHeaders);
    }

    // /projects/:id/devices/:deviceId/revoke
    const revokeMatch = sub.match(/^\/devices\/([^/]+)\/revoke$/);
    if (revokeMatch && method === 'POST') {
      return dashboardRevokeDevice(env, projectId, revokeMatch[1], corsHeaders);
    }

    // /projects/:id/reveal-token
    if (sub === '/reveal-token' && method === 'POST') {
      return dashboardCreateRevealToken(env, user, projectId, corsHeaders);
    }
  }

  return Response.json({ error: 'Not found' }, { status: 404, headers: corsHeaders });
}

// ── Dashboard Auth Handlers ────────────────────────────────────────────────

async function dashboardSignup(request, env, corsHeaders) {
  const { email, password } = await request.json();

  if (!email || !password) {
    return Response.json({ error: 'Email and password required' }, { status: 400, headers: corsHeaders });
  }
  if (password.length < 8) {
    return Response.json({ error: 'Password must be at least 8 characters' }, { status: 400, headers: corsHeaders });
  }

  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first();
  if (existing) {
    return Response.json({ error: 'Email already registered' }, { status: 409, headers: corsHeaders });
  }

  const id = crypto.randomUUID();
  const passwordHash = await hashPassword(password);
  const now = new Date().toISOString();

  await env.DB.prepare(
    'INSERT INTO users (id, email, password_hash, plan, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(id, email.toLowerCase(), passwordHash, 'free', now).run();

  const token = await createSession(env, id);

  return Response.json({
    token,
    user: { id, email: email.toLowerCase(), plan: 'free', created_at: now },
  }, { headers: corsHeaders });
}

async function dashboardLogin(request, env, corsHeaders) {
  const { email, password } = await request.json();

  if (!email || !password) {
    return Response.json({ error: 'Email and password required' }, { status: 400, headers: corsHeaders });
  }

  const user = await env.DB.prepare(
    'SELECT * FROM users WHERE email = ?'
  ).bind(email.toLowerCase()).first();

  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return Response.json({ error: 'Invalid email or password' }, { status: 401, headers: corsHeaders });
  }

  const token = await createSession(env, user.id);

  return Response.json({
    token,
    user: { id: user.id, email: user.email, plan: user.plan || 'free', created_at: user.created_at },
  }, { headers: corsHeaders });
}

// ── Dashboard Project Handlers ─────────────────────────────────────────────

async function dashboardListProjects(env, user, corsHeaders) {
  const rows = await env.DB.prepare(`
    SELECT p.id, p.name, p.created_at
    FROM projects p
    JOIN user_projects up ON p.id = up.project_id
    WHERE up.user_id = ?
    ORDER BY p.created_at DESC
  `).bind(user.id).all();

  const projects = [];
  for (const proj of rows.results) {
    const envs = await env.DB.prepare(
      'SELECT id, name, created_at FROM environments WHERE project_id = ? ORDER BY name'
    ).bind(proj.id).all();

    const environments = [];
    for (const e of envs.results) {
      const latest = await env.DB.prepare(
        'SELECT version, created_at FROM secret_versions WHERE environment_id = ? ORDER BY version DESC LIMIT 1'
      ).bind(e.id).first();
      environments.push({
        ...e,
        latest_version: latest?.version || null,
        updated_at: latest?.created_at || null,
      });
    }

    projects.push({ ...proj, environments });
  }

  return Response.json({ projects }, { headers: corsHeaders });
}

async function dashboardCreateProject(request, env, user, corsHeaders) {
  const { project_name } = await request.json();
  if (!project_name) {
    return Response.json({ error: 'project_name required' }, { status: 400, headers: corsHeaders });
  }

  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  await env.DB.prepare(
    'INSERT INTO projects (id, name, key_hash, created_at) VALUES (?, ?, ?, ?)'
  ).bind(id, project_name, '', now).run();

  for (const envName of ['development', 'staging', 'production']) {
    await env.DB.prepare(
      'INSERT INTO environments (id, project_id, name, created_at) VALUES (?, ?, ?, ?)'
    ).bind(crypto.randomUUID(), id, envName, now).run();
  }

  await env.DB.prepare(
    'INSERT INTO user_projects (user_id, project_id, role, created_at) VALUES (?, ?, ?, ?)'
  ).bind(user.id, id, 'owner', now).run();

  return Response.json({ project_id: id }, { headers: corsHeaders });
}

async function dashboardGetProject(env, projectId, corsHeaders) {
  const project = await env.DB.prepare('SELECT id, name, created_at FROM projects WHERE id = ?').bind(projectId).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  const envs = await env.DB.prepare(
    'SELECT id, name, created_at FROM environments WHERE project_id = ? ORDER BY name'
  ).bind(projectId).all();

  const environments = [];
  for (const e of envs.results) {
    const latest = await env.DB.prepare(
      'SELECT version, created_at FROM secret_versions WHERE environment_id = ? ORDER BY version DESC LIMIT 1'
    ).bind(e.id).first();
    environments.push({
      ...e,
      latest_version: latest?.version || null,
      updated_at: latest?.created_at || null,
    });
  }

  return Response.json({ ...project, environments }, { headers: corsHeaders });
}

async function dashboardListEnvironments(env, projectId, corsHeaders) {
  const envs = await env.DB.prepare(
    'SELECT id, name, created_at FROM environments WHERE project_id = ? ORDER BY name'
  ).bind(projectId).all();
  return Response.json({ environments: envs.results }, { headers: corsHeaders });
}

// ── Dashboard Device Handlers ──────────────────────────────────────────────

async function dashboardListDevices(env, projectId, corsHeaders) {
  const devices = await env.DB.prepare(
    'SELECT id, device_name, status, created_at, approved_at, last_seen_at FROM devices WHERE project_id = ? ORDER BY created_at DESC'
  ).bind(projectId).all();
  return Response.json({ devices: devices.results }, { headers: corsHeaders });
}

async function dashboardApproveDevice(env, projectId, deviceId, corsHeaders) {
  const device = await env.DB.prepare(
    'SELECT * FROM devices WHERE id = ? AND project_id = ?'
  ).bind(deviceId, projectId).first();
  if (!device) return Response.json({ error: 'Device not found' }, { status: 404, headers: corsHeaders });

  await env.DB.prepare(
    'UPDATE devices SET status = ?, approved_at = ? WHERE id = ?'
  ).bind('approved', new Date().toISOString(), deviceId).run();

  return Response.json({ device_id: deviceId, status: 'approved' }, { headers: corsHeaders });
}

async function dashboardRevokeDevice(env, projectId, deviceId, corsHeaders) {
  const device = await env.DB.prepare(
    'SELECT * FROM devices WHERE id = ? AND project_id = ?'
  ).bind(deviceId, projectId).first();
  if (!device) return Response.json({ error: 'Device not found' }, { status: 404, headers: corsHeaders });

  await env.DB.prepare('UPDATE devices SET status = ? WHERE id = ?').bind('revoked', deviceId).run();

  return Response.json({ device_id: deviceId, status: 'revoked' }, { headers: corsHeaders });
}

// ── Dashboard Version + Audit Handlers ─────────────────────────────────────

async function dashboardListVersions(env, projectId, environment, corsHeaders) {
  const envRow = await env.DB.prepare(
    'SELECT * FROM environments WHERE project_id = ? AND name = ?'
  ).bind(projectId, environment).first();
  if (!envRow) return Response.json({ error: 'Environment not found' }, { status: 404, headers: corsHeaders });

  const versions = await env.DB.prepare(
    'SELECT version, changed_keys, created_at FROM secret_versions WHERE environment_id = ? ORDER BY version DESC LIMIT 50'
  ).bind(envRow.id).all();

  return Response.json({ versions: versions.results }, { headers: corsHeaders });
}

async function dashboardListAudit(request, env, projectId, corsHeaders) {
  const url = new URL(request.url);
  const page = parseInt(url.searchParams.get('page') || '1', 10);
  const limit = 50;
  const offset = (page - 1) * limit;

  const countRow = await env.DB.prepare(
    'SELECT COUNT(*) as total FROM audit_log WHERE project_id = ?'
  ).bind(projectId).first();

  const entries = await env.DB.prepare(`
    SELECT a.id, a.action, a.ip, a.user_agent, a.created_at,
           e.name as environment_name
    FROM audit_log a
    LEFT JOIN environments e ON a.environment_id = e.id
    WHERE a.project_id = ?
    ORDER BY a.created_at DESC
    LIMIT ? OFFSET ?
  `).bind(projectId, limit, offset).all();

  return Response.json({
    entries: entries.results,
    total: countRow?.total || 0,
  }, { headers: corsHeaders });
}

// ── Plan Limits ────────────────────────────────────────────────────────────

const PLAN_LIMITS = {
  free:  { secrets: 10, environments: 2, projects: 1,  devices: 2  },
  pro:   { secrets: 30, environments: 3, projects: 3,  devices: 5  },
  team:  { secrets: -1, environments: -1, projects: 10, devices: -1 }, // -1 = unlimited
};

async function getUserPlanUsage(env, userId) {
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

  // Max secrets in any single environment (limit is per-env)
  const maxSecrets = await env.DB.prepare(`
    SELECT MAX(sv.key_count) as max_keys
    FROM secret_versions sv
    JOIN environments e ON sv.environment_id = e.id
    JOIN user_projects up ON e.project_id = up.project_id
    WHERE up.user_id = ?
      AND sv.version = (SELECT MAX(version) FROM secret_versions WHERE environment_id = sv.environment_id)
  `).bind(userId).first();

  return {
    plan, limits,
    projectCount: projectCount?.cnt || 0,
    environmentCount: envCount?.cnt || 0,
    deviceCount: deviceCount?.cnt || 0,
    secretCount: maxSecrets?.max_keys || 0,
  };
}

// ── Plan Handlers ──────────────────────────────────────────────────────────

async function dashboardGetPlan(env, user, corsHeaders) {
  const usage = await getUserPlanUsage(env, user.id);

  return Response.json({
    plan: usage.plan,
    limits: usage.limits,
    usage: {
      projects: usage.projectCount,
      environments: usage.environmentCount,
      devices: usage.deviceCount,
      secrets: usage.secretCount,
    },
  }, { headers: corsHeaders });
}

async function dashboardUpgradePlan(request, env, user, corsHeaders) {
  // Disabled until Stripe is integrated
  return Response.json({ error: 'Plan changes are not yet available. Contact support.' }, { status: 403, headers: corsHeaders });
}

// ── Invite Handlers ────────────────────────────────────────────────────────

const INVITE_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

async function dashboardCreateInvite(request, env, user, projectId, userRole, corsHeaders) {
  // Only owners can invite
  if (userRole !== 'owner') {
    return Response.json({ error: 'Only project owners can invite members' }, { status: 403, headers: corsHeaders });
  }

  const { email, role } = await request.json();

  if (!email) {
    return Response.json({ error: 'Email required' }, { status: 400, headers: corsHeaders });
  }

  const inviteRole = role === 'owner' ? 'owner' : 'member';

  // Check if already a member
  const existingUser = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first();
  if (existingUser) {
    const existingMember = await env.DB.prepare(
      'SELECT * FROM user_projects WHERE user_id = ? AND project_id = ?'
    ).bind(existingUser.id, projectId).first();
    if (existingMember) {
      return Response.json({ error: 'User is already a member of this project' }, { status: 409, headers: corsHeaders });
    }
  }

  // Check for existing pending invite
  const existingInvite = await env.DB.prepare(
    'SELECT * FROM invites WHERE project_id = ? AND email = ? AND status = ?'
  ).bind(projectId, email.toLowerCase(), 'pending').first();
  if (existingInvite) {
    return Response.json({ error: 'Invite already sent to this email' }, { status: 409, headers: corsHeaders });
  }

  const id = crypto.randomUUID();
  const token = crypto.randomUUID();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + INVITE_EXPIRY_MS);

  await env.DB.prepare(
    'INSERT INTO invites (id, project_id, email, role, invited_by, status, token, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, projectId, email.toLowerCase(), inviteRole, user.id, 'pending', token, now.toISOString(), expiresAt.toISOString()).run();

  // TODO: Send invite email via Resend
  // For now, return the token so it can be shared manually
  return Response.json({
    invite_id: id,
    token,
    email: email.toLowerCase(),
    role: inviteRole,
    expires_at: expiresAt.toISOString(),
  }, { headers: corsHeaders });
}

async function dashboardListInvites(env, projectId, corsHeaders) {
  const invites = await env.DB.prepare(`
    SELECT i.id, i.email, i.role, i.status, i.created_at, i.expires_at,
           u.email as invited_by_email
    FROM invites i
    JOIN users u ON i.invited_by = u.id
    WHERE i.project_id = ?
    ORDER BY i.created_at DESC
  `).bind(projectId).all();

  return Response.json({ invites: invites.results }, { headers: corsHeaders });
}

async function dashboardRevokeInvite(env, projectId, inviteId, corsHeaders) {
  const invite = await env.DB.prepare(
    'SELECT * FROM invites WHERE id = ? AND project_id = ?'
  ).bind(inviteId, projectId).first();
  if (!invite) return Response.json({ error: 'Invite not found' }, { status: 404, headers: corsHeaders });

  await env.DB.prepare('UPDATE invites SET status = ? WHERE id = ?').bind('revoked', inviteId).run();

  return Response.json({ ok: true }, { headers: corsHeaders });
}

async function dashboardAcceptInvite(request, env, user, corsHeaders) {
  const { token } = await request.json();

  if (!token) {
    return Response.json({ error: 'Invite token required' }, { status: 400, headers: corsHeaders });
  }

  const invite = await env.DB.prepare(
    'SELECT * FROM invites WHERE token = ? AND status = ?'
  ).bind(token, 'pending').first();

  if (!invite) {
    return Response.json({ error: 'Invalid or expired invite' }, { status: 404, headers: corsHeaders });
  }

  // Check expiry
  if (new Date(invite.expires_at) < new Date()) {
    await env.DB.prepare('UPDATE invites SET status = ? WHERE id = ?').bind('expired', invite.id).run();
    return Response.json({ error: 'Invite has expired' }, { status: 410, headers: corsHeaders });
  }

  // Check email matches
  if (invite.email !== user.email) {
    return Response.json({ error: 'This invite was sent to a different email address' }, { status: 403, headers: corsHeaders });
  }

  // Check not already a member
  const existing = await env.DB.prepare(
    'SELECT * FROM user_projects WHERE user_id = ? AND project_id = ?'
  ).bind(user.id, invite.project_id).first();
  if (existing) {
    return Response.json({ error: 'Already a member of this project' }, { status: 409, headers: corsHeaders });
  }

  const now = new Date().toISOString();

  // Add to project
  await env.DB.prepare(
    'INSERT INTO user_projects (user_id, project_id, role, created_at) VALUES (?, ?, ?, ?)'
  ).bind(user.id, invite.project_id, invite.role, now).run();

  // Mark invite as accepted
  await env.DB.prepare(
    'UPDATE invites SET status = ?, accepted_at = ? WHERE id = ?'
  ).bind('accepted', now, invite.id).run();

  return Response.json({
    project_id: invite.project_id,
    role: invite.role,
  }, { headers: corsHeaders });
}

async function dashboardListMyInvites(env, user, corsHeaders) {
  const invites = await env.DB.prepare(`
    SELECT i.id, i.token, i.role, i.status, i.created_at, i.expires_at,
           p.name as project_name,
           u.email as invited_by_email
    FROM invites i
    JOIN projects p ON i.project_id = p.id
    JOIN users u ON i.invited_by = u.id
    WHERE i.email = ? AND i.status = 'pending'
    ORDER BY i.created_at DESC
  `).bind(user.email).all();

  return Response.json({ invites: invites.results }, { headers: corsHeaders });
}

// ── Member Handlers ────────────────────────────────────────────────────────

async function dashboardListMembers(env, projectId, corsHeaders) {
  const members = await env.DB.prepare(`
    SELECT u.id, u.email, up.role, up.created_at
    FROM user_projects up
    JOIN users u ON up.user_id = u.id
    WHERE up.project_id = ?
    ORDER BY up.created_at ASC
  `).bind(projectId).all();

  return Response.json({ members: members.results }, { headers: corsHeaders });
}

async function dashboardRemoveMember(env, projectId, targetUserId, currentUserId, corsHeaders) {
  // Can't remove yourself
  if (targetUserId === currentUserId) {
    return Response.json({ error: 'Cannot remove yourself' }, { status: 400, headers: corsHeaders });
  }

  // Check current user is owner
  const currentRole = await env.DB.prepare(
    'SELECT role FROM user_projects WHERE user_id = ? AND project_id = ?'
  ).bind(currentUserId, projectId).first();
  if (!currentRole || currentRole.role !== 'owner') {
    return Response.json({ error: 'Only owners can remove members' }, { status: 403, headers: corsHeaders });
  }

  const target = await env.DB.prepare(
    'SELECT * FROM user_projects WHERE user_id = ? AND project_id = ?'
  ).bind(targetUserId, projectId).first();
  if (!target) {
    return Response.json({ error: 'Member not found' }, { status: 404, headers: corsHeaders });
  }

  await env.DB.prepare(
    'DELETE FROM user_projects WHERE user_id = ? AND project_id = ?'
  ).bind(targetUserId, projectId).run();

  return Response.json({ ok: true }, { headers: corsHeaders });
}

// ── Reveal Token Handlers ─────────────────────────────────────────────────

const REVEAL_TOKEN_TTL_MS = 60_000; // 60 seconds

async function dashboardCreateRevealToken(env, user, projectId, corsHeaders) {
  const id = 'rt_' + crypto.randomUUID().replace(/-/g, '').slice(0, 24);
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + REVEAL_TOKEN_TTL_MS).toISOString();

  await env.DB.prepare(
    'INSERT INTO reveal_tokens (id, project_id, user_id, expires_at, used_at, created_at) VALUES (?, ?, ?, ?, NULL, ?)'
  ).bind(id, projectId, user.id, expiresAt, now).run();

  // Audit log
  await env.DB.prepare(
    'INSERT INTO audit_log (project_id, action, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(projectId, 'reveal_token_created', '', '', now).run();

  return Response.json({ token: id, expires_at: expiresAt }, { headers: corsHeaders });
}

async function handleRevealTokenValidate(request, env, corsHeaders) {
  const body = await request.text();
  const { project_id, token } = JSON.parse(body);

  if (!project_id || !token) {
    return Response.json({ error: 'project_id and token required' }, { status: 400, headers: corsHeaders });
  }

  // Verify VAULT_KEY signature
  const sigHeader = request.headers.get('X-Vault-Signature');
  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) {
    return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });
  }

  const sigResult = await verifySignature(body, sigHeader, project.key_hash);
  if (!sigResult.valid) {
    return Response.json({ error: 'Invalid signature' }, { status: 403, headers: corsHeaders });
  }

  // Validate token
  const row = await env.DB.prepare(
    'SELECT * FROM reveal_tokens WHERE id = ? AND project_id = ?'
  ).bind(token, project_id).first();

  if (!row) {
    return Response.json({ valid: false, reason: 'not_found' }, { headers: corsHeaders });
  }

  if (row.used_at) {
    return Response.json({ valid: false, reason: 'already_used' }, { headers: corsHeaders });
  }

  if (new Date(row.expires_at) < new Date()) {
    return Response.json({ valid: false, reason: 'expired' }, { headers: corsHeaders });
  }

  // Mark as used (single-use)
  await env.DB.prepare(
    'UPDATE reveal_tokens SET used_at = ? WHERE id = ?'
  ).bind(new Date().toISOString(), token).run();

  return Response.json({ valid: true }, { headers: corsHeaders });
}

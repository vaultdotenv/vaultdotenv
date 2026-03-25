/**
 * Dashboard auth endpoints: signup, login.
 * CLI auth endpoints: start, poll, approve.
 */

import { hashPassword, verifyPassword } from '../lib/crypto.js';
import { createSession } from '../lib/middleware.js';
import { sendEmail, welcomeEmailHtml } from '../lib/email.js';
import { DASHBOARD_URL, CLI_AUTH_EXPIRY_MS } from '../lib/config.js';

// ── Dashboard Auth ─────────────────────────────────────────────────────────

export async function dashboardSignup(request, env, corsHeaders) {
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

  // Create personal org
  const orgId = crypto.randomUUID();
  const slug = email.toLowerCase().split('@')[0] + '-personal';
  await env.DB.prepare(
    'INSERT INTO orgs (id, name, slug, personal, plan, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(orgId, 'Personal', slug, 1, 'free', id, now).run();

  await env.DB.prepare(
    'INSERT INTO org_members (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)'
  ).bind(orgId, id, 'owner', now).run();

  const token = await createSession(env, id);

  // Send welcome email (non-blocking)
  sendEmail(env, {
    to: email.toLowerCase(),
    subject: 'Welcome to vaultdotenv',
    html: welcomeEmailHtml(email.toLowerCase()),
  }).catch(() => {});

  return Response.json({
    token,
    user: { id, email: email.toLowerCase(), plan: 'free', created_at: now },
  }, { headers: corsHeaders });
}

export async function dashboardLogin(request, env, corsHeaders) {
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
    user: { id: user.id, email: user.email, plan: user.plan || 'free', is_superadmin: !!user.is_superadmin, created_at: user.created_at },
  }, { headers: corsHeaders });
}

// ── CLI Auth ───────────────────────────────────────────────────────────────

export async function handleCliAuthStart(env, corsHeaders) {
  const code = crypto.randomUUID().split('-')[0]; // Short 8-char code
  const now = new Date();
  const expiresAt = new Date(now.getTime() + CLI_AUTH_EXPIRY_MS);

  await env.DB.prepare(
    'INSERT INTO cli_auth_codes (code, status, created_at, expires_at) VALUES (?, ?, ?, ?)'
  ).bind(code, 'pending', now.toISOString(), expiresAt.toISOString()).run();

  return Response.json({
    code,
    auth_url: `${DASHBOARD_URL}/cli-auth?code=${code}`,
    expires_at: expiresAt.toISOString(),
  }, { headers: corsHeaders });
}

export async function handleCliAuthPoll(env, code, corsHeaders) {
  if (!code) {
    return Response.json({ error: 'Code required' }, { status: 400, headers: corsHeaders });
  }

  const row = await env.DB.prepare(
    'SELECT * FROM cli_auth_codes WHERE code = ?'
  ).bind(code).first();

  if (!row) {
    return Response.json({ error: 'Invalid code' }, { status: 404, headers: corsHeaders });
  }

  if (new Date(row.expires_at) < new Date()) {
    return Response.json({ status: 'expired' }, { headers: corsHeaders });
  }

  if (row.status === 'approved' && row.session_token) {
    // Clean up the code
    await env.DB.prepare('DELETE FROM cli_auth_codes WHERE code = ?').bind(code).run();

    // Get user info
    const user = await env.DB.prepare('SELECT id, email, plan FROM users WHERE id = ?').bind(row.user_id).first();

    return Response.json({
      status: 'approved',
      token: row.session_token,
      user: user ? { id: user.id, email: user.email, plan: user.plan } : null,
    }, { headers: corsHeaders });
  }

  return Response.json({ status: 'pending' }, { headers: corsHeaders });
}

export async function handleCliAuthApprove(request, env, user, corsHeaders) {
  const { code } = await request.json();

  if (!code) {
    return Response.json({ error: 'Code required' }, { status: 400, headers: corsHeaders });
  }

  const row = await env.DB.prepare(
    'SELECT * FROM cli_auth_codes WHERE code = ? AND status = ?'
  ).bind(code, 'pending').first();

  if (!row) {
    return Response.json({ error: 'Invalid or expired code' }, { status: 404, headers: corsHeaders });
  }

  if (new Date(row.expires_at) < new Date()) {
    return Response.json({ error: 'Code expired' }, { status: 410, headers: corsHeaders });
  }

  // Create a long-lived session for the CLI (30 days)
  const sessionId = crypto.randomUUID();
  const now = new Date();
  const sessionExpires = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  await env.DB.prepare(
    'INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)'
  ).bind(sessionId, user.id, sessionExpires.toISOString(), now.toISOString()).run();

  // Mark the code as approved with the session token
  await env.DB.prepare(
    'UPDATE cli_auth_codes SET status = ?, session_token = ?, user_id = ? WHERE code = ?'
  ).bind('approved', sessionId, user.id, code).run();

  return Response.json({ ok: true }, { headers: corsHeaders });
}

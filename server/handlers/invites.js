/**
 * Dashboard invite endpoints: create, list, revoke, accept, list-my-invites.
 * All endpoints require session auth. Create/revoke require project admin permission.
 */

import { sendEmail, inviteEmailHtml } from '../lib/email.js';
import { DASHBOARD_URL, INVITE_EXPIRY_MS } from '../lib/config.js';

export async function dashboardCreateInvite(request, env, user, projectId, userRole, corsHeaders) {
  // Only owners can invite
  if (userRole !== 'owner') {
    return Response.json({ error: 'Only project owners can invite members' }, { status: 403, headers: corsHeaders });
  }

  const { email, role, permission, env_scope } = await request.json();

  if (!email) {
    return Response.json({ error: 'Email required' }, { status: 400, headers: corsHeaders });
  }

  const inviteRole = role === 'owner' ? 'owner' : 'member';
  const invitePermission = ['read', 'write', 'admin'].includes(permission) ? permission : 'write';
  const inviteEnvScope = env_scope && Array.isArray(env_scope) ? JSON.stringify(env_scope) : null;

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
    'INSERT INTO invites (id, project_id, email, role, invited_by, status, token, permission, env_scope, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, projectId, email.toLowerCase(), inviteRole, user.id, 'pending', token, invitePermission, inviteEnvScope, now.toISOString(), expiresAt.toISOString()).run();

  // Send invite email
  const project = await env.DB.prepare('SELECT name FROM projects WHERE id = ?').bind(projectId).first();
  const acceptUrl = `${DASHBOARD_URL}/invites/accept?token=${token}`;
  await sendEmail(env, {
    to: email.toLowerCase(),
    subject: `You've been invited to ${project?.name || 'a project'} on vaultdotenv`,
    html: inviteEmailHtml(user.email, project?.name || 'a project', inviteRole, acceptUrl),
  });

  return Response.json({
    invite_id: id,
    token,
    email: email.toLowerCase(),
    role: inviteRole,
    expires_at: expiresAt.toISOString(),
  }, { headers: corsHeaders });
}

export async function dashboardListInvites(env, projectId, corsHeaders) {
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

export async function dashboardRevokeInvite(env, projectId, inviteId, corsHeaders) {
  const invite = await env.DB.prepare(
    'SELECT * FROM invites WHERE id = ? AND project_id = ?'
  ).bind(inviteId, projectId).first();
  if (!invite) return Response.json({ error: 'Invite not found' }, { status: 404, headers: corsHeaders });

  await env.DB.prepare('UPDATE invites SET status = ? WHERE id = ?').bind('revoked', inviteId).run();

  return Response.json({ ok: true }, { headers: corsHeaders });
}

export async function dashboardAcceptInvite(request, env, user, corsHeaders) {
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

  // Add to project with permission + env_scope from invite
  await env.DB.prepare(
    'INSERT INTO user_projects (user_id, project_id, role, permission, env_scope, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(user.id, invite.project_id, invite.role, invite.permission || 'write', invite.env_scope || null, now).run();

  // Mark invite as accepted
  await env.DB.prepare(
    'UPDATE invites SET status = ?, accepted_at = ? WHERE id = ?'
  ).bind('accepted', now, invite.id).run();

  return Response.json({
    project_id: invite.project_id,
    role: invite.role,
  }, { headers: corsHeaders });
}

export async function dashboardListMyInvites(env, user, corsHeaders) {
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

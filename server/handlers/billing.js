/**
 * Dashboard billing endpoints: get-plan, upgrade-plan.
 * Reveal token endpoints: create, validate.
 */

import { verifySignature } from '../lib/crypto.js';
import { getUserPlanUsage } from '../lib/middleware.js';
import { REVEAL_TOKEN_TTL_MS } from '../lib/config.js';

// ── Plan Handlers ──────────────────────────────────────────────────────────

export async function dashboardGetPlan(env, user, corsHeaders) {
  const usage = await getUserPlanUsage(env, user.id);

  return Response.json({
    plan: usage.plan,
    limits: usage.limits,
    usage: {
      projects: usage.projectCount,
      environments: usage.environmentCount,
      devices: usage.deviceCount,
      secrets: usage.secretCount,
      secretsByEnv: usage.secretsByEnv,
    },
  }, { headers: corsHeaders });
}

export async function dashboardUpgradePlan(request, env, user, corsHeaders) {
  // Disabled until Stripe is integrated
  return Response.json({ error: 'Plan changes are not yet available. Contact support.' }, { status: 403, headers: corsHeaders });

  // When enabled, sync plan to both user and personal org:
  // const { plan } = await request.json();
  // if (!['free', 'pro', 'team'].includes(plan)) {
  //   return Response.json({ error: 'Invalid plan' }, { status: 400, headers: corsHeaders });
  // }
  // await env.DB.prepare('UPDATE users SET plan = ? WHERE id = ?').bind(plan, user.id).run();
  // const personalOrg = await getPersonalOrg(env, user.id);
  // if (personalOrg) {
  //   await env.DB.prepare('UPDATE orgs SET plan = ? WHERE id = ?').bind(plan, personalOrg.id).run();
  // }
  // return Response.json({ plan }, { headers: corsHeaders });
}

// ── Reveal Token Handlers ──────────────────────────────────────────────────

export async function dashboardCreateRevealToken(env, user, projectId, corsHeaders) {
  const id = 'rt_' + crypto.randomUUID().replace(/-/g, '').substring(0, 24);
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

export async function handleRevealTokenValidate(request, env, corsHeaders) {
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

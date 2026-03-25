/**
 * Vault Server — Cloudflare Worker
 *
 * Routes requests to handler modules. All business logic lives in handlers/.
 * Encrypted secrets stored in D1 — server never sees decryption keys.
 */

import { requireSession, requireProjectAccess, requireOrgAccess } from './lib/middleware.js';
import { handleCurrentVersion, handlePull, handlePush, handleVersions, handleRollback } from './handlers/secrets.js';
import { handleCreateProject, handleSetKey, dashboardListProjects, dashboardCreateProject, dashboardGetProject, dashboardListEnvironments, dashboardLinkProject, dashboardMoveProject } from './handlers/projects.js';
import { handleDeviceRegister, handleDeviceApprove, handleDeviceList, handleDeviceRevoke, dashboardListDevices, dashboardApproveDevice, dashboardRevokeDevice } from './handlers/devices.js';
import { dashboardSignup, dashboardLogin, handleCliAuthStart, handleCliAuthPoll, handleCliAuthApprove } from './handlers/auth.js';
import { dashboardCreateInvite, dashboardListInvites, dashboardRevokeInvite, dashboardAcceptInvite, dashboardListMyInvites } from './handlers/invites.js';
import { dashboardListMembers, dashboardUpdatePermissions, dashboardRemoveMember } from './handlers/members.js';
import { dashboardListOrgs, dashboardCreateOrg, dashboardGetOrg, dashboardListOrgMembers, dashboardInviteOrgMember, dashboardRemoveOrgMember, dashboardListOrgProjects, dashboardCreateOrgProject, dashboardGetOrgPlan, dashboardUpgradeOrgPlan } from './handlers/orgs.js';
import { dashboardGetPlan, dashboardUpgradePlan, dashboardCreateRevealToken, handleRevealTokenValidate } from './handlers/billing.js';
import { handleAdmin } from './handlers/admin.js';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Vault-Signature, Authorization',
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const corsHeaders = { 'Access-Control-Allow-Origin': '*' };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    try {
      // ── Health ──────────────────────────────────────────────────────────
      if (path === '/health') {
        return Response.json({ status: 'ok', ts: Date.now() }, { headers: corsHeaders });
      }

      // ── CLI API (HMAC auth) ────────────────────────────────────────────
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

      // ── CLI Auth (no session) ──────────────────────────────────────────
      if (path === '/api/v1/cli/auth/start' && request.method === 'POST') {
        return handleCliAuthStart(env, corsHeaders);
      }
      if (path === '/api/v1/cli/auth/poll' && request.method === 'GET') {
        const code = url.searchParams.get('code');
        return handleCliAuthPoll(env, code, corsHeaders);
      }

      // ── Dashboard API (session auth) ───────────────────────────────────
      if (path.startsWith('/api/v1/dashboard/')) {
        return handleDashboardRoutes(request, env, corsHeaders, path);
      }

      return Response.json({ error: 'Not found' }, { status: 404, headers: corsHeaders });
    } catch (err) {
      return Response.json({ error: err.message }, { status: 500, headers: corsHeaders });
    }
  },
};

// ── Dashboard Router ─────────────────────────────────────────────────────────

async function handleDashboardRoutes(request, env, corsHeaders, path) {
  const method = request.method;

  // ── Unauthenticated ────────────────────────────────────────────────────
  if (path === '/api/v1/dashboard/signup' && method === 'POST') {
    return Response.json({ error: 'Signups are temporarily closed. Coming soon.' }, { status: 403, headers: corsHeaders });
    // return dashboardSignup(request, env, corsHeaders);
  }
  if (path === '/api/v1/dashboard/login' && method === 'POST') {
    return dashboardLogin(request, env, corsHeaders);
  }

  // ── Authenticated ──────────────────────────────────────────────────────
  const { user, error } = await requireSession(env, request, corsHeaders);
  if (error) return error;

  if (path === '/api/v1/dashboard/me' && method === 'GET') {
    return Response.json(user, { headers: corsHeaders });
  }
  if (path === '/api/v1/dashboard/logout' && method === 'POST') {
    const token = (request.headers.get('Authorization') || '').slice(7);
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(token).run();
    return Response.json({ ok: true }, { headers: corsHeaders });
  }
  if (path === '/api/v1/dashboard/cli-auth/approve' && method === 'POST') {
    return handleCliAuthApprove(request, env, user, corsHeaders);
  }
  if (path === '/api/v1/dashboard/invites/accept' && method === 'POST') {
    return dashboardAcceptInvite(request, env, user, corsHeaders);
  }
  if (path === '/api/v1/dashboard/invites' && method === 'GET') {
    return dashboardListMyInvites(env, user, corsHeaders);
  }
  if (path === '/api/v1/dashboard/plan' && method === 'GET') {
    return dashboardGetPlan(env, user, corsHeaders);
  }
  if (path === '/api/v1/dashboard/plan/upgrade' && method === 'POST') {
    return dashboardUpgradePlan(request, env, user, corsHeaders);
  }

  // ── Admin ──────────────────────────────────────────────────────────────
  if (path.startsWith('/api/v1/dashboard/admin/')) {
    if (!user.is_superadmin) {
      return Response.json({ error: 'Forbidden' }, { status: 403, headers: corsHeaders });
    }
    return handleAdmin(request, env, user, corsHeaders, path, method);
  }

  // ── Orgs ───────────────────────────────────────────────────────────────
  if (path === '/api/v1/dashboard/orgs' && method === 'GET') {
    return dashboardListOrgs(env, user, corsHeaders);
  }
  if (path === '/api/v1/dashboard/orgs/create' && method === 'POST') {
    return dashboardCreateOrg(request, env, user, corsHeaders);
  }

  const orgMatch = path.match(/^\/api\/v1\/dashboard\/orgs\/([^/]+)(.*)$/);
  if (orgMatch && orgMatch[1] !== 'create') {
    const orgId = orgMatch[1];
    const sub = orgMatch[2];
    const orgAccess = await requireOrgAccess(env, user.id, orgId, corsHeaders);
    if (!orgAccess.ok) return orgAccess.error;

    if (sub === '' && method === 'GET') return dashboardGetOrg(env, orgId, corsHeaders);
    if (sub === '/members' && method === 'GET') return dashboardListOrgMembers(env, orgId, corsHeaders);
    if (sub === '/members' && method === 'POST') return dashboardInviteOrgMember(request, env, user, orgId, orgAccess.role, corsHeaders);
    if (sub === '/projects' && method === 'GET') return dashboardListOrgProjects(env, orgId, corsHeaders);
    if (sub === '/projects' && method === 'POST') return dashboardCreateOrgProject(request, env, user, orgId, corsHeaders);
    if (sub === '/plan' && method === 'GET') return dashboardGetOrgPlan(env, orgId, corsHeaders);
    if (sub === '/plan/upgrade' && method === 'POST') return dashboardUpgradeOrgPlan(request, env, orgId, orgAccess.role, corsHeaders);

    const removeMemberMatch = sub.match(/^\/members\/([^/]+)\/remove$/);
    if (removeMemberMatch && method === 'POST') {
      return dashboardRemoveOrgMember(env, orgId, removeMemberMatch[1], user.id, orgAccess.role, corsHeaders);
    }
  }

  // ── Projects ───────────────────────────────────────────────────────────
  if (path === '/api/v1/dashboard/projects' && method === 'GET') {
    return dashboardListProjects(env, user, corsHeaders);
  }
  if (path === '/api/v1/dashboard/projects/create' && method === 'POST') {
    return dashboardCreateProject(request, env, user, corsHeaders);
  }
  if (path === '/api/v1/dashboard/projects/link' && method === 'POST') {
    return dashboardLinkProject(request, env, user, corsHeaders);
  }

  const projectMatch = path.match(/^\/api\/v1\/dashboard\/projects\/([^/]+)(.*)$/);
  if (projectMatch && !['create', 'link'].includes(projectMatch[1])) {
    const projectId = projectMatch[1];
    const sub = projectMatch[2];
    const access = await requireProjectAccess(env, user.id, projectId, corsHeaders, 'read');
    if (!access.ok) return access.error;

    // Read-level routes
    if (sub === '' && method === 'GET') return dashboardGetProject(env, projectId, corsHeaders);
    if (sub === '/environments' && method === 'GET') return dashboardListEnvironments(env, projectId, corsHeaders);
    if (sub === '/devices' && method === 'GET') return dashboardListDevices(env, projectId, corsHeaders);
    if (sub === '/audit' && method === 'GET') return (await import('./handlers/billing.js')).default ? null : dashboardListAudit(request, env, projectId, corsHeaders);
    if (sub === '/members' && method === 'GET') return dashboardListMembers(env, projectId, corsHeaders);
    if (sub === '/invites' && method === 'GET') return dashboardListInvites(env, projectId, corsHeaders);

    const versionsMatch = sub.match(/^\/environments\/([^/]+)\/versions$/);
    if (versionsMatch && method === 'GET') {
      if (access.envScope && !access.envScope.includes(versionsMatch[1])) {
        return Response.json({ error: `No access to ${versionsMatch[1]} environment` }, { status: 403, headers: corsHeaders });
      }
      return dashboardListVersions(env, projectId, versionsMatch[1], corsHeaders);
    }

    // Admin-level routes
    const requireAdmin = (fn) => {
      if (access.permission !== 'admin') {
        return Response.json({ error: 'Requires admin permission' }, { status: 403, headers: corsHeaders });
      }
      return fn;
    };

    if (sub === '/invites' && method === 'POST') return requireAdmin(dashboardCreateInvite(request, env, user, projectId, access.role, corsHeaders));
    if (sub === '/reveal-token' && method === 'POST') return dashboardCreateRevealToken(env, user, projectId, corsHeaders);
    if (sub === '/move' && method === 'POST') return requireAdmin(dashboardMoveProject(request, env, user, projectId, corsHeaders));

    const revokeInviteMatch = sub.match(/^\/invites\/([^/]+)\/revoke$/);
    if (revokeInviteMatch && method === 'POST') return requireAdmin(dashboardRevokeInvite(env, projectId, revokeInviteMatch[1], corsHeaders));

    const removeMemberMatch = sub.match(/^\/members\/([^/]+)\/remove$/);
    if (removeMemberMatch && method === 'POST') return requireAdmin(dashboardRemoveMember(env, projectId, removeMemberMatch[1], user.id, corsHeaders));

    const permMatch = sub.match(/^\/members\/([^/]+)\/permissions$/);
    if (permMatch && method === 'POST') return requireAdmin(dashboardUpdatePermissions(request, env, projectId, permMatch[1], corsHeaders));

    const approveMatch = sub.match(/^\/devices\/([^/]+)\/approve$/);
    if (approveMatch && method === 'POST') return requireAdmin(dashboardApproveDevice(env, projectId, approveMatch[1], corsHeaders));

    const revokeMatch = sub.match(/^\/devices\/([^/]+)\/revoke$/);
    if (revokeMatch && method === 'POST') return requireAdmin(dashboardRevokeDevice(env, projectId, revokeMatch[1], corsHeaders));
  }

  return Response.json({ error: 'Not found' }, { status: 404, headers: corsHeaders });
}

// ── Audit handler (inline — too small for own file) ──────────────────────────

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

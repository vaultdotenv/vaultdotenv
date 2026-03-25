/**
 * Admin endpoints: stats, users, projects, orgs, update-user, delete-user.
 * All endpoints require superadmin access (checked by the router).
 */

export async function handleAdmin(request, env, currentUser, corsHeaders, path, method) {
  if (path === '/api/v1/dashboard/admin/stats' && method === 'GET') {
    return adminStats(env, corsHeaders);
  }
  if (path === '/api/v1/dashboard/admin/users' && method === 'GET') {
    return adminListUsers(env, corsHeaders);
  }
  if (path === '/api/v1/dashboard/admin/projects' && method === 'GET') {
    return adminListProjects(env, corsHeaders);
  }
  if (path === '/api/v1/dashboard/admin/orgs' && method === 'GET') {
    return adminListOrgs(env, corsHeaders);
  }

  // /admin/users/:id/update
  const userUpdateMatch = path.match(/^\/api\/v1\/dashboard\/admin\/users\/([^/]+)\/update$/);
  if (userUpdateMatch && method === 'POST') {
    return adminUpdateUser(request, env, currentUser, userUpdateMatch[1], corsHeaders);
  }

  // /admin/users/:id/delete
  const userDeleteMatch = path.match(/^\/api\/v1\/dashboard\/admin\/users\/([^/]+)\/delete$/);
  if (userDeleteMatch && method === 'POST') {
    return adminDeleteUser(env, userDeleteMatch[1], corsHeaders);
  }

  return Response.json({ error: 'Not found' }, { status: 404, headers: corsHeaders });
}

export async function adminStats(env, corsHeaders) {
  const users = await env.DB.prepare('SELECT COUNT(*) as cnt FROM users').first();
  const projects = await env.DB.prepare('SELECT COUNT(*) as cnt FROM projects').first();
  const orgs = await env.DB.prepare('SELECT COUNT(*) as cnt FROM orgs WHERE personal = 0').first();
  const devices = await env.DB.prepare("SELECT COUNT(*) as cnt FROM devices WHERE status = 'approved'").first();
  const secrets = await env.DB.prepare('SELECT COUNT(*) as cnt FROM secret_versions').first();
  const invites = await env.DB.prepare("SELECT COUNT(*) as cnt FROM invites WHERE status = 'pending'").first();

  return Response.json({
    users: users?.cnt || 0,
    projects: projects?.cnt || 0,
    orgs: orgs?.cnt || 0,
    devices: devices?.cnt || 0,
    secret_versions: secrets?.cnt || 0,
    pending_invites: invites?.cnt || 0,
  }, { headers: corsHeaders });
}

export async function adminListUsers(env, corsHeaders) {
  const users = await env.DB.prepare(`
    SELECT u.id, u.email, u.plan, u.is_superadmin, u.created_at,
           (SELECT COUNT(*) FROM user_projects WHERE user_id = u.id) as project_count,
           (SELECT COUNT(*) FROM org_members WHERE user_id = u.id AND org_id IN (SELECT id FROM orgs WHERE personal = 0)) as org_count
    FROM users u
    ORDER BY u.created_at DESC
  `).all();

  return Response.json({ users: users.results }, { headers: corsHeaders });
}

export async function adminListProjects(env, corsHeaders) {
  const projects = await env.DB.prepare(`
    SELECT p.id, p.name, p.org_id, p.created_at,
           o.name as org_name,
           (SELECT COUNT(*) FROM environments WHERE project_id = p.id) as env_count,
           (SELECT COUNT(*) FROM devices WHERE project_id = p.id) as device_count,
           (SELECT COUNT(*) FROM user_projects WHERE project_id = p.id) as member_count
    FROM projects p
    LEFT JOIN orgs o ON p.org_id = o.id
    ORDER BY p.created_at DESC
  `).all();

  return Response.json({ projects: projects.results }, { headers: corsHeaders });
}

export async function adminListOrgs(env, corsHeaders) {
  const orgs = await env.DB.prepare(`
    SELECT o.id, o.name, o.slug, o.personal, o.plan, o.created_at,
           u.email as created_by_email,
           (SELECT COUNT(*) FROM org_members WHERE org_id = o.id) as member_count,
           (SELECT COUNT(*) FROM projects WHERE org_id = o.id) as project_count
    FROM orgs o
    LEFT JOIN users u ON o.created_by = u.id
    ORDER BY o.created_at DESC
  `).all();

  return Response.json({ orgs: orgs.results }, { headers: corsHeaders });
}

export async function adminUpdateUser(request, env, currentUser, userId, corsHeaders) {
  const { plan, is_superadmin } = await request.json();

  const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
  if (!user) return Response.json({ error: 'User not found' }, { status: 404, headers: corsHeaders });

  if (plan && ['free', 'pro', 'team'].includes(plan)) {
    await env.DB.prepare('UPDATE users SET plan = ? WHERE id = ?').bind(plan, userId).run();
    // Sync personal org plan
    const personalOrg = await env.DB.prepare(
      'SELECT id FROM orgs WHERE created_by = ? AND personal = 1'
    ).bind(userId).first();
    if (personalOrg) {
      await env.DB.prepare('UPDATE orgs SET plan = ? WHERE id = ?').bind(plan, personalOrg.id).run();
    }
  }

  if (is_superadmin !== undefined) {
    // Prevent self-revocation
    if (!is_superadmin && userId === currentUser.id) {
      return Response.json({ error: 'Cannot revoke your own superadmin access' }, { status: 400, headers: corsHeaders });
    }
    // Prevent revoking the last superadmin
    if (!is_superadmin) {
      const superadminCount = await env.DB.prepare(
        'SELECT COUNT(*) as cnt FROM users WHERE is_superadmin = 1'
      ).first();
      if (superadminCount?.cnt <= 1 && user.is_superadmin) {
        return Response.json({ error: 'Cannot revoke the last superadmin' }, { status: 400, headers: corsHeaders });
      }
    }
    await env.DB.prepare('UPDATE users SET is_superadmin = ? WHERE id = ?').bind(is_superadmin ? 1 : 0, userId).run();
  }

  return Response.json({ ok: true }, { headers: corsHeaders });
}

export async function adminDeleteUser(env, userId, corsHeaders) {
  // Don't allow deleting superadmins
  const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
  if (!user) return Response.json({ error: 'User not found' }, { status: 404, headers: corsHeaders });
  if (user.is_superadmin) return Response.json({ error: 'Cannot delete superadmin' }, { status: 403, headers: corsHeaders });

  // Remove from projects, orgs, sessions, then delete user
  await env.DB.prepare('DELETE FROM user_projects WHERE user_id = ?').bind(userId).run();
  await env.DB.prepare('DELETE FROM org_members WHERE user_id = ?').bind(userId).run();
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId).run();
  await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();

  return Response.json({ ok: true }, { headers: corsHeaders });
}

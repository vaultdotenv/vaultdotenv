/**
 * Dashboard organization endpoints: list, create, get, members, projects, plan.
 * All endpoints require session auth. Org membership is verified by the router.
 */

import { sendEmail, orgInviteEmailHtml } from '../lib/email.js';
import { slugify, getPersonalOrg } from '../lib/middleware.js';
import { PLAN_LIMITS } from '../lib/config.js';

export async function dashboardListOrgs(env, user, corsHeaders) {
  const orgs = await env.DB.prepare(`
    SELECT o.id, o.name, o.slug, o.personal, o.plan, o.created_at, om.role
    FROM orgs o
    JOIN org_members om ON o.id = om.org_id
    WHERE om.user_id = ?
    ORDER BY o.personal DESC, o.name ASC
  `).bind(user.id).all();

  return Response.json({ orgs: orgs.results }, { headers: corsHeaders });
}

export async function dashboardCreateOrg(request, env, user, corsHeaders) {
  // Check user's personal org plan -- need Team+ to create orgs
  const personalOrg = await getPersonalOrg(env, user.id);
  const plan = personalOrg?.plan || 'free';
  if (plan === 'free' || plan === 'pro') {
    return Response.json({ error: 'Organizations require the Team plan or higher' }, { status: 403, headers: corsHeaders });
  }

  const { name } = await request.json();
  if (!name) {
    return Response.json({ error: 'Organization name required' }, { status: 400, headers: corsHeaders });
  }

  const slug = slugify(name);
  if (!slug) {
    return Response.json({ error: 'Invalid organization name' }, { status: 400, headers: corsHeaders });
  }

  // Check slug uniqueness
  const existing = await env.DB.prepare('SELECT id FROM orgs WHERE slug = ?').bind(slug).first();
  if (existing) {
    return Response.json({ error: 'Organization name already taken' }, { status: 409, headers: corsHeaders });
  }

  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  await env.DB.prepare(
    'INSERT INTO orgs (id, name, slug, personal, plan, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, name, slug, 0, 'team', user.id, now).run();

  await env.DB.prepare(
    'INSERT INTO org_members (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)'
  ).bind(id, user.id, 'owner', now).run();

  return Response.json({ id, name, slug }, { headers: corsHeaders });
}

export async function dashboardGetOrg(env, orgId, corsHeaders) {
  const org = await env.DB.prepare(
    'SELECT id, name, slug, personal, plan, created_at FROM orgs WHERE id = ?'
  ).bind(orgId).first();
  if (!org) return Response.json({ error: 'Org not found' }, { status: 404, headers: corsHeaders });

  const memberCount = await env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM org_members WHERE org_id = ?'
  ).bind(orgId).first();

  const projectCount = await env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM projects WHERE org_id = ?'
  ).bind(orgId).first();

  return Response.json({
    ...org,
    member_count: memberCount?.cnt || 0,
    project_count: projectCount?.cnt || 0,
  }, { headers: corsHeaders });
}

export async function dashboardListOrgMembers(env, orgId, corsHeaders) {
  const members = await env.DB.prepare(`
    SELECT u.id, u.email, om.role, om.created_at
    FROM org_members om
    JOIN users u ON om.user_id = u.id
    WHERE om.org_id = ?
    ORDER BY om.created_at ASC
  `).bind(orgId).all();

  return Response.json({ members: members.results }, { headers: corsHeaders });
}

export async function dashboardInviteOrgMember(request, env, user, orgId, userRole, corsHeaders) {
  if (userRole !== 'owner') {
    return Response.json({ error: 'Only org owners can invite members' }, { status: 403, headers: corsHeaders });
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
      'SELECT * FROM org_members WHERE user_id = ? AND org_id = ?'
    ).bind(existingUser.id, orgId).first();
    if (existingMember) {
      return Response.json({ error: 'User is already a member of this organization' }, { status: 409, headers: corsHeaders });
    }

    // User exists -- add them directly
    const now = new Date().toISOString();
    await env.DB.prepare(
      'INSERT INTO org_members (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)'
    ).bind(orgId, existingUser.id, inviteRole, now).run();

    // Also add them to all org projects
    const orgProjects = await env.DB.prepare(
      'SELECT id FROM projects WHERE org_id = ?'
    ).bind(orgId).all();
    for (const proj of orgProjects.results) {
      const exists = await env.DB.prepare(
        'SELECT 1 FROM user_projects WHERE user_id = ? AND project_id = ?'
      ).bind(existingUser.id, proj.id).first();
      if (!exists) {
        await env.DB.prepare(
          'INSERT INTO user_projects (user_id, project_id, role, created_at) VALUES (?, ?, ?, ?)'
        ).bind(existingUser.id, proj.id, inviteRole, now).run();
      }
    }

    return Response.json({ status: 'added', email: email.toLowerCase() }, { headers: corsHeaders });
  }

  // User doesn't exist yet -- send invite email
  const org = await env.DB.prepare('SELECT name FROM orgs WHERE id = ?').bind(orgId).first();
  await sendEmail(env, {
    to: email.toLowerCase(),
    subject: `You've been invited to ${org?.name || 'an organization'} on vaultdotenv`,
    html: orgInviteEmailHtml(user.email, org?.name || 'an organization', inviteRole),
  });

  return Response.json({ status: 'invite_sent', email: email.toLowerCase() }, { headers: corsHeaders });
}

export async function dashboardRemoveOrgMember(env, orgId, targetUserId, currentUserId, currentRole, corsHeaders) {
  if (targetUserId === currentUserId) {
    return Response.json({ error: 'Cannot remove yourself' }, { status: 400, headers: corsHeaders });
  }
  if (currentRole !== 'owner') {
    return Response.json({ error: 'Only owners can remove members' }, { status: 403, headers: corsHeaders });
  }

  const target = await env.DB.prepare(
    'SELECT * FROM org_members WHERE user_id = ? AND org_id = ?'
  ).bind(targetUserId, orgId).first();
  if (!target) {
    return Response.json({ error: 'Member not found' }, { status: 404, headers: corsHeaders });
  }

  // Remove from org
  await env.DB.prepare(
    'DELETE FROM org_members WHERE user_id = ? AND org_id = ?'
  ).bind(targetUserId, orgId).run();

  // Remove from all org projects
  const orgProjects = await env.DB.prepare(
    'SELECT id FROM projects WHERE org_id = ?'
  ).bind(orgId).all();
  for (const proj of orgProjects.results) {
    await env.DB.prepare(
      'DELETE FROM user_projects WHERE user_id = ? AND project_id = ?'
    ).bind(targetUserId, proj.id).run();
  }

  return Response.json({ ok: true }, { headers: corsHeaders });
}

export async function dashboardListOrgProjects(env, orgId, corsHeaders) {
  const rows = await env.DB.prepare(
    'SELECT id, name, created_at FROM projects WHERE org_id = ? ORDER BY created_at DESC'
  ).bind(orgId).all();

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

export async function dashboardCreateOrgProject(request, env, user, orgId, corsHeaders) {
  const { project_name } = await request.json();
  if (!project_name) {
    return Response.json({ error: 'project_name required' }, { status: 400, headers: corsHeaders });
  }

  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  await env.DB.prepare(
    'INSERT INTO projects (id, name, key_hash, org_id, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(id, project_name, '', orgId, now).run();

  for (const envName of ['development', 'staging', 'production']) {
    await env.DB.prepare(
      'INSERT INTO environments (id, project_id, name, created_at) VALUES (?, ?, ?, ?)'
    ).bind(crypto.randomUUID(), id, envName, now).run();
  }

  // Add all org members to the project
  const orgMembers = await env.DB.prepare(
    'SELECT user_id, role FROM org_members WHERE org_id = ?'
  ).bind(orgId).all();
  for (const member of orgMembers.results) {
    await env.DB.prepare(
      'INSERT INTO user_projects (user_id, project_id, role, created_at) VALUES (?, ?, ?, ?)'
    ).bind(member.user_id, id, member.role, now).run();
  }

  return Response.json({ project_id: id, org_id: orgId }, { headers: corsHeaders });
}

export async function dashboardGetOrgPlan(env, orgId, corsHeaders) {
  const org = await env.DB.prepare('SELECT plan FROM orgs WHERE id = ?').bind(orgId).first();
  const plan = org?.plan || 'free';
  const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.free;

  const projectCount = await env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM projects WHERE org_id = ?'
  ).bind(orgId).first();

  const envCount = await env.DB.prepare(`
    SELECT COUNT(*) as cnt FROM environments e
    JOIN projects p ON e.project_id = p.id
    WHERE p.org_id = ?
  `).bind(orgId).first();

  const deviceCount = await env.DB.prepare(`
    SELECT COUNT(*) as cnt FROM devices d
    JOIN projects p ON d.project_id = p.id
    WHERE p.org_id = ? AND d.status != 'revoked'
  `).bind(orgId).first();

  return Response.json({
    plan,
    limits,
    usage: {
      projects: projectCount?.cnt || 0,
      environments: envCount?.cnt || 0,
      devices: deviceCount?.cnt || 0,
    },
  }, { headers: corsHeaders });
}

export async function dashboardUpgradeOrgPlan(request, env, orgId, userRole, corsHeaders) {
  if (userRole !== 'owner') {
    return Response.json({ error: 'Only org owners can change the plan' }, { status: 403, headers: corsHeaders });
  }

  const { plan } = await request.json();
  if (!['free', 'pro', 'team'].includes(plan)) {
    return Response.json({ error: 'Invalid plan' }, { status: 400, headers: corsHeaders });
  }

  // TODO: Stripe integration
  await env.DB.prepare('UPDATE orgs SET plan = ? WHERE id = ?').bind(plan, orgId).run();

  return Response.json({ plan }, { headers: corsHeaders });
}

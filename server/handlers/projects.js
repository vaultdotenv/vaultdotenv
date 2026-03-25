/**
 * CLI project endpoints: create, set-key.
 * Dashboard project endpoints: list, get, create, link, move.
 */

import { verifySignature } from '../lib/crypto.js';
import { getPersonalOrg } from '../lib/middleware.js';

// ── CLI Endpoints (HMAC auth) ──────────────────────────────────────────────

export async function handleCreateProject(request, env, corsHeaders) {
  const body = await request.text();
  const { project_name } = JSON.parse(body);

  if (!project_name) {
    return Response.json({ error: 'project_name required' }, { status: 400, headers: corsHeaders });
  }

  const id = crypto.randomUUID();
  await env.DB.prepare(
    'INSERT INTO projects (id, name, key_hash, created_at) VALUES (?, ?, ?, ?)'
  ).bind(id, project_name, '', new Date().toISOString()).run();

  for (const envName of ['development', 'staging', 'production']) {
    await env.DB.prepare(
      'INSERT INTO environments (id, project_id, name, created_at) VALUES (?, ?, ?, ?)'
    ).bind(crypto.randomUUID(), id, envName, new Date().toISOString()).run();
  }

  return Response.json({ project_id: id, environments: ['development', 'staging', 'production'] }, { headers: corsHeaders });
}

export async function handleSetKey(request, env, corsHeaders) {
  const body = await request.text();
  const { project_id, auth_key_hash } = JSON.parse(body);

  if (!project_id || !auth_key_hash) {
    return Response.json({ error: 'project_id and auth_key_hash required' }, { status: 400, headers: corsHeaders });
  }

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  if (project.key_hash) {
    return Response.json({ error: 'Auth key already set' }, { status: 409, headers: corsHeaders });
  }

  await env.DB.prepare('UPDATE projects SET key_hash = ? WHERE id = ?').bind(auth_key_hash, project_id).run();
  return Response.json({ ok: true }, { headers: corsHeaders });
}

// ── Dashboard Endpoints (session auth) ─────────────────────────────────────

export async function dashboardListProjects(env, user, corsHeaders) {
  const rows = await env.DB.prepare(`
    SELECT p.id, p.name, p.org_id, p.created_at
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

export async function dashboardCreateProject(request, env, user, corsHeaders) {
  const { project_name, org_id } = await request.json();
  if (!project_name) {
    return Response.json({ error: 'project_name required' }, { status: 400, headers: corsHeaders });
  }

  let targetOrgId = org_id;
  if (!targetOrgId) {
    const personalOrg = await getPersonalOrg(env, user.id);
    targetOrgId = personalOrg?.id || null;
  }

  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  await env.DB.prepare(
    'INSERT INTO projects (id, name, key_hash, org_id, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(id, project_name, '', targetOrgId, now).run();

  for (const envName of ['development', 'staging', 'production']) {
    await env.DB.prepare(
      'INSERT INTO environments (id, project_id, name, created_at) VALUES (?, ?, ?, ?)'
    ).bind(crypto.randomUUID(), id, envName, now).run();
  }

  await env.DB.prepare(
    'INSERT INTO user_projects (user_id, project_id, role, permission, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(user.id, id, 'owner', 'admin', now).run();

  return Response.json({ project_id: id, org_id: targetOrgId }, { headers: corsHeaders });
}

export async function dashboardGetProject(env, projectId, corsHeaders) {
  const project = await env.DB.prepare('SELECT id, name, org_id, created_at FROM projects WHERE id = ?').bind(projectId).first();
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

export async function dashboardListEnvironments(env, projectId, corsHeaders) {
  const envs = await env.DB.prepare(
    'SELECT id, name, created_at FROM environments WHERE project_id = ? ORDER BY name'
  ).bind(projectId).all();
  return Response.json({ environments: envs.results }, { headers: corsHeaders });
}

export async function dashboardLinkProject(request, env, user, corsHeaders) {
  const { project_id } = await request.json();
  if (!project_id) {
    return Response.json({ error: 'project_id required' }, { status: 400, headers: corsHeaders });
  }

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  const existing = await env.DB.prepare(
    'SELECT 1 FROM user_projects WHERE user_id = ? AND project_id = ?'
  ).bind(user.id, project_id).first();
  if (existing) return Response.json({ ok: true, already_linked: true }, { headers: corsHeaders });

  const now = new Date().toISOString();
  await env.DB.prepare(
    'INSERT INTO user_projects (user_id, project_id, role, permission, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(user.id, project_id, 'owner', 'admin', now).run();

  if (!project.org_id) {
    const personalOrg = await getPersonalOrg(env, user.id);
    if (personalOrg) {
      await env.DB.prepare('UPDATE projects SET org_id = ? WHERE id = ?').bind(personalOrg.id, project_id).run();
    }
  }

  return Response.json({ ok: true }, { headers: corsHeaders });
}

export async function dashboardMoveProject(request, env, user, projectId, corsHeaders) {
  const { target_org_id } = await request.json();

  if (!target_org_id) {
    return Response.json({ error: 'target_org_id required' }, { status: 400, headers: corsHeaders });
  }

  const orgAccess = await env.DB.prepare(
    'SELECT * FROM org_members WHERE user_id = ? AND org_id = ?'
  ).bind(user.id, target_org_id).first();
  if (!orgAccess) {
    return Response.json({ error: 'No access to target organization' }, { status: 403, headers: corsHeaders });
  }

  await env.DB.prepare('UPDATE projects SET org_id = ? WHERE id = ?').bind(target_org_id, projectId).run();

  const org = await env.DB.prepare('SELECT * FROM orgs WHERE id = ?').bind(target_org_id).first();
  if (org && !org.personal) {
    const orgMembers = await env.DB.prepare(
      'SELECT user_id, role FROM org_members WHERE org_id = ?'
    ).bind(target_org_id).all();
    const now = new Date().toISOString();
    for (const member of orgMembers.results) {
      const exists = await env.DB.prepare(
        'SELECT 1 FROM user_projects WHERE user_id = ? AND project_id = ?'
      ).bind(member.user_id, projectId).first();
      if (!exists) {
        await env.DB.prepare(
          'INSERT INTO user_projects (user_id, project_id, role, permission, created_at) VALUES (?, ?, ?, ?, ?)'
        ).bind(member.user_id, projectId, member.role, 'write', now).run();
      }
    }
  }

  return Response.json({ ok: true, org_id: target_org_id }, { headers: corsHeaders });
}

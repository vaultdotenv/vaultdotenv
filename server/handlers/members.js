/**
 * Dashboard member endpoints: list, update-permissions, remove.
 * All endpoints require session auth. Update/remove require project admin permission.
 */

export async function dashboardListMembers(env, projectId, corsHeaders) {
  const members = await env.DB.prepare(`
    SELECT u.id, u.email, up.role, up.permission, up.env_scope, up.created_at
    FROM user_projects up
    JOIN users u ON up.user_id = u.id
    WHERE up.project_id = ?
    ORDER BY up.created_at ASC
  `).bind(projectId).all();

  return Response.json({ members: members.results }, { headers: corsHeaders });
}

export async function dashboardUpdatePermissions(request, env, projectId, targetUserId, corsHeaders) {
  const { permission, env_scope } = await request.json();

  if (permission && !['read', 'write', 'admin'].includes(permission)) {
    return Response.json({ error: 'Invalid permission. Must be read, write, or admin.' }, { status: 400, headers: corsHeaders });
  }

  if (env_scope !== undefined && env_scope !== null && !Array.isArray(env_scope)) {
    return Response.json({ error: 'env_scope must be an array of environment names or null' }, { status: 400, headers: corsHeaders });
  }

  const target = await env.DB.prepare(
    'SELECT * FROM user_projects WHERE user_id = ? AND project_id = ?'
  ).bind(targetUserId, projectId).first();
  if (!target) {
    return Response.json({ error: 'Member not found' }, { status: 404, headers: corsHeaders });
  }

  const updates = [];
  const binds = [];
  if (permission) {
    updates.push('permission = ?');
    binds.push(permission);
  }
  if (env_scope !== undefined) {
    updates.push('env_scope = ?');
    binds.push(env_scope ? JSON.stringify(env_scope) : null);
  }

  if (updates.length > 0) {
    binds.push(targetUserId, projectId);
    await env.DB.prepare(
      `UPDATE user_projects SET ${updates.join(', ')} WHERE user_id = ? AND project_id = ?`
    ).bind(...binds).run();
  }

  return Response.json({
    user_id: targetUserId,
    permission: permission || target.permission,
    env_scope: env_scope !== undefined ? env_scope : (target.env_scope ? JSON.parse(target.env_scope) : null),
  }, { headers: corsHeaders });
}

export async function dashboardRemoveMember(env, projectId, targetUserId, currentUserId, corsHeaders) {
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

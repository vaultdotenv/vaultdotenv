'use strict';

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');

const API_URL = process.env.TEST_API_URL || 'https://api.vaultdotenv.io';

async function api(path, options = {}) {
  const resp = await fetch(`${API_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  const data = await resp.json().catch(() => null);
  return { status: resp.status, data, ok: resp.ok };
}

describe('API integration (live server)', () => {
  describe('health', () => {
    it('returns ok', async () => {
      const { status, data } = await api('/health');
      assert.equal(status, 200);
      assert.equal(data.status, 'ok');
      assert.ok(data.ts > 0);
    });
  });

  describe('CORS', () => {
    it('responds to OPTIONS with CORS headers', async () => {
      const resp = await fetch(`${API_URL}/api/v1/secrets/pull`, { method: 'OPTIONS' });
      assert.ok([200, 204].includes(resp.status));
      assert.ok(resp.headers.get('access-control-allow-origin'));
    });
  });

  describe('auth', () => {
    it('signup is disabled', async () => {
      const { status, data } = await api('/api/v1/dashboard/signup', {
        method: 'POST',
        body: JSON.stringify({ email: 'test@example.com', password: 'testpass123' }),
      });
      assert.equal(status, 403);
      assert.ok(data.error.includes('closed') || data.error.includes('disabled'));
    });

    it('login with invalid credentials returns 401', async () => {
      const { status, data } = await api('/api/v1/dashboard/login', {
        method: 'POST',
        body: JSON.stringify({ email: 'nonexistent@example.com', password: 'wrong' }),
      });
      assert.equal(status, 401);
      assert.ok(data.error);
    });

    it('login with missing fields returns 400', async () => {
      const { status } = await api('/api/v1/dashboard/login', {
        method: 'POST',
        body: JSON.stringify({}),
      });
      assert.equal(status, 400);
    });

    it('/me without token returns 401', async () => {
      const { status } = await api('/api/v1/dashboard/me');
      assert.equal(status, 401);
    });

    it('/projects without token returns 401', async () => {
      const { status } = await api('/api/v1/dashboard/projects');
      assert.equal(status, 401);
    });
  });

  describe('CLI auth', () => {
    it('start returns a code and auth_url', async () => {
      const { status, data } = await api('/api/v1/cli/auth/start', { method: 'POST' });
      assert.equal(status, 200);
      assert.ok(data.code);
      assert.ok(data.auth_url);
      assert.ok(data.expires_at);
    });

    it('poll with invalid code returns 404', async () => {
      const { status, data } = await api('/api/v1/cli/auth/poll?code=invalid');
      assert.equal(status, 404);
      assert.ok(data.error);
    });

    it('poll with valid code returns pending', async () => {
      const { data: startData } = await api('/api/v1/cli/auth/start', { method: 'POST' });
      const { status, data } = await api(`/api/v1/cli/auth/poll?code=${startData.code}`);
      assert.equal(status, 200);
      assert.equal(data.status, 'pending');
    });

    it('poll without code returns 400', async () => {
      const { status } = await api('/api/v1/cli/auth/poll');
      assert.equal(status, 400);
    });
  });

  describe('admin', () => {
    it('admin endpoints without auth return 401', async () => {
      const { status } = await api('/api/v1/dashboard/admin/stats');
      assert.equal(status, 401);
    });
  });

  describe('404 handling', () => {
    it('unknown API path returns 404', async () => {
      const { status, data } = await api('/api/v1/nonexistent');
      assert.equal(status, 404);
      assert.equal(data.error, 'Not found');
    });

    it('unknown dashboard path returns 404', async () => {
      const { status } = await api('/api/v1/dashboard/nonexistent', {
        headers: { 'Authorization': 'Bearer fake-token' },
      });
      // Either 401 (invalid token) or 404 — both acceptable
      assert.ok([401, 404].includes(status));
    });
  });

  describe('secret endpoints (HMAC auth)', () => {
    it('pull without signature returns 401', async () => {
      const { status } = await api('/api/v1/secrets/pull', {
        method: 'POST',
        body: JSON.stringify({ project_id: 'fake', environment: 'production' }),
      });
      // 401 (bad sig) or 404 (project not found) — both acceptable
      assert.ok([401, 404].includes(status));
    });

    it('push without signature returns 401', async () => {
      const { status } = await api('/api/v1/secrets/push', {
        method: 'POST',
        body: JSON.stringify({ project_id: 'fake', environment: 'production', secrets: 'x' }),
      });
      assert.ok([401, 404].includes(status));
    });

    it('project create without name returns 400', async () => {
      const { status, data } = await api('/api/v1/project/create', {
        method: 'POST',
        body: JSON.stringify({}),
      });
      assert.equal(status, 400);
      assert.ok(data.error.includes('project_name'));
    });
  });
});

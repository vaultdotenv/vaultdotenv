/**
 * Email sending via Resend API + HTML templates.
 */

import { DASHBOARD_URL, EMAIL_FROM } from './config.js';

// ── Send ───────────────────────────────────────────────────────────────────

export async function sendEmail(env, { to, subject, html }) {
  if (!env.RESEND_API_KEY) {
    console.log(`[email] Skipped (no RESEND_API_KEY): to=${to} subject=${subject}`);
    return { sent: false, reason: 'no_api_key' };
  }

  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ from: EMAIL_FROM, to: [to], subject, html }),
  });

  if (!resp.ok) {
    const err = await resp.text().catch(() => '');
    console.error(`[email] Failed: ${resp.status} ${err}`);
    return { sent: false, reason: err };
  }

  return { sent: true };
}

// ── Templates ──────────────────────────────────────────────────────────────

const LOGO_SVG = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`;

function emailWrapper(content) {
  return `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 480px; margin: 0 auto; padding: 40px 20px;">
      <div style="text-align: center; margin-bottom: 32px;">
        <div style="display: inline-block; background: #0d6efd; border-radius: 12px; padding: 12px; margin-bottom: 16px;">
          ${LOGO_SVG}
        </div>
        ${content}
      </div>
    </div>
  `;
}

export function inviteEmailHtml(inviterEmail, projectName, role, acceptUrl) {
  return emailWrapper(`
    <h1 style="font-size: 20px; font-weight: 700; color: #1a202c; margin: 0;">You've been invited</h1>
    </div>
    <p style="font-size: 15px; color: #2d3748; line-height: 1.6;">
      <strong>${inviterEmail}</strong> has invited you to join <strong>${projectName}</strong> as a <strong>${role}</strong> on vaultdotenv.
    </p>
    <div style="text-align: center; margin: 32px 0;">
      <a href="${acceptUrl}" style="display: inline-block; background: #0d6efd; color: white; text-decoration: none; font-weight: 600; font-size: 15px; padding: 12px 32px; border-radius: 8px;">Accept Invitation</a>
    </div>
    <p style="font-size: 13px; color: #a0aec0; text-align: center;">
      This invite expires in 7 days. If you didn't expect this email, you can safely ignore it.
    </p>
  `);
}

export function orgInviteEmailHtml(inviterEmail, orgName, role) {
  return emailWrapper(`
    <h1 style="font-size: 20px; font-weight: 700; color: #1a202c; margin: 0;">You've been invited</h1>
    </div>
    <p style="font-size: 15px; color: #2d3748; line-height: 1.6;">
      <strong>${inviterEmail}</strong> has invited you to join the <strong>${orgName}</strong> organization as a <strong>${role}</strong> on vaultdotenv.
    </p>
    <div style="text-align: center; margin: 32px 0;">
      <a href="${DASHBOARD_URL}/signup" style="display: inline-block; background: #0d6efd; color: white; text-decoration: none; font-weight: 600; font-size: 15px; padding: 12px 32px; border-radius: 8px;">Create Account</a>
    </div>
    <p style="font-size: 13px; color: #a0aec0; text-align: center;">
      Once you create an account, you'll automatically be added to the organization.
    </p>
  `);
}

export function welcomeEmailHtml(email) {
  return emailWrapper(`
    <h1 style="font-size: 22px; font-weight: 700; color: #1a202c; margin: 0;">Welcome to vaultdotenv</h1>
    </div>
    <p style="font-size: 15px; color: #2d3748; line-height: 1.6;">
      You're all set, <strong>${email}</strong>. Your account is ready.
    </p>
    <p style="font-size: 15px; color: #2d3748; line-height: 1.6;">Here's how to get started:</p>
    <div style="background: #1a202c; border-radius: 12px; padding: 20px; margin: 24px 0;">
      <pre style="margin: 0; font-family: 'JetBrains Mono', monospace; font-size: 13px; line-height: 1.8; color: #e2e8f0; overflow-x: auto;"><span style="color: #a0aec0;"># Install the CLI</span>
<span style="color: #0d6efd;">$</span> npm install -g @vaultdotenv/cli

<span style="color: #a0aec0;"># Log in and create your first project</span>
<span style="color: #0d6efd;">$</span> vde login
<span style="color: #0d6efd;">$</span> vde init --name my-app

<span style="color: #a0aec0;"># Push your secrets</span>
<span style="color: #0d6efd;">$</span> vde push --env production</pre>
    </div>
    <div style="text-align: center; margin: 32px 0;">
      <a href="${DASHBOARD_URL}/projects" style="display: inline-block; background: #0d6efd; color: white; text-decoration: none; font-weight: 600; font-size: 15px; padding: 12px 32px; border-radius: 8px;">Open Dashboard</a>
    </div>
    <div style="border-top: 1px solid #e2e8f0; margin-top: 32px; padding-top: 20px;">
      <p style="font-size: 13px; color: #a0aec0; line-height: 1.6; margin: 0;">
        <strong>Useful links:</strong><br/>
        <a href="https://vaultdotenv.io/docs" style="color: #0d6efd; text-decoration: none;">Documentation</a> &middot;
        <a href="https://github.com/vaultdotenv/vaultdotenv" style="color: #0d6efd; text-decoration: none;">GitHub</a> &middot;
        <a href="${DASHBOARD_URL}/settings" style="color: #0d6efd; text-decoration: none;">Account Settings</a>
      </p>
    </div>
  `);
}

/**
 * Stripe billing: checkout session creation + webhook handler.
 *
 * Uses Stripe REST API directly (no SDK — runs on Cloudflare Workers).
 * Webhook signature verified via HMAC-SHA256.
 */

import { DASHBOARD_URL as DEFAULT_DASHBOARD_URL } from '../lib/config.js';

const STRIPE_API = 'https://api.stripe.com/v1';

function getDashboardUrl(env) {
  return env.DASHBOARD_URL || DEFAULT_DASHBOARD_URL;
}

const PRICE_MAP = {
  pro: 'price_1TF1j8IRrTIgf1hhxgTiFNjF',
  team: 'price_1TF1jXIRrTIgf1hhdxrXtDhM',
};

const PRICE_TO_PLAN = Object.fromEntries(
  Object.entries(PRICE_MAP).map(([plan, price]) => [price, plan])
);

// ── Stripe REST helpers ─────────────────────────────────────────────────────

async function stripeRequest(env, method, path, params = {}) {
  const body = new URLSearchParams();
  for (const [key, val] of Object.entries(params)) {
    if (val !== undefined && val !== null) body.append(key, String(val));
  }

  const resp = await fetch(`${STRIPE_API}${path}`, {
    method,
    headers: {
      'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: method !== 'GET' ? body.toString() : undefined,
  });

  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data.error?.message || `Stripe API error (${resp.status})`);
  }
  return data;
}

// ── Webhook signature verification ──────────────────────────────────────────

async function verifyWebhookSignature(payload, sigHeader, secret) {
  const parts = {};
  for (const item of sigHeader.split(',')) {
    const [k, v] = item.split('=');
    parts[k] = v;
  }

  const timestamp = parts.t;
  const signature = parts.v1;
  if (!timestamp || !signature) return false;

  // Reject if older than 5 minutes
  const age = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (age > 300) return false;

  const signedPayload = `${timestamp}.${payload}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signedPayload));
  const expected = [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');

  return expected === signature;
}

// ── Create Checkout Session ─────────────────────────────────────────────────

export async function createCheckoutSession(request, env, user, corsHeaders) {
  const { plan } = await request.json();

  if (!plan || !PRICE_MAP[plan]) {
    return Response.json({ error: 'Invalid plan. Must be "pro" or "team".' }, { status: 400, headers: corsHeaders });
  }

  // Get or create Stripe customer
  let customerId = null;
  const dbUser = await env.DB.prepare('SELECT stripe_customer_id FROM users WHERE id = ?').bind(user.id).first();

  if (dbUser?.stripe_customer_id) {
    customerId = dbUser.stripe_customer_id;
  } else {
    const customer = await stripeRequest(env, 'POST', '/customers', {
      email: user.email,
      'metadata[vault_user_id]': user.id,
    });
    customerId = customer.id;
    await env.DB.prepare('UPDATE users SET stripe_customer_id = ? WHERE id = ?').bind(customerId, user.id).run();
  }

  // Create checkout session
  const session = await stripeRequest(env, 'POST', '/checkout/sessions', {
    customer: customerId,
    mode: 'subscription',
    'line_items[0][price]': PRICE_MAP[plan],
    'line_items[0][quantity]': '1',
    success_url: `${getDashboardUrl(env)}/billing?success=true`,
    cancel_url: `${getDashboardUrl(env)}/billing?cancelled=true`,
    'metadata[vault_user_id]': user.id,
    'metadata[plan]': plan,
    'subscription_data[metadata][vault_user_id]': user.id,
    'subscription_data[metadata][plan]': plan,
  });

  return Response.json({ url: session.url }, { headers: corsHeaders });
}

// ── Customer Portal Session ─────────────────────────────────────────────────

export async function createPortalSession(request, env, user, corsHeaders) {
  const dbUser = await env.DB.prepare('SELECT stripe_customer_id FROM users WHERE id = ?').bind(user.id).first();

  if (!dbUser?.stripe_customer_id) {
    return Response.json({ error: 'No billing account found' }, { status: 400, headers: corsHeaders });
  }

  const session = await stripeRequest(env, 'POST', '/billing_portal/sessions', {
    customer: dbUser.stripe_customer_id,
    return_url: `${getDashboardUrl(env)}/billing`,
  });

  return Response.json({ url: session.url }, { headers: corsHeaders });
}

// ── Webhook Handler ─────────────────────────────────────────────────────────

export async function handleStripeWebhook(request, env, corsHeaders) {
  const payload = await request.text();
  const sigHeader = request.headers.get('stripe-signature');

  if (!sigHeader) {
    return Response.json({ error: 'Missing signature' }, { status: 400, headers: corsHeaders });
  }

  const valid = await verifyWebhookSignature(payload, sigHeader, env.STRIPE_WEBHOOK_SECRET);
  if (!valid) {
    return Response.json({ error: 'Invalid signature' }, { status: 400, headers: corsHeaders });
  }

  const event = JSON.parse(payload);

  switch (event.type) {
    case 'checkout.session.completed':
      await handleCheckoutCompleted(event.data.object, env);
      break;

    case 'customer.subscription.updated':
      await handleSubscriptionUpdated(event.data.object, env);
      break;

    case 'customer.subscription.deleted':
      await handleSubscriptionDeleted(event.data.object, env);
      break;

    case 'invoice.payment_failed':
      await handlePaymentFailed(event.data.object, env);
      break;

    case 'invoice.payment_succeeded':
      // Confirm plan stays active — subscription.updated handles status
      break;

    case 'charge.refunded':
      await handleRefund(event.data.object, env);
      break;
  }

  return Response.json({ received: true }, { headers: corsHeaders });
}

// ── Event Handlers ──────────────────────────────────────────────────────────

async function handleCheckoutCompleted(session, env) {
  if (session.mode !== 'subscription') return;

  const userId = session.metadata?.vault_user_id;
  const plan = session.metadata?.plan;
  if (!userId || !plan) return;

  await env.DB.prepare(
    'UPDATE users SET plan = ?, stripe_customer_id = ?, stripe_subscription_id = ? WHERE id = ?'
  ).bind(plan, session.customer, session.subscription, userId).run();

  // Sync personal org plan
  const personalOrg = await env.DB.prepare(
    'SELECT id FROM orgs WHERE created_by = ? AND personal = 1'
  ).bind(userId).first();
  if (personalOrg) {
    await env.DB.prepare('UPDATE orgs SET plan = ? WHERE id = ?').bind(plan, personalOrg.id).run();
  }
}

async function handleSubscriptionUpdated(sub, env) {
  const user = await env.DB.prepare(
    'SELECT id FROM users WHERE stripe_subscription_id = ?'
  ).bind(sub.id).first();
  if (!user) return;

  // If subscription went to canceled/unpaid/past_due, downgrade to free
  if (['canceled', 'unpaid'].includes(sub.status)) {
    await syncPlan(env, user.id, 'free');
  } else if (sub.status === 'active') {
    // Plan may have changed — check price
    const priceId = sub.items?.data?.[0]?.price?.id;
    const plan = PRICE_TO_PLAN[priceId];
    if (plan) {
      await syncPlan(env, user.id, plan);
    }
  }
  // past_due: leave current plan for now, payment_failed handles downgrade
}

async function handleSubscriptionDeleted(sub, env) {
  const user = await env.DB.prepare(
    'SELECT id FROM users WHERE stripe_subscription_id = ?'
  ).bind(sub.id).first();
  if (!user) return;

  await env.DB.prepare(
    'UPDATE users SET plan = ?, stripe_subscription_id = NULL WHERE id = ?'
  ).bind('free', user.id).run();

  // Sync personal org
  const personalOrg = await env.DB.prepare(
    'SELECT id FROM orgs WHERE created_by = ? AND personal = 1'
  ).bind(user.id).first();
  if (personalOrg) {
    await env.DB.prepare('UPDATE orgs SET plan = ? WHERE id = ?').bind('free', personalOrg.id).run();
  }
}

async function handlePaymentFailed(invoice, env) {
  if (!invoice.customer) return;

  const user = await env.DB.prepare(
    'SELECT id FROM users WHERE stripe_customer_id = ?'
  ).bind(invoice.customer).first();
  if (!user) return;

  // Downgrade to free on payment failure
  await syncPlan(env, user.id, 'free');
}

async function handleRefund(charge, env) {
  if (!charge.customer) return;

  const user = await env.DB.prepare(
    'SELECT id FROM users WHERE stripe_customer_id = ?'
  ).bind(charge.customer).first();
  if (!user) return;

  // Downgrade to free on refund
  await syncPlan(env, user.id, 'free');
}

// ── Helpers ─────────────────────────────────────────────────────────────────

async function syncPlan(env, userId, plan) {
  await env.DB.prepare('UPDATE users SET plan = ? WHERE id = ?').bind(plan, userId).run();

  const personalOrg = await env.DB.prepare(
    'SELECT id FROM orgs WHERE created_by = ? AND personal = 1'
  ).bind(userId).first();
  if (personalOrg) {
    await env.DB.prepare('UPDATE orgs SET plan = ? WHERE id = ?').bind(plan, personalOrg.id).run();
  }
}

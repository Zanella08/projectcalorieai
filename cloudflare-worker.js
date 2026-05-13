/**
 * ============================================================
 * CalorieAI — Cloudflare Worker v2
 * ============================================================
 * Routes:
 *   POST /                → AI proxy (Groq)
 *   POST /create-checkout → Create Stripe checkout session
 *   POST /verify-payment  → Verify payment & upgrade user
 *   POST /webhook         → Handle Stripe webhook events
 *
 * Add these secrets in Worker Settings → Variables and Secrets:
 *   GROQ_API_KEY           your gsk_... key
 *   STRIPE_SECRET_KEY      your sk_live_... key
 *   STRIPE_WEBHOOK_SECRET  your whsec_... key
 *   SUPABASE_URL           https://frcyjkvlbsjumprqqpgz.supabase.co
 *   SUPABASE_SERVICE_KEY   service_role key from Supabase Settings → API
 * ============================================================
 */

const ALLOWED_ORIGIN = '*'; // Change to your domain in production

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin':  ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders() },
  });
}

// Simple per-IP rate limiter (in-memory)
const rateMap = new Map();
function isRateLimited(ip) {
  const now = Date.now();
  const e = rateMap.get(ip) || { count: 0, start: now };
  if (now - e.start > 60000) { rateMap.set(ip, { count: 1, start: now }); return false; }
  if (e.count >= 20) return true;
  e.count++; rateMap.set(ip, e); return false;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }
    if (request.method !== 'POST') {
      return new Response('CalorieAI API v2', { status: 200 });
    }

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

    if (url.pathname === '/webhook')         return handleWebhook(request, env);
    if (url.pathname === '/create-checkout') return createCheckout(request, env, ip);
    if (url.pathname === '/verify-payment')  return verifyPayment(request, env);

    // Default: AI proxy
    if (isRateLimited(ip)) return json({ error: { message: 'Too many requests.' } }, 429);
    return proxyAI(request, env);
  },
};

// ── AI Proxy ────────────────────────────────────────────────
async function proxyAI(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: { message: 'Invalid JSON' } }, 400); }

  const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${env.GROQ_API_KEY}` },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  return json(data, res.status);
}

// ── Create Stripe Checkout ───────────────────────────────────
async function createCheckout(request, env, ip) {
  if (isRateLimited(ip)) return json({ error: 'Too many requests' }, 429);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }

  const { priceId, userId, email, successUrl, cancelUrl } = body;
  if (!priceId || !userId || !email) return json({ error: 'Missing required fields' }, 400);

  const params = new URLSearchParams({
    'mode': 'subscription',
    'line_items[0][price]': priceId,
    'line_items[0][quantity]': '1',
    'customer_email': email,
    'success_url': successUrl + '?success=true&session_id={CHECKOUT_SESSION_ID}',
    'cancel_url': cancelUrl + '?canceled=true',
    'metadata[user_id]': userId,
    'subscription_data[metadata][user_id]': userId,
    'allow_promotion_codes': 'true',
  });

  const res = await fetch('https://api.stripe.com/v1/checkout/sessions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });
  const session = await res.json();
  if (!res.ok) return json({ error: session.error?.message || 'Stripe error' }, 400);
  return json({ url: session.url });
}

// ── Verify Payment ───────────────────────────────────────────
async function verifyPayment(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }

  const { sessionId, userId } = body;
  if (!sessionId || !userId) return json({ error: 'Missing sessionId or userId' }, 400);

  const res = await fetch(`https://api.stripe.com/v1/checkout/sessions/${sessionId}`, {
    headers: { 'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}` }
  });
  const session = await res.json();
  if (!res.ok || session.payment_status !== 'paid') {
    return json({ success: false, error: 'Payment not verified' }, 400);
  }

  await upgradeUser(userId, session.customer, session.subscription, env);
  return json({ success: true, plan: 'pro' });
}

// ── Stripe Webhook ───────────────────────────────────────────
async function handleWebhook(request, env) {
  const payload   = await request.text();
  const sigHeader = request.headers.get('stripe-signature');
  let event;
  try { event = await verifyStripeSignature(payload, sigHeader, env.STRIPE_WEBHOOK_SECRET); }
  catch (err) { return new Response(`Webhook Error: ${err.message}`, { status: 400 }); }

  const obj = event.data.object;
  switch (event.type) {
    case 'customer.subscription.created':
    case 'invoice.payment_succeeded': {
      const uid = obj.metadata?.user_id || obj.subscription_details?.metadata?.user_id;
      if (uid) await upgradeUser(uid, obj.customer, obj.subscription || obj.id, env);
      break;
    }
    case 'customer.subscription.deleted':
      await downgradeUser(obj.id, env); break;
    case 'customer.subscription.updated':
      if (obj.status === 'canceled' || obj.status === 'unpaid') await downgradeUser(obj.id, env);
      break;
    case 'invoice.payment_failed':
      await downgradeUser(obj.subscription, env); break;
  }
  return new Response(JSON.stringify({ received: true }), {
    status: 200, headers: { 'Content-Type': 'application/json' }
  });
}

async function verifyStripeSignature(payload, sigHeader, secret) {
  const encoder = new TextEncoder();
  const parts = sigHeader.split(',');
  const ts  = parts.find(p => p.startsWith('t=')).split('=')[1];
  const sig = parts.find(p => p.startsWith('v1=')).split('=')[1];
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const mac = await crypto.subtle.sign('HMAC', key, encoder.encode(`${ts}.${payload}`));
  const hex = Array.from(new Uint8Array(mac)).map(b => b.toString(16).padStart(2,'0')).join('');
  if (hex !== sig) throw new Error('Invalid signature');
  if (Math.abs(Date.now()/1000 - parseInt(ts)) > 300) throw new Error('Timestamp too old');
  return JSON.parse(payload);
}

// ── Supabase Helpers ─────────────────────────────────────────
async function upgradeUser(userId, customerId, subscriptionId, env) {
  await fetch(`${env.SUPABASE_URL}/rest/v1/profiles?id=eq.${userId}`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'apikey': env.SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${env.SUPABASE_SERVICE_KEY}`,
      'Prefer': 'return=minimal',
    },
    body: JSON.stringify({
      plan: 'pro', subscription_status: 'active',
      stripe_customer_id: customerId,
      stripe_subscription_id: subscriptionId,
      updated_at: new Date().toISOString(),
    }),
  });
}

async function downgradeUser(subscriptionId, env) {
  await fetch(`${env.SUPABASE_URL}/rest/v1/profiles?stripe_subscription_id=eq.${subscriptionId}`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'apikey': env.SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${env.SUPABASE_SERVICE_KEY}`,
      'Prefer': 'return=minimal',
    },
    body: JSON.stringify({
      plan: 'free', subscription_status: 'canceled',
      updated_at: new Date().toISOString(),
    }),
  });
}

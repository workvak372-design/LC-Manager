// Server-only auth helpers for the Lakhan Construction app.
// This file runs on Vercel's serverless infrastructure — it is never sent
// to the browser. The real password lives in the APP_PASSWORD environment
// variable (set in the Vercel project dashboard), not in any file here.

const crypto = require('crypto');

const SESSION_MAX_AGE_SECONDS = 12 * 60 * 60; // 12 hours

function getSecret() {
  const secret = process.env.SESSION_SECRET;
  if (!secret) throw new Error('SESSION_SECRET environment variable is not set');
  return secret;
}

function sign(payload) {
  return crypto.createHmac('sha256', getSecret()).update(payload).digest('base64url');
}

// A session token is just `<payload>.<hmac signature>` — the server can
// recompute the signature and reject anything that doesn't match or has
// expired. The browser cannot forge one without knowing SESSION_SECRET,
// which only exists on the server.
function createSessionToken() {
  const exp = Date.now() + SESSION_MAX_AGE_SECONDS * 1000;
  const payload = Buffer.from(JSON.stringify({ exp })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

function verifySessionToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return false;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return false;

  let expectedSig;
  try {
    expectedSig = sign(payload);
  } catch (e) {
    return false; // SESSION_SECRET missing/misconfigured
  }

  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return false;
  }

  let data;
  try {
    data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch (e) {
    return false;
  }
  return typeof data.exp === 'number' && Date.now() <= data.exp;
}

// Constant-time string comparison so a wrong-password response can't be
// timed to leak how many leading characters were correct.
function timingSafeStringEqual(a, b) {
  const aBuf = Buffer.from(String(a || ''));
  const bBuf = Buffer.from(String(b || ''));
  if (aBuf.length !== bBuf.length) {
    // Compare against itself so this branch takes a similar amount of time
    // as the real comparison below, rather than returning instantly.
    crypto.timingSafeEqual(aBuf, aBuf);
    return false;
  }
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key) out[key] = decodeURIComponent(val);
  });
  return out;
}

function setSessionCookie(res, token) {
  res.setHeader(
    'Set-Cookie',
    `lc_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_MAX_AGE_SECONDS}`
  );
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'lc_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');
}

// Best-effort rate limiting. This resets whenever the serverless instance
// cold-starts and only applies within a single warm instance, so it is NOT
// a strong guarantee against a determined, distributed attacker — but it
// meaningfully slows down casual brute-forcing, which is the realistic
// threat for a small internal tool like this. For a hard guarantee across
// instances, this would need a shared store like Vercel KV or Upstash Redis
// — a reasonable future upgrade, not implemented here to avoid adding a new
// infrastructure dependency for a single-password internal tool.
const attempts = new Map(); // ip -> { count, resetAt }
const MAX_ATTEMPTS = 8;
const WINDOW_MS = 5 * 60 * 1000;
// Hard ceiling on how many distinct keys we'll ever track at once. Without
// this, an attacker who spoofs many different X-Forwarded-For values (or
// simply a very long-lived warm instance with lots of one-off visitors)
// could grow this Map indefinitely. This bounds it without needing any
// external store.
const MAX_TRACKED_IPS = 5000;

function pruneIfNeeded(now) {
  if (attempts.size <= MAX_TRACKED_IPS) return;
  // First pass: drop anything whose window has already expired — the
  // common case, and free of any ordering assumptions.
  for (const [key, rec] of attempts) {
    if (now > rec.resetAt) attempts.delete(key);
  }
  // Still over the cap (e.g. a burst of distinct keys all within one
  // window)? Evict the oldest-inserted entries rather than let memory grow
  // without bound. Map iteration order is insertion order, so this is a
  // cheap approximate LRU.
  if (attempts.size > MAX_TRACKED_IPS) {
    const excess = attempts.size - MAX_TRACKED_IPS;
    let i = 0;
    for (const key of attempts.keys()) {
      if (i++ >= excess) break;
      attempts.delete(key);
    }
  }
}

function checkRateLimit(ip) {
  const now = Date.now();
  pruneIfNeeded(now);
  const rec = attempts.get(ip);
  if (!rec || now > rec.resetAt) {
    attempts.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return true;
  }
  if (rec.count >= MAX_ATTEMPTS) {
    // Sliding lockout: continuing to hit the endpoint while already blocked
    // pushes the reset further out, so a bot that just retries every few
    // seconds can't simply wait out a fixed window.
    rec.resetAt = now + WINDOW_MS;
    return false;
  }
  rec.count += 1;
  return true;
}

function getIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return String(fwd).split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

async function readJsonBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch (e) { return {}; }
  }
  // A real payload here is just `{ "password": "..." }`, so anything much
  // bigger than this is either a mistake or an attempt to waste server
  // memory/CPU buffering an oversized body — stop reading as soon as we
  // cross the limit instead of buffering it all first.
  const MAX_BYTES = 10 * 1024;
  return new Promise((resolve) => {
    let data = '';
    let bytes = 0;
    let done = false;
    const finish = (value) => { if (!done) { done = true; resolve(value); } };
    req.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > MAX_BYTES) {
        finish({});
        req.destroy();
        return;
      }
      data += chunk;
    });
    req.on('end', () => {
      try { finish(JSON.parse(data || '{}')); } catch (e) { finish({}); }
    });
    req.on('error', () => finish({}));
  });
}

module.exports = {
  createSessionToken,
  verifySessionToken,
  parseCookies,
  setSessionCookie,
  clearSessionCookie,
  timingSafeStringEqual,
  checkRateLimit,
  getIp,
  readJsonBody,
};

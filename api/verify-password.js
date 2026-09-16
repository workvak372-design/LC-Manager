const {
  verifySessionToken,
  parseCookies,
  timingSafeStringEqual,
  checkRateLimit,
  getIp,
  readJsonBody,
} = require('./_lib/auth');

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    if (req.method !== 'POST') {
      res.status(405).json({ ok: false, error: 'method_not_allowed' });
      return;
    }

    const cookies = parseCookies(req);
    if (!verifySessionToken(cookies.lc_session)) {
      res.status(401).json({ ok: false, error: 'not_authenticated' });
      return;
    }

    const ip = getIp(req);
    if (!checkRateLimit(ip)) {
      res.status(429).json({ ok: false, error: 'too_many_attempts' });
      return;
    }

    const appPassword = process.env.APP_PASSWORD;
    if (!appPassword || !process.env.SESSION_SECRET) {
      console.error('Verify-password blocked: APP_PASSWORD or SESSION_SECRET is not set in the Vercel project.');
      res.status(500).json({ ok: false, error: 'server_not_configured' });
      return;
    }

    const body = await readJsonBody(req);
    const password = body && typeof body.password === 'string' ? body.password : '';

    if (!timingSafeStringEqual(password, appPassword)) {
      res.status(401).json({ ok: false, error: 'invalid_password' });
      return;
    }

    res.status(200).json({ ok: true });
  } catch (e) {
    console.error('Unexpected error in /api/verify-password:', e && e.message);
    if (!res.headersSent) res.status(500).json({ ok: false, error: 'server_error' });
  }
};

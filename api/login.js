const {
  createSessionToken,
  setSessionCookie,
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

    const ip = getIp(req);
    if (!checkRateLimit(ip)) {
      res.status(429).json({ ok: false, error: 'too_many_attempts' });
      return;
    }

    const appPassword = process.env.APP_PASSWORD;
    if (!appPassword || !process.env.SESSION_SECRET) {
      // Deliberately generic to the client, but this tells you (the deployer)
      // exactly what's missing when you check the Vercel function logs.
      // Never logs the password/secret values themselves — only the fact
      // that one is missing.
      console.error('Login blocked: APP_PASSWORD or SESSION_SECRET is not set in the Vercel project.');
      res.status(500).json({ ok: false, error: 'server_not_configured' });
      return;
    }

    const body = await readJsonBody(req);
    const password = body && typeof body.password === 'string' ? body.password : '';

    if (!timingSafeStringEqual(password, appPassword)) {
      res.status(401).json({ ok: false, error: 'invalid_password' });
      return;
    }

    setSessionCookie(res, createSessionToken());
    res.status(200).json({ ok: true });
  } catch (e) {
    // Never include the caught error's message verbatim in the response —
    // it could in theory echo back request data. Log server-side only, and
    // never log req.body (which may contain the password).
    console.error('Unexpected error in /api/login:', e && e.message);
    if (!res.headersSent) res.status(500).json({ ok: false, error: 'server_error' });
  }
};

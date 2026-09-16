const { clearSessionCookie } = require('./_lib/auth');

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    if (req.method !== 'POST') {
      res.status(405).json({ ok: false, error: 'method_not_allowed' });
      return;
    }
    clearSessionCookie(res);
    res.status(200).json({ ok: true });
  } catch (e) {
    console.error('Unexpected error in /api/logout:', e && e.message);
    if (!res.headersSent) res.status(500).json({ ok: false, error: 'server_error' });
  }
};

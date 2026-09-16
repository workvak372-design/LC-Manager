const { verifySessionToken, parseCookies } = require('./_lib/auth');

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const cookies = parseCookies(req);
    const authenticated = verifySessionToken(cookies.lc_session);
    res.status(200).json({ authenticated });
  } catch (e) {
    // Fail closed: if anything unexpected goes wrong, report "not
    // authenticated" rather than leaking an error or defaulting open.
    console.error('Unexpected error in /api/session:', e && e.message);
    res.status(200).json({ authenticated: false });
  }
};

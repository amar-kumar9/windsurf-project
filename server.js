// server.js
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const path = require('path');
const session = require('express-session');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// allow running behind a proxy (Replit) when TRUST_PROXY=1
if (process.env.TRUST_PROXY === '1') {
  app.set('trust proxy', 1);
}

// Session configuration
const sessionCookieSecure = (process.env.SESSION_COOKIE_SECURE === '1'); // set to 1 on Replit
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: sessionCookieSecure,   // requires HTTPS when true
    sameSite: 'none',              // required for cross-site iframes
    httpOnly: true,
    maxAge: 60 * 60 * 1000         // 1 hour
  }
}));

const {
  SF_LOGIN_URL = 'https://login.salesforce.com',
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI
} = process.env;

if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI) {
  console.warn('Warning: CLIENT_ID, CLIENT_SECRET, and REDIRECT_URI should be set in env');
}

// Serve static assets from /public
app.use(express.static(path.join(__dirname, 'public')));

// --- Start OAuth flow: redirect to Salesforce authorize endpoint ---
app.get('/auth', (req, res) => {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'web refresh_token openid'
  });
  const authUrl = `${SF_LOGIN_URL}/services/oauth2/authorize?${params.toString()}`;
  res.redirect(authUrl);
});

// --- OAuth callback: exchange code and save tokens in session ---
app.get('/oauth/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send('Missing code');

  try {
    const tokenUrl = `${SF_LOGIN_URL}/services/oauth2/token`;
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI
    });

    const tokenResp = await axios.post(tokenUrl, params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    req.session.sf = {
      access_token: tokenResp.data.access_token,
      refresh_token: tokenResp.data.refresh_token,
      instance_url: tokenResp.data.instance_url,
      id: tokenResp.data.id,
      issued_at: tokenResp.data.issued_at
    };

    res.redirect('/');
  } catch (err) {
    console.error('OAuth token exchange failed:', err.response?.data || err.message);
    res.status(500).send('OAuth token exchange failed. Check server logs.');
  }
});

// --- Logout ---
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// --- API: Return one-time frontdoor URL for the current session ---
app.get('/api/frontdoor', async (req, res) => {
  const sf = req.session.sf;
  if (!sf || !sf.access_token || !sf.instance_url) {
    return res.status(401).json({ error: 'not_authenticated' });
  }

  try {
    const singleaccessUrl = `${sf.instance_url}/services/oauth2/singleaccess`;
    const params = new URLSearchParams({ access_token: sf.access_token });

    const r = await axios.post(singleaccessUrl, params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const data = r.data;
    let frontdoor = data.frontdoor_uri || data.frontdoor_url || null;

    if (!frontdoor && typeof data === 'string') {
      frontdoor = data;
    }

    if (!frontdoor) {
      const fallback = `${sf.instance_url}/secur/frontdoor.jsp?sid=${encodeURIComponent(sf.access_token)}`;
      return res.json({ frontdoorUrl: fallback, note: 'fallback (not recommended for prod)' });
    }

    const fullFrontdoor = frontdoor.startsWith('http') ? frontdoor : `${sf.instance_url}${frontdoor}`;
    return res.json({ frontdoorUrl: fullFrontdoor });
  } catch (err) {
    console.error('Error getting frontdoor:', err.response?.data || err.message);
    return res.status(500).json({ error: 'singleaccess_failed', detail: err.response?.data || err.message });
  }
});

// --- Helper: expose auth state to client ---
app.get('/api/me', (req, res) => {
  if (!req.session.sf) return res.json({ authenticated: false });
  return res.json({ authenticated: true, instance_url: req.session.sf.instance_url });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));

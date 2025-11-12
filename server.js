// server.js
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const path = require('path');
const session = require('express-session');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Required for correct cookie handling behind Render's proxy
app.set('trust proxy', 1);

// Secure cookie configuration for cross-site iframes
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,        // Render always serves HTTPS
    sameSite: 'none',    // Required for Salesforce iframe cookies
    httpOnly: true,
    maxAge: 60 * 60 * 1000 // 1 hour
  }
}));

const {
  SF_LOGIN_URL = 'https://login.salesforce.com',
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI
} = process.env;

if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI) {
  console.warn('⚠️  Missing Salesforce Connected App environment variables.');
}

// Serve static assets
app.use(express.static(path.join(__dirname, 'public')));

// ===== OAuth login route =====
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

// ===== OAuth callback =====
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
    console.error('OAuth exchange failed:', err.response?.data || err.message);
    res.status(500).send('OAuth token exchange failed.');
  }
});

// ===== Logout =====
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// ===== Frontdoor URL exchange =====
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
    let frontdoor = data.frontdoor_uri || data.frontdoor_url || (typeof data === 'string' ? data : null);
    if (!frontdoor) {
      const fallback = `${sf.instance_url}/secur/frontdoor.jsp?sid=${encodeURIComponent(sf.access_token)}`;
      return res.json({ frontdoorUrl: fallback, note: 'fallback frontdoor (not recommended for prod)' });
    }

    const fullFrontdoor = frontdoor.startsWith('http')
      ? frontdoor
      : `${sf.instance_url}${frontdoor}`;
    res.json({ frontdoorUrl: fullFrontdoor });
  } catch (err) {
    console.error('Frontdoor request failed:', err.response?.data || err.message);
    res.status(500).json({ error: 'singleaccess_failed', detail: err.message });
  }
});

// ===== Auth check =====
app.get('/api/me', (req, res) => {
  if (!req.session.sf) return res.json({ authenticated: false });
  res.json({ authenticated: true, instance_url: req.session.sf.instance_url });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));

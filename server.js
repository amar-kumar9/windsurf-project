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

// debug token exchange block — replace existing handler while debugging
try {
const tokenUrl = `${SF_LOGIN_URL.replace(/\/$/, '')}/services/oauth2/token`;
const params = new URLSearchParams();
params.append('grant_type', 'authorization_code');
params.append('code', code);
params.append('client_id', CLIENT_ID);
params.append('client_secret', CLIENT_SECRET);
params.append('redirect_uri', REDIRECT_URI);

console.log('POSTing token request to:', tokenUrl);
console.log('Request body (urlencoded):', params.toString());

const tokenResp = await axios.post(tokenUrl, params.toString(), {
  headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' },
  maxRedirects: 0,
  validateStatus: status => status < 500
});

console.log('Token endpoint status:', tokenResp.status);
console.log('Token endpoint headers:', tokenResp.headers);
console.log('Token endpoint body (truncated):', typeof tokenResp.data === 'string' ? tokenResp.data.substring(0,2000) : JSON.stringify(tokenResp.data));

if (tokenResp.status === 200 && tokenResp.data && tokenResp.data.access_token) {
  req.session.sf = {
    access_token: tokenResp.data.access_token,
    refresh_token: tokenResp.data.refresh_token,
    instance_url: tokenResp.data.instance_url
  };
  return res.redirect('/');
}

// If it's a redirect (302) or other non-200, log location if present
if (tokenResp.status >= 300 && tokenResp.status < 400) {
  console.error('Token endpoint redirected. Location header:', tokenResp.headers.location);
}

console.error('Token endpoint returned non-200 and no access_token.');
return res.status(500).send('OAuth token exchange failed — token endpoint returned unexpected response. See server logs.');

} catch (err) {
console.error('Token exchange exception:', err.message);
if (err.response) {
  console.error('Err response status:', err.response.status);
  console.error('Err response headers:', err.response.headers);
  console.error('Err response body (truncated):', typeof err.response.data === 'string' ? err.response.data.substring(0,2000) : JSON.stringify(err.response.data));
} else {
  console.error('No response object in error:', err);
}
return res.status(500).send('OAuth token exchange failed. See server logs.');
}

  // As a debugging aid, try the generic login.salesforce.com token endpoint (do not use in prod)
  try {
    const altUrl = 'https://login.salesforce.com/services/oauth2/token';
    console.log('Attempting fallback token request to login.salesforce.com (debug only)');
    const altParams = new URLSearchParams();
    altParams.append('grant_type', 'authorization_code');
    altParams.append('code', code);
    altParams.append('client_id', CLIENT_ID);
    altParams.append('client_secret', CLIENT_SECRET);
    altParams.append('redirect_uri', REDIRECT_URI);

    const altResp = await axios.post(altUrl, altParams.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' },
      maxRedirects: 0,
      validateStatus: status => status < 500
    });

    console.log('Fallback status:', altResp.status);
    console.log('Fallback body:', altResp.data);
  } catch (altErr) {
    console.error('Fallback token attempt failed:', altErr.response ? altErr.response.data : altErr.message);
  }

  return res.status(500).send('OAuth token exchange failed. See server logs for details.');
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

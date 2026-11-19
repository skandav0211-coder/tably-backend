const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { newId } = require('./db');
const { entitlement } = require('./entitlement');
const { DAY, addMonths, nowIso, parseCookies } = require('./util');
const { authCodeEmail } = require('./mailer');
const { validateProductionEnv } = require('./config');

function normalizeOrigins(value) {
  return value.split(',').map((origin) => origin.trim().replace(/\/+$/, '')).filter(Boolean);
}

function createApp(db, opts = {}) {
  if (process.env.NODE_ENV === 'production') validateProductionEnv(process.env);
  const USER_SECRET = opts.userSecret || process.env.USER_JWT_SECRET || crypto.randomBytes(32).toString('hex');
  const ADMIN_SECRET = opts.adminSecret || process.env.ADMIN_JWT_SECRET || crypto.randomBytes(32).toString('hex');
  const ENT_SECRET = opts.entSecret || process.env.ENTITLEMENT_SECRET || crypto.randomBytes(32).toString('hex');
  const mailer = opts.mailer || require('./mailer').createMailer();
  if (!mailer) throw new Error('SMTP_HOST (and credentials) must be set so the Super Admin can receive sign-in codes by email');
  const limit = (max) => rateLimit({ windowMs: 15 * 60 * 1000, max: opts.noRateLimit ? 1e9 : max, standardHeaders: true, legacyHeaders: false });

  const app = express();
  app.set('trust proxy', 1);
  app.use(helmet());
  const origins = normalizeOrigins(process.env.ADMIN_PORTAL_ORIGINS || '');
  if (process.env.NODE_ENV === 'production' && origins.some((origin) => origin.includes('*'))) {
    throw new Error('ADMIN_PORTAL_ORIGINS must not contain wildcard origins in production');
  }
  const adminOrigins = new Set(origins);
  if (process.env.NODE_ENV !== 'production' && adminOrigins.size === 0) {
    adminOrigins.add('http://localhost:5173');
    adminOrigins.add('http://127.0.0.1:5173');
  }
  app.use('/admin-api', cors({
    origin: (origin, callback) => callback(null, origin && adminOrigins.has(origin) ? origin : false),
    credentials: true,
    allowedHeaders: ['Content-Type', 'X-CSRF'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  }));
  app.use(express.json({ limit: '1mb' }));
  app.use(['/api', '/admin-api'], (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  app.use('/api', limit(1500));
  app.get('/health', (req, res) => {
    db.prepare('SELECT 1').get();
    res.json({ ok: true });
  });

  const setting = (k) => db.prepare('SELECT value FROM settings WHERE key=?').get(k)?.value;
  const audit = (actor, action, target, reason, before, after, ip) =>
    db.prepare('INSERT INTO audit_events(actor,action,target,reason,before,after,ip,created_at) VALUES (?,?,?,?,?,?,?,?)')
      .run(actor, action, target || null, reason || null, before ? JSON.stringify(before) : null, after ? JSON.stringify(after) : null, ip || null, nowIso());
  const notify = (bid, title, body) =>
    db.prepare('INSERT INTO notifications(business_id,title,body,created_at) VALUES (?,?,?,?)').run(bid, title, body, nowIso());
  const secEvent = (bid, kind, detail) =>
    db.prepare('INSERT INTO security_events(business_id,kind,detail,created_at) VALUES (?,?,?,?)').run(bid, kind, detail, nowIso());
  const bad = (res, code, msg, extra = {}) => res.status(code).json({ error: msg, ...extra });
  const wrap = (fn) => (req, res, next) => { try { Promise.resolve(fn(req, res, next)).catch(next); } catch (e) { next(e); } };

  // ───────────────────────── Customer auth ─────────────────────────
  const CODE_MIN = 10, MAX_CODE_TRIES = 5, CODE_COOLDOWN_MS = 30000, MAX_CODE_SENDS = 4;
  const emailNorm = (v) => String(v || '').trim().toLowerCase();
  const emailOk = (v) => typeof v === 'string' && v.length <= 254 && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v);
  const passwordOk = (v) => typeof v === 'string' && v.length >= 10 && Buffer.byteLength(v, 'utf8') <= 72;
  const phoneNorm = (v) => typeof v === 'string' ? v.trim().replace(/[ ()-]/g, '') : '';
  const phoneOk = (v) => /^(?:\d{10}|\+[1-9]\d{9,14})$/.test(v);
  const maskEmail = (email) => email.replace(/^(.)(.*)(@.*)$/, (_, first, middle, domain) => first + '*'.repeat(Math.min(middle.length, 6)) + domain);
  const DUMMY_USER_PASSWORD = bcrypt.hashSync('not-a-real-user-password', 10);
  async function sendAuthCode(challenge, req) {
    const code = String(crypto.randomInt(0, 1e6)).padStart(6, '0');
    db.prepare('UPDATE auth_challenges SET code_hash=?, expires_at=?, attempts=0, last_sent_at=? WHERE id=?')
      .run(bcrypt.hashSync(code, 8), Date.now() + CODE_MIN * 60000, Date.now(), challenge.id);
    if (process.env.NODE_ENV !== 'production') console.log(`[AUTH CODE] ${challenge.email} (${challenge.purpose}): ${code}`);
    await mailer.sendMail(authCodeEmail({ to: challenge.email, code, minutes: CODE_MIN, purpose: challenge.purpose }));
  }
  function makeChallenge({ userId = null, email, purpose, phone = null, ownerName = null, passwordHash = null }) {
    const id = crypto.randomBytes(16).toString('hex');
    db.prepare(`INSERT INTO auth_challenges(id,user_id,email,purpose,code_hash,expires_at,attempts,sends,last_sent_at,phone,owner_name,password_hash)
      VALUES (?,?,?,?,?,0,0,1,0,?,?,?)`).run(id, userId, email, purpose, '-', phone, ownerName, passwordHash);
    return db.prepare('SELECT * FROM auth_challenges WHERE id=?').get(id);
  }
  const getChallenge = (id, purpose) => db.prepare('SELECT * FROM auth_challenges WHERE id=? AND purpose=?').get(String(id || ''), purpose);
  function badCode(res, challenge) {
    if (!challenge || challenge.expires_at < Date.now()) {
      if (challenge) db.prepare('DELETE FROM auth_challenges WHERE id=?').run(challenge.id);
      return bad(res, 400, 'Code expired or invalid. Request a new one.');
    }
    if (challenge.attempts >= MAX_CODE_TRIES) return bad(res, 400, 'Too many incorrect codes. Request a new one.');
    return null;
  }
  function checkCode(res, challenge, code) {
    const error = badCode(res, challenge); if (error) return false;
    if (!bcrypt.compareSync(String(code || '').trim(), challenge.code_hash)) {
      const attempts = challenge.attempts + 1;
      if (attempts >= MAX_CODE_TRIES) db.prepare('DELETE FROM auth_challenges WHERE id=?').run(challenge.id);
      else db.prepare('UPDATE auth_challenges SET attempts=? WHERE id=?').run(attempts, challenge.id);
      bad(res, 400, attempts >= MAX_CODE_TRIES ? 'Too many incorrect codes. Request a new one.' : 'Incorrect code.');
      return false;
    }
    return true;
  }
  async function resendChallenge(req, res, purpose, deliver = true) {
    const c = getChallenge(req.body.challenge, purpose);
    if (!c || c.expires_at < Date.now()) {
      if (c) db.prepare('DELETE FROM auth_challenges WHERE id=?').run(c.id);
      return bad(res, 400, 'Request expired. Start again.');
    }
    if (Date.now() - c.last_sent_at < CODE_COOLDOWN_MS) return bad(res, 429, 'Please wait 30 seconds before requesting another code.');
    if (c.sends >= MAX_CODE_SENDS) { db.prepare('DELETE FROM auth_challenges WHERE id=?').run(c.id); return bad(res, 429, 'Too many codes requested. Start again.'); }
    db.prepare('UPDATE auth_challenges SET sends=sends+1 WHERE id=?').run(c.id);
    if (deliver) {
      try { await sendAuthCode(c, req); } catch (e) { console.error('Customer verification email failed:', e.message); return bad(res, 502, 'Could not send the email. Check the email address and try again.'); }
    } else {
      db.prepare('UPDATE auth_challenges SET code_hash=?,expires_at=?,attempts=0,last_sent_at=? WHERE id=?')
        .run(bcrypt.hashSync(crypto.randomBytes(32).toString('hex'), 8), Date.now() + CODE_MIN * 60000, Date.now(), c.id);
    }
    res.json({ ok: true, challenge: c.id, email: maskEmail(c.email), expiresInSec: CODE_MIN * 60, resendAfterSec: CODE_COOLDOWN_MS / 1000 });
  }
  const userToken = (u) => jwt.sign({ sub: u.id, tv: u.token_version, typ: 'user' }, USER_SECRET, { expiresIn: '1h' });
  const issueUserSession = (res, user) => {
    if (user.status !== 'active') return bad(res, 403, 'Account disabled');
    const biz = db.prepare('SELECT id FROM businesses WHERE owner_user_id=?').get(user.id);
    res.json({ token: userToken(user), userId: user.id, businessId: biz?.id || null, isNew: !biz });
  };
  app.post('/api/auth/register', limit(10), wrap(async (req, res) => {
    const email = emailNorm(req.body.email), password = req.body.password, ownerName = String(req.body.ownerName || '').trim();
    const phone = phoneNorm(req.body.phone);
    if (!emailOk(email)) return bad(res, 400, 'Enter a valid email address.');
    if (!passwordOk(password)) return bad(res, 400, 'Password must be at least 10 characters and no more than 72 UTF-8 bytes.');
    if (!ownerName || ownerName.length > 100) return bad(res, 400, 'Enter an owner name up to 100 characters.');
    if (!phoneOk(phone)) return bad(res, 400, 'Enter a phone number with 10 digits, optionally prefixed by a country code.');
    if (db.prepare('SELECT 1 FROM users WHERE lower(email)=?').get(email)) return bad(res, 409, 'An account already uses this email. Sign in or reset your password.');
    const pending = db.prepare("SELECT * FROM auth_challenges WHERE email=? AND purpose='register' ORDER BY last_sent_at DESC LIMIT 1").get(email);
    if (pending && pending.expires_at >= Date.now()) return res.status(202).json({ challenge: pending.id, email: maskEmail(email), expiresInSec: CODE_MIN * 60, resendAfterSec: CODE_COOLDOWN_MS / 1000 });
    if (pending) db.prepare('DELETE FROM auth_challenges WHERE id=?').run(pending.id);
    const challenge = makeChallenge({ email, purpose: 'register', phone, ownerName, passwordHash: bcrypt.hashSync(password, 10) });
    try { await sendAuthCode(challenge, req); } catch (e) { db.prepare('DELETE FROM auth_challenges WHERE id=?').run(challenge.id); console.error('Customer verification email failed:', e.message); return bad(res, 502, 'Could not send the verification email. Check your email and try again.'); }
    res.status(202).json({ challenge: challenge.id, email: maskEmail(email), expiresInSec: CODE_MIN * 60, resendAfterSec: CODE_COOLDOWN_MS / 1000 });
  }));
  app.post('/api/auth/register/resend', limit(10), wrap((req, res) => resendChallenge(req, res, 'register')));
  app.post('/api/auth/register/verify', limit(20), wrap((req, res) => {
    const c = getChallenge(req.body.challenge, 'register');
    if (!checkCode(res, c, req.body.code)) return;
    try {
      const id = newId(db, 'USR', 'users');
      db.transaction(() => {
        db.prepare(`INSERT INTO users(id,mobile,email,phone,password_hash,email_verified,owner_name,verified,created_at)
          VALUES (?,?, ?,?,?,1,?,1,?)`).run(id, 'legacy-' + id.toLowerCase(), c.email, c.phone, c.password_hash, c.owner_name, nowIso());
        db.prepare('DELETE FROM auth_challenges WHERE id=?').run(c.id);
      })();
      const user = db.prepare('SELECT * FROM users WHERE id=?').get(id);
      audit('system', 'user.registered', id);
      issueUserSession(res, user);
    } catch (e) {
      if (String(e.code || '').startsWith('SQLITE_CONSTRAINT')) return bad(res, 409, 'An account already uses this email. Sign in or reset your password.');
      throw e;
    }
  }));
  app.post('/api/auth/login', limit(20), wrap((req, res) => {
    const email = emailNorm(req.body.email), password = String(req.body.password || '');
    const user = emailOk(email) ? db.prepare('SELECT * FROM users WHERE lower(email)=?').get(email) : null;
    if (!user) { bcrypt.compareSync(password, DUMMY_USER_PASSWORD); return bad(res, 401, 'Invalid email or password.'); }
    const passwordMatches = bcrypt.compareSync(password, user.password_hash || DUMMY_USER_PASSWORD);
    if (user.locked_until > Date.now()) return bad(res, 401, 'Invalid email or password.');
    if (!passwordMatches || !user.email_verified) {
      const failed = user.failed_logins + 1;
      db.prepare('UPDATE users SET failed_logins=?,locked_until=? WHERE id=?')
        .run(failed >= 5 ? 0 : failed, failed >= 5 ? Date.now() + 15 * 60000 : 0, user.id);
      return bad(res, 401, 'Invalid email or password.');
    }
    db.prepare('UPDATE users SET failed_logins=0,locked_until=0 WHERE id=?').run(user.id);
    issueUserSession(res, user);
  }));
  app.post('/api/auth/password/forgot', limit(10), wrap(async (req, res) => {
    const email = emailNorm(req.body.email);
    if (!emailOk(email)) return bad(res, 400, 'Enter a valid email address.');
    const user = db.prepare('SELECT id,email FROM users WHERE lower(email)=? AND email_verified=1 AND password_hash IS NOT NULL').get(email);
    const existing = db.prepare("SELECT id FROM auth_challenges WHERE email=? AND purpose='reset' AND expires_at>=? ORDER BY last_sent_at DESC LIMIT 1").get(email, Date.now());
    if (existing) return res.json({ ok: true, challenge: existing.id, message: 'If an account exists for this email, a password reset code has been sent.' });
    db.prepare("DELETE FROM auth_challenges WHERE email=? AND purpose='reset'").run(email);
    const c = makeChallenge({ userId: user?.id || null, email, purpose: 'reset' });
    if (user) {
      try { await sendAuthCode(c, req); } catch (e) {
        console.error('Password reset email failed:', e.message);
        db.prepare('UPDATE auth_challenges SET user_id=NULL,code_hash=?,expires_at=? WHERE id=?')
          .run(bcrypt.hashSync(crypto.randomBytes(32).toString('hex'), 8), Date.now() + CODE_MIN * 60000, c.id);
      }
    } else {
      db.prepare('UPDATE auth_challenges SET code_hash=?,expires_at=? WHERE id=?')
        .run(bcrypt.hashSync(crypto.randomBytes(32).toString('hex'), 8), Date.now() + CODE_MIN * 60000, c.id);
    }
    res.json({ ok: true, challenge: c.id, message: 'If an account exists for this email, a password reset code has been sent.' });
  }));
  app.post('/api/auth/password/resend', limit(10), wrap((req, res) => {
    const c = getChallenge(req.body.challenge, 'reset');
    return resendChallenge(req, res, 'reset', !!c?.user_id);
  }));
  app.post('/api/auth/password/reset', limit(20), wrap((req, res) => {
    const c = getChallenge(req.body.challenge, 'reset');
    if (!passwordOk(req.body.password)) return bad(res, 400, 'Password must be at least 10 characters and no more than 72 UTF-8 bytes.');
    if (!checkCode(res, c, req.body.code)) return;
    if (!c.user_id) return bad(res, 400, 'Invalid code. Request a new one.');
    const hash = bcrypt.hashSync(req.body.password, 10);
    db.transaction(() => {
      db.prepare('UPDATE users SET password_hash=?,failed_logins=0,locked_until=0,token_version=token_version+1 WHERE id=?').run(hash, c.user_id);
      db.prepare('DELETE FROM auth_challenges WHERE user_id=?').run(c.user_id);
    })();
    audit('user:' + c.user_id, 'password.reset', c.user_id, null, null, null, req.ip);
    res.json({ ok: true });
  }));
  app.post('/api/auth/setup/verify', limit(20), wrap((req, res) => {
    const email = emailNorm(req.body.email);
    const c = req.body.challenge ? getChallenge(req.body.challenge, 'setup')
      : db.prepare("SELECT * FROM auth_challenges WHERE email=? AND purpose='setup' ORDER BY last_sent_at DESC LIMIT 1").get(email);
    if (!passwordOk(req.body.password)) return bad(res, 400, 'Password must be at least 10 characters and no more than 72 UTF-8 bytes.');
    if (!checkCode(res, c, req.body.code)) return;
    const hash = bcrypt.hashSync(req.body.password, 10);
    db.transaction(() => {
      db.prepare('UPDATE users SET email=?,password_hash=?,email_verified=1,failed_logins=0,locked_until=0 WHERE id=?').run(c.email, hash, c.user_id);
      db.prepare('DELETE FROM auth_challenges WHERE id=?').run(c.id);
    })();
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(c.user_id);
    audit('user:' + c.user_id, 'account.setup_completed', c.user_id, null, null, null, req.ip);
    issueUserSession(res, user);
  }));
  app.post('/api/auth/setup/resend', limit(10), wrap((req, res) => {
    if (!req.body.challenge && emailOk(emailNorm(req.body.email))) {
      const c = db.prepare("SELECT id FROM auth_challenges WHERE email=? AND purpose='setup' ORDER BY last_sent_at DESC LIMIT 1").get(emailNorm(req.body.email));
      if (!c) return bad(res, 400, 'No setup invite was found for this email.');
      req.body.challenge = c.id;
    }
    return resendChallenge(req, res, 'setup');
  }));
  async function createSetupInvite(userId, email, req) {
    const normalizedEmail = emailNorm(email);
    if (!emailOk(normalizedEmail)) throw Object.assign(new Error('Enter a valid email address.'), { status: 400 });
    if (db.prepare('SELECT 1 FROM users WHERE lower(email)=? AND id<>?').get(normalizedEmail, userId)) throw Object.assign(new Error('That email is already in use.'), { status: 409 });
    db.prepare("DELETE FROM auth_challenges WHERE user_id=? AND purpose='setup'").run(userId);
    const challenge = makeChallenge({ userId, email: normalizedEmail, purpose: 'setup' });
    try { await sendAuthCode(challenge, req); } catch (e) {
      db.prepare('DELETE FROM auth_challenges WHERE id=?').run(challenge.id);
      console.error('Account setup email failed:', e.message);
      throw Object.assign(new Error('Could not send the setup email. Check SMTP and try again.'), { status: 502 });
    }
    return { challenge: challenge.id, email: maskEmail(normalizedEmail), expiresInSec: CODE_MIN * 60, resendAfterSec: CODE_COOLDOWN_MS / 1000 };
  }

  function auth(req, res, next) {
    const h = req.headers.authorization || '';
    if (!h.startsWith('Bearer ')) return bad(res, 401, 'Missing token');
    let p;
    try { p = jwt.verify(h.slice(7), USER_SECRET, { algorithms: ['HS256'] }); } catch { return bad(res, 401, 'Invalid or expired token'); }
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(p.sub);
    if (!user || user.status !== 'active' || user.token_version !== p.tv) return bad(res, 401, 'Session revoked');
    req.user = user; req.tokenType = p.typ;
    const biz = db.prepare('SELECT * FROM businesses WHERE owner_user_id=?').get(user.id);
    req.business = biz || null; req.businessId = biz?.id || null; // tenant comes ONLY from the token, never request params
    if (p.typ === 'device') {
      const dev = db.prepare("SELECT * FROM devices WHERE id=? AND business_id=? AND status='active'").get(p.did, req.businessId);
      if (!dev) return bad(res, 401, 'Device not registered or revoked', { code: 'DEVICE_REVOKED' });
      req.device = dev;
      db.prepare('UPDATE devices SET last_seen_at=? WHERE id=?').run(nowIso(), dev.id);
    }
    next();
  }
  const needBusiness = (req, res, next) => req.businessId ? next() : bad(res, 409, 'Create a business profile first');
  const needDevice = (req, res, next) => req.device ? next() : bad(res, 403, 'Device registration required', { code: 'DEVICE_REQUIRED' });
  const needPaid = (req, res, next) => {
    const e = entitlement(db, req.businessId);
    if (!e.paid) return bad(res, 402, 'Subscription does not permit this action', { code: 'SUBSCRIPTION_' + e.status.toUpperCase(), status: e.status });
    req.ent = e; next();
  };

  app.post('/api/auth/logout-all', auth, wrap((req, res) => {
    db.prepare('UPDATE users SET token_version=token_version+1 WHERE id=?').run(req.user.id);
    audit('user:' + req.user.id, 'session.revoke_all', req.user.id);
    res.json({ ok: true });
  }));

  // ───────────────────────── Business profile ─────────────────────────
  app.post('/api/business', auth, wrap((req, res) => {
    if (req.business) return bad(res, 409, 'Business already exists for this owner');
    const { ownerName, businessName, businessType, address, gstin } = req.body;
    const contact = phoneNorm(req.body.contact);
    for (const [k, v, max] of [['ownerName', ownerName, 100], ['businessName', businessName, 150], ['businessType', businessType, 50], ['address', address, 300], ['contact', contact, 20], ['gstin', gstin, 15]])
      if (v != null && (typeof v !== 'string' || v.length > max)) return bad(res, 400, `${k} must be text up to ${max} characters`);
    if (!phoneOk(contact)) return bad(res, 400, 'Enter a phone number with 10 digits, optionally prefixed by a country code.');
    if (gstin && db.prepare('SELECT 1 FROM businesses WHERE gstin=?').get(gstin)) return bad(res, 409, 'A business with this GSTIN is already registered. Contact support if this is your business.');
    if (!ownerName || !businessName || !businessType || !address || !contact) return bad(res, 400, 'ownerName, businessName, businessType, address, contact are required');
    if (gstin && !/^[0-9A-Z]{15}$/.test(gstin)) return bad(res, 400, 'GSTIN must be 15 alphanumeric characters');
    const id = newId(db, 'BIZ', 'businesses');
    db.prepare('UPDATE users SET owner_name=?, phone=? WHERE id=?').run(ownerName, contact, req.user.id);
    db.prepare('INSERT INTO businesses(id,owner_user_id,name,type,address,contact,gstin,created_at) VALUES (?,?,?,?,?,?,?,?)')
      .run(id, req.user.id, businessName, businessType, address, contact, gstin || null, nowIso());
    audit('user:' + req.user.id, 'business.created', id);
    res.status(201).json({ businessId: id });
  }));
  app.get('/api/me', auth, wrap((req, res) => {
    const { id, phone, email, owner_name } = req.user;
    const devs = req.businessId ? db.prepare("SELECT COUNT(*) c FROM devices WHERE business_id=? AND status='active'").get(req.businessId).c : 0;
    const e = req.businessId ? entitlement(db, req.businessId) : { status: 'none' };
    res.json({ user: { id, phone, email, ownerName: owner_name }, business: req.business, subscription: pubEnt(e), deviceSlots: { used: devs, max: Number(setting('max_devices')) }, defaults: { receiptFooter: setting('receipt_footer_default') || '' } });
  }));
  app.put('/api/business', auth, needBusiness, wrap((req, res) => {
    const f = { name: 'name', type: 'type', address: 'address', contact: 'contact', gstin: 'gstin', taxProfile: 'tax_profile', receiptFooter: 'receipt_footer', logo: 'logo' };
    const max = { name: 150, type: 50, address: 300, contact: 30, gstin: 15, taxProfile: 500, receiptFooter: 200, logo: 200000 };
    for (const k of Object.keys(f)) if (k in req.body && req.body[k] != null && (typeof req.body[k] !== 'string' || req.body[k].length > max[k])) return bad(res, 400, `${k} must be text up to ${max[k]} characters`);
    if (req.body.gstin && !/^[0-9A-Z]{15}$/.test(req.body.gstin)) return bad(res, 400, 'GSTIN must be 15 alphanumeric characters');
    if ('contact' in req.body) {
      req.body.contact = phoneNorm(req.body.contact);
      if (!phoneOk(req.body.contact)) return bad(res, 400, 'Enter a phone number with 10 digits, optionally prefixed by a country code.');
    }
    if (req.body.gstin && db.prepare('SELECT 1 FROM businesses WHERE gstin=? AND id<>?').get(req.body.gstin, req.businessId)) return bad(res, 409, 'This GSTIN is already registered to another business');
    for (const k of ['name', 'address', 'contact']) if (k in req.body && !String(req.body[k] || '').trim()) return bad(res, 400, `${k} cannot be empty`);
    if ('taxProfile' in req.body && req.body.taxProfile) { try { JSON.parse(req.body.taxProfile); } catch { return bad(res, 400, 'taxProfile must be valid JSON'); } }
    const sets = [], vals = [];
    for (const [k, col] of Object.entries(f)) if (k in req.body) { sets.push(col + '=?'); vals.push(req.body[k]); }
    if (!sets.length) return bad(res, 400, 'Nothing to update');
    db.prepare(`UPDATE businesses SET ${sets.join(',')} WHERE id=?`).run(...vals, req.businessId);
    if ('contact' in req.body) db.prepare('UPDATE users SET phone=? WHERE id=?').run(req.body.contact, req.user.id);
    res.json(db.prepare('SELECT * FROM businesses WHERE id=?').get(req.businessId));
  }));

  // ───────────────────────── Subscription (customer side) ─────────────────────────
  function pubEnt(e) {
    const s = e.subscription;
    const days = (setting('reminder_days') || '').split(',').map(Number);
    return { status: e.status, paid: e.paid, daysLeft: e.daysLeft ?? null, message: e.message || null,
      subscriptionId: s?.id || null, startDate: s?.start_date || null, endDate: s?.end_date || null,
      reminder: e.daysLeft != null && days.some(d => e.daysLeft <= d) };
  }
  app.get('/api/subscription', auth, needBusiness, wrap((req, res) => {
    const history = db.prepare('SELECT id,plan,amount,status,start_date,end_date,admin_message,created_at FROM subscriptions WHERE business_id=? ORDER BY created_at DESC').all(req.businessId);
    res.json({ ...pubEnt(entitlement(db, req.businessId)), planMonths: Number(setting('plan_months')), planPrice: Number(setting('plan_price')), paymentInstructions: setting('payment_instructions') || '', supportContact: setting('support_contact') || '', history });
  }));
  app.post('/api/subscription/request', auth, needBusiness, wrap((req, res) => {
    const { paymentRef, amount, method, evidence } = req.body;
    if (!paymentRef) return bad(res, 400, 'paymentRef is required');
    if (db.prepare("SELECT 1 FROM subscriptions WHERE business_id=? AND status='pending'").get(req.businessId))
      return bad(res, 409, 'A request is already pending approval');
    if (typeof paymentRef !== 'string' || paymentRef.length > 100) return bad(res, 400, 'Invalid paymentRef');
    if ((evidence != null && (typeof evidence !== 'string' || evidence.length > 500)) || (method != null && !['upi', 'bank', 'card', 'cash', 'other'].includes(method)) || (amount != null && !(typeof amount === 'number' && amount >= 0 && amount < 1e9))) return bad(res, 400, 'Invalid amount, method or evidence');
    if (db.prepare('SELECT 1 FROM payments WHERE lower(provider_ref)=lower(?) AND verification_state!=\'rejected\'').get(paymentRef))
      return bad(res, 409, 'This payment reference has already been submitted. Each payment can be used once.', { code: 'PAYMENT_REF_USED' });
    const e = entitlement(db, req.businessId);
    if (e.status === 'suspended') return bad(res, 403, 'Account suspended; contact support');
    const sid = newId(db, 'SUB', 'subscriptions'), pid = newId(db, 'PAY', 'payments');
    db.transaction(() => {
      db.prepare("INSERT INTO subscriptions(id,business_id,plan,amount,status,created_at) VALUES (?,?,?,?, 'pending', ?)")
        .run(sid, req.businessId, `${setting('plan_months')}-month`, amount ?? Number(setting('plan_price')), nowIso());
      db.prepare('INSERT INTO payments(id,business_id,subscription_id,amount,method,provider_ref,evidence,created_at) VALUES (?,?,?,?,?,?,?,?)')
        .run(pid, req.businessId, sid, amount ?? null, method || null, paymentRef, evidence || null, nowIso());
    })();
    audit('user:' + req.user.id, 'subscription.requested', sid, null, null, { paymentRef });
    res.status(201).json({ subscriptionId: sid, status: 'pending' }); // payment alone never unlocks paid features
  }));

  // ───────────────────────── Devices (≤3 per business) ─────────────────────────
  const issueDevice = (user, dev) => jwt.sign({ sub: user.id, tv: user.token_version, typ: 'device', did: dev.id }, USER_SECRET, { expiresIn: '30d' });
  function entToken(bid, deviceId) {
    const e = entitlement(db, bid);
    const win = Number(setting('offline_window_hours')) * 3600;
    const endSec = e.subscription?.end_date ? Math.floor(new Date(e.subscription.end_date).getTime() / 1000) : 0;
    const exp = e.paid ? Math.min(Math.floor(Date.now() / 1000) + win, endSec || Infinity) : Math.floor(Date.now() / 1000) + 60;
    const validUntil = new Date(exp * 1000).toISOString();
    // Server remembers how far this device was allowed to bill offline; used to reject backdated/late bills on sync.
    if (deviceId) db.prepare('UPDATE devices SET entitled_until=? WHERE id=?').run(e.paid ? validUntil : nowIso(), deviceId);
    return { token: jwt.sign({ bid, status: e.status, paid: e.paid, exp }, ENT_SECRET), validUntil };
  }
  app.post('/api/devices/register', auth, needBusiness, wrap((req, res) => {
    const { appInstanceId, label } = req.body;
    if (typeof appInstanceId !== 'string' || !appInstanceId || appInstanceId.length > 100) return bad(res, 400, 'appInstanceId required');
    const e = entitlement(db, req.businessId);
    if (!e.paid) return bad(res, 402, 'Active subscription required to register devices', { status: e.status });
    let dev = db.prepare("SELECT * FROM devices WHERE business_id=? AND app_instance_id=? AND status='active'").get(req.businessId, appInstanceId);
    if (!dev) {
      const max = Number(setting('max_devices'));
      const used = db.prepare("SELECT slot FROM devices WHERE business_id=? AND status='active'").all(req.businessId).map(r => r.slot);
      if (used.length >= max) {
        secEvent(req.businessId, 'device_limit_exceeded', `Attempted registration of "${label || appInstanceId}"`);
        return bad(res, 403, `Device limit of ${max} reached. Remove a device first.`, { code: 'DEVICE_LIMIT' });
      }
      let slot = 1; while (used.includes(slot)) slot++;
      const id = newId(db, 'DEV', 'devices');
      db.prepare('INSERT INTO devices(id,business_id,app_instance_id,slot,label,registered_at,last_seen_at,reg_seq) VALUES (?,?,?,?,?,?,?,(SELECT COALESCE(MAX(reg_seq),0)+1 FROM devices WHERE business_id=?))')
        .run(id, req.businessId, appInstanceId, slot, String(label || '').slice(0, 80) || null, nowIso(), nowIso(), req.businessId);
      dev = db.prepare('SELECT * FROM devices WHERE id=?').get(id);
      audit('user:' + req.user.id, 'device.registered', id, null, null, { slot, label });
    }
    res.status(201).json({ deviceId: dev.id, slot: dev.slot, invoicePrefix: 'D' + dev.reg_seq, token: issueDevice(req.user, dev), entitlement: entToken(req.businessId, dev.id) });
  }));
  app.get('/api/devices', auth, needBusiness, wrap((req, res) => {
    const rows = db.prepare("SELECT id,slot,label,registered_at,last_seen_at,status FROM devices WHERE business_id=? AND status='active' ORDER BY slot").all(req.businessId);
    res.json({ max: Number(setting('max_devices')), used: rows.length, devices: rows.map(r => ({ ...r, current: req.device?.id === r.id })) });
  }));
  app.delete('/api/devices/:id', auth, needBusiness, wrap((req, res) => {
    const d = db.prepare("SELECT * FROM devices WHERE id=? AND business_id=? AND status='active'").get(req.params.id, req.businessId);
    if (!d) return bad(res, 404, 'Device not found');
    db.prepare("UPDATE devices SET status='removed' WHERE id=?").run(d.id);
    audit('user:' + req.user.id, 'device.removed', d.id, 'Owner removal', d, { status: 'removed' });
    res.json({ ok: true });
  }));
  // Session refresh re-validates device + entitlement server-side (SRS §5)
  app.post('/api/session/refresh', auth, needBusiness, needDevice, wrap((req, res) => {
    res.json({ token: issueDevice(req.user, req.device), entitlement: entToken(req.businessId, req.device.id), subscription: pubEnt(entitlement(db, req.businessId)) });
  }));

  // ───────────────────────── Products ─────────────────────────
  const prodOut = (p) => ({ ...p, available: !!p.available, active: !!p.active, favourite: !!p.favourite, variants: p.variants ? JSON.parse(p.variants) : [] });
  app.get('/api/products', auth, needBusiness, wrap((req, res) => {
    res.json(db.prepare('SELECT * FROM products WHERE business_id=? ORDER BY category,name').all(req.businessId).map(prodOut));
  }));
  const validProduct = (b, partial) => {
    const txt = (k, max) => b[k] == null || (typeof b[k] === 'string' && b[k].length <= max);
    if (!partial && (typeof b.name !== 'string' || !b.name.trim())) return 'name required';
    if (!txt('name', 150) || !txt('category', 80) || !txt('sku', 60) || !txt('description', 500)) return 'text field too long or not text';
    if (b.name !== undefined && !String(b.name).trim()) return 'name cannot be empty';
    if (!partial && !num(b.price, 0, 1e7)) return 'price must be a non-negative number';
    if (partial && b.price !== undefined && !num(b.price, 0, 1e7)) return 'price must be a non-negative number';
    if (b.taxRate !== undefined && !num(b.taxRate, 0, 100)) return 'taxRate must be between 0 and 100';
    if (b.variants !== undefined) {
      if (!Array.isArray(b.variants) || b.variants.length > 30) return 'variants must be a list of up to 30 options';
      for (const v of b.variants) if (!v || typeof v.name !== 'string' || !v.name.trim() || v.name.length > 60 || !num(v.priceDelta ?? 0, -1e6, 1e6) || !['variant', 'addon'].includes(v.kind || 'variant')) return 'each variant needs a name, numeric priceDelta and kind variant|addon';
    }
    return null;
  };
  app.post('/api/products', auth, needBusiness, needPaid, wrap((req, res) => {
    const b = req.body;
    const verr = validProduct(b, false); if (verr) return bad(res, 400, verr);
    const id = newId(db, 'ITM', 'products');
    db.prepare('INSERT INTO products(id,business_id,category,name,sku,description,price,tax_rate,available,favourite,variants,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(id, req.businessId, b.category || null, b.name, b.sku || null, b.description || null, b.price, b.taxRate ?? 0, b.available === false ? 0 : 1, b.favourite ? 1 : 0, JSON.stringify(b.variants || []), nowIso());
    res.status(201).json(prodOut(db.prepare('SELECT * FROM products WHERE id=?').get(id)));
  }));
  app.put('/api/products/:id', auth, needBusiness, needPaid, wrap((req, res) => {
    const p = db.prepare('SELECT * FROM products WHERE id=? AND business_id=?').get(req.params.id, req.businessId);
    if (!p) return bad(res, 404, 'Not found');
    const b = req.body;
    const verr = validProduct(b, true); if (verr) return bad(res, 400, verr);
    db.prepare('UPDATE products SET category=?,name=?,sku=?,description=?,price=?,tax_rate=?,available=?,active=?,favourite=?,variants=?,updated_at=? WHERE id=?').run(
      b.category ?? p.category, b.name ?? p.name, b.sku ?? p.sku, b.description ?? p.description, b.price ?? p.price, b.taxRate ?? p.tax_rate,
      'available' in b ? +!!b.available : p.available, 'active' in b ? +!!b.active : p.active, 'favourite' in b ? +!!b.favourite : p.favourite,
      'variants' in b ? JSON.stringify(b.variants) : p.variants, nowIso(), p.id);
    res.json(prodOut(db.prepare('SELECT * FROM products WHERE id=?').get(p.id)));
  }));

  // ───────────────────────── Bills & sync ─────────────────────────
  const money = (n) => Math.round(n * 100) / 100;
  const METHODS = ['cash', 'upi', 'card'];
  const num = (v, min, max) => typeof v === 'number' && Number.isFinite(v) && v >= min && v <= max;
  // Decides whether a bill with this createdAt may be accepted now. Closes backdating / post-suspension / post-expiry loopholes.
  function billWindowError(bid, device, createdAt, live) {
    const t = Date.parse(createdAt);
    if (Number.isNaN(t)) return 'INVALID_DATE';
    const now = Date.now();
    if (t > now + 5 * 60000) return 'FUTURE_DATE';
    if (t < Date.parse(device.registered_at) - 5 * 60000) return 'BEFORE_DEVICE_REGISTRATION';
    const biz = db.prepare('SELECT suspended_at FROM businesses WHERE id=?').get(bid);
    if (biz.suspended_at && t >= Date.parse(biz.suspended_at)) return 'ACCOUNT_SUSPENDED';
    const grace = (Number(setting('grace_days')) || 0) * DAY;
    const covered = db.prepare("SELECT * FROM subscriptions WHERE business_id=? AND status IN ('active','suspended','revoked') AND start_date IS NOT NULL").all(bid).some(s => {
      let end = Date.parse(s.end_date) + (s.status === 'active' ? grace : 0);
      if (s.disabled_at) end = Math.min(end, Date.parse(s.disabled_at));
      return t >= Date.parse(s.start_date) && t <= end;
    });
    if (!covered) return 'OUTSIDE_SUBSCRIPTION_TERM';
    if (!live.paid) { // not entitled right now: only bills made inside the offline window the server granted this device
      const cutoff = device.entitled_until ? Date.parse(device.entitled_until) : 0;
      if (t > cutoff) return 'SUBSCRIPTION_' + live.status.toUpperCase();
    }
    return null;
  }
  // Idempotent: the same clientTxnId is never stored twice (duplicate prevention for offline sync).
  app.post('/api/bills/sync', auth, needBusiness, needDevice, wrap((req, res) => {
    const list = Array.isArray(req.body.bills) ? req.body.bills : [];
    if (list.length > 200) return bad(res, 400, 'Max 200 bills per sync');
    const live = entitlement(db, req.businessId);
    const results = [];
    for (const b of list) {
      const r = { clientTxnId: b?.clientTxnId };
      try {
        if (!b || typeof b.clientTxnId !== 'string' || b.clientTxnId.length > 64 || typeof b.invoiceNo !== 'string' || b.invoiceNo.length > 40
          || !Array.isArray(b.items) || !b.items.length || b.items.length > 200 || typeof b.createdAt !== 'string') throw new Error('INVALID');
        if (!new RegExp('^D' + req.device.reg_seq + '-[A-Za-z0-9]{1,20}$').test(b.invoiceNo)) throw new Error('INVALID_INVOICE_NO');
        for (const k of ['cashier', 'customerName', 'customerMobile', 'tableNo', 'notes'])
          if (b[k] != null && (typeof b[k] !== 'string' || b[k].length > 300)) throw new Error('INVALID');
        const existing = db.prepare('SELECT * FROM bills WHERE business_id=? AND client_txn_id=?').get(req.businessId, b.clientTxnId);
        if (existing) {
          if (existing.status === 'completed' && ['void', 'refunded'].includes(b.status)) {
            if (!live.paid) throw new Error('SUBSCRIPTION_' + live.status.toUpperCase());
            db.prepare('UPDATE bills SET status=? WHERE id=?').run(b.status, existing.id);
            audit('user:' + req.user.id, 'bill.' + b.status, existing.id, String(b.reason || '').slice(0, 300) || null, { status: 'completed' }, { status: b.status });
            r.result = 'updated';
          } else r.result = 'duplicate';
          r.billId = existing.id; results.push(r); continue;
        }
        if (!['completed', 'void', 'refunded'].includes(b.status)) throw new Error('INVALID_STATUS');
        const werr = billWindowError(req.businessId, req.device, b.createdAt, live);
        if (werr) throw new Error(werr);
        // Server recomputes totals from line items; client totals are never trusted.
        let sub = 0, tax = 0;
        for (const it of b.items) {
          if (!it || typeof it.name !== 'string' || it.name.length > 200 || !num(it.qty, 0.001, 100000) || !num(it.price, 0, 1e7) || !num(it.taxRate ?? 0, 0, 100)) throw new Error('INVALID_ITEM');
          const line = it.qty * it.price; sub += line; tax += line * (it.taxRate || 0) / 100;
        }
        const disc = num(b.discount ?? 0, 0, 1e9) ? Math.min(b.discount ?? 0, sub) : NaN;
        const svc = b.serviceCharge ?? 0;
        if (Number.isNaN(disc) || !num(svc, 0, 1e9)) throw new Error('INVALID_AMOUNT');
        tax = sub > 0 ? tax * ((sub - disc) / sub) : 0;   // discount reduces the taxable value (pro-rata)
        const total = money(sub - disc + tax + svc);
        const pays = Array.isArray(b.payments) ? b.payments : [];
        if (b.status === 'completed') {
          if (!pays.length || pays.length > 5 || pays.some(p => !p || !METHODS.includes(p.method) || !num(p.amount, 0, 1e9))) throw new Error('INVALID_PAYMENT');
          if (Math.abs(pays.reduce((a, p) => a + p.amount, 0) - total) > 0.011) throw new Error('PAYMENT_MISMATCH');
        }
        const id = newId(db, 'BILL', 'bills');
        db.prepare(`INSERT INTO bills(id,client_txn_id,business_id,device_id,invoice_no,status,cashier,customer_name,customer_mobile,table_no,notes,items,subtotal,discount,tax,service_charge,total,payments,created_at,synced_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, b.clientTxnId, req.businessId, req.device.id, b.invoiceNo, b.status, b.cashier || null, b.customerName || null, b.customerMobile || null, b.tableNo || null, b.notes || null,
          JSON.stringify(b.items.map(i => ({ name: i.name, qty: i.qty, price: i.price, taxRate: i.taxRate || 0 }))), money(sub), money(disc), money(tax), money(svc), total, JSON.stringify(pays.map(p => ({ method: p.method, amount: p.amount }))), new Date(b.createdAt).toISOString(), nowIso());
        r.result = 'created'; r.billId = id; r.total = total;
      } catch (e) {
        r.result = 'rejected';
        const m = String(e.message);
        r.reason = /UNIQUE.*invoice_no/i.test(m) ? 'DUPLICATE_INVOICE_NO' : /^[A-Z_]+$/.test(m) ? m : 'INVALID';   // never leak internals
      }
      results.push(r);
    }
    res.json({ results });
  }));
  app.get('/api/bills', auth, needBusiness, wrap((req, res) => {
    const { from, to, status, q, cashier, method, limit = 100 } = req.query;
    let sql = 'SELECT * FROM bills WHERE business_id=?'; const a = [req.businessId];
    if (from) { sql += ' AND created_at>=?'; a.push(from); }
    if (to) { sql += ' AND created_at<=?'; a.push(to); }
    if (status) { sql += ' AND status=?'; a.push(status); }
    if (cashier) { sql += ' AND cashier=?'; a.push(cashier); }
    if (q) { sql += ' AND invoice_no LIKE ?'; a.push(`%${q}%`); }
    if (method) { sql += ' AND payments LIKE ?'; a.push(`%"${String(method).replace(/[^a-zA-Z]/g, '')}"%`); }
    sql += ' ORDER BY created_at DESC LIMIT ?'; a.push(Math.min(+limit || 100, 500));
    res.json(db.prepare(sql).all(...a).map(b => ({ ...b, items: JSON.parse(b.items), payments: JSON.parse(b.payments || '[]') })));
  }));
  app.get('/api/reports/summary', auth, needBusiness, wrap((req, res) => {
    const { from = '0000', to = '9999' } = req.query;
    const rows = db.prepare("SELECT * FROM bills WHERE business_id=? AND status='completed' AND created_at>=? AND created_at<=?").all(req.businessId, from, to);
    const items = {}, byMethod = {}; let total = 0, disc = 0, tax = 0;
    for (const b of rows) {
      total += b.total; disc += b.discount; tax += b.tax;
      for (const p of JSON.parse(b.payments || '[]')) byMethod[p.method] = money((byMethod[p.method] || 0) + p.amount);
      for (const i of JSON.parse(b.items)) { const k = i.name; items[k] = items[k] || { name: k, qty: 0, revenue: 0 }; items[k].qty += i.qty; items[k].revenue = money(items[k].revenue + i.qty * i.price); }
    }
    res.json({ billCount: rows.length, total: money(total), averageBill: rows.length ? money(total / rows.length) : 0, discounts: money(disc), tax: money(tax), byMethod, itemWise: Object.values(items).sort((a, b) => b.revenue - a.revenue) });
  }));
  app.get('/api/reports/export.csv', auth, needBusiness, wrap((req, res) => {
    const rows = db.prepare("SELECT invoice_no,created_at,status,cashier,subtotal,discount,tax,service_charge,total FROM bills WHERE business_id=? ORDER BY created_at").all(req.businessId);
    const esc = (v) => { v = String(v ?? ''); return /^[=+\-@]/.test(v) ? `"'${v}"` : /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v; };
    res.type('text/csv').send(['invoice_no,created_at,status,cashier,subtotal,discount,tax,service_charge,total', ...rows.map(r => Object.values(r).map(esc).join(','))].join('\n'));
  }));

  // ───────────────────────── Misc customer ─────────────────────────
  app.get('/api/notifications', auth, needBusiness, wrap((req, res) => {
    res.json(db.prepare('SELECT * FROM notifications WHERE business_id=? ORDER BY id DESC LIMIT 50').all(req.businessId));
  }));
  app.post('/api/notifications/read-all', auth, needBusiness, wrap((req, res) => { db.prepare('UPDATE notifications SET read=1 WHERE business_id=?').run(req.businessId); res.json({ ok: true }); }));
  app.post('/api/support', auth, needBusiness, wrap((req, res) => {
    const id = newId(db, 'SUP', 'support_requests');
    const sub = String(req.body.subject || '').slice(0, 150), msg = String(req.body.message || '').slice(0, 2000);
    if (!msg.trim()) return bad(res, 400, 'message required');
    db.prepare('INSERT INTO support_requests(id,business_id,subject,message,created_at) VALUES (?,?,?,?,?)').run(id, req.businessId, sub, msg, nowIso());
    res.status(201).json({ id });
  }));
  app.get('/api/app/version', wrap((req, res) => {
    res.json(db.prepare('SELECT version,min_supported,notes,apk_url,created_at FROM releases ORDER BY id DESC LIMIT 1').get() || {});
  }));

  require('./admin')(app, { mailer, alert: opts.alert, db, audit, notify, secEvent, setting, bad, wrap, limit, ADMIN_SECRET, jwt, bcrypt, newId, entitlement, addMonths, nowIso, parseCookies, DAY, createSetupInvite });

  app.use((err, req, res, next) => {
    if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') return res.status(400).json({ error: 'Invalid request body' });
    console.error(err); res.status(500).json({ error: 'Internal error' });
  });
  return app;
}
module.exports = { createApp };

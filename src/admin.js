// Owner-only Super Admin API. Mounted at /admin-api; no registration endpoint exists.
module.exports = function mountAdmin(app, c) {
  const { mailer, alert, db, audit, notify, setting, bad, wrap, limit, ADMIN_SECRET, jwt, bcrypt, entitlement, addMonths, nowIso, parseCookies, newId, DAY, createSetupInvite } = c;
  const express = require('express');
  const r = express.Router();
  const COOKIE = 'sa_session';
  const cookieSecure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  const ip = (req) => req.ip;
  const raise = (msg) => { try { (alert || ((m) => console.warn('[ADMIN ALERT]', m)))(msg); } catch {} };
  const seenIps = new Set();

  const CODE_MIN = 10, MAX_TRIES = 5, COOLDOWN_MS = 30000, MAX_SENDS = 4;
  const crypto = require('crypto');
  const { signInCodeEmail } = require('./mailer');
  const DUMMY = bcrypt.hashSync('not-a-real-password', 10);
  const mask = (e) => e.replace(/^(.)(.*)(@.*)$/, (_, f, m, d) => f + '*'.repeat(Math.min(m.length, 6)) + d);
  const lockIfNeeded = (a, n) => db.prepare('UPDATE admins SET failed_logins=?, locked_until=? WHERE id=?').run(n >= 5 ? 0 : n, n >= 5 ? Date.now() + 15 * 60000 : 0, a.id);
  async function sendCode(a, challengeId, req) {
    const code = String(crypto.randomInt(0, 1e6)).padStart(6, '0');
    db.prepare('UPDATE admin_challenges SET code_hash=?, expires_at=?, attempts=0, last_sent_at=? WHERE id=?').run(bcrypt.hashSync(code, 8), Date.now() + CODE_MIN * 60000, Date.now(), challengeId);
    await mailer.send(signInCodeEmail({ to: a.email, code, minutes: CODE_MIN, ip: ip(req), when: new Date().toUTCString() }));
  }
  const reply = (a, id) => ({ challenge: id, email: mask(a.email), expiresInSec: CODE_MIN * 60, resendAfterSec: COOLDOWN_MS / 1000 });

  // Step 1: email + password. Only if they match is a one-time code emailed to the Super Admin's own address.
  r.post('/login', limit(10), wrap(async (req, res) => {
    const { email, password } = req.body;
    const a = db.prepare('SELECT * FROM admins WHERE email=?').get(String(email || '').toLowerCase());
    const fail = (why) => { audit('anonymous', 'admin.login_failed', email || null, why, null, null, ip(req)); raise(`Failed admin login from ${ip(req)}: ${why}`); return bad(res, 401, 'Invalid email or password'); };
    if (!a) { bcrypt.compareSync(String(password || ''), DUMMY); return fail('unknown email'); }   // constant-ish time: no account enumeration
    if (a.locked_until > Date.now()) return bad(res, 429, 'Too many attempts. Try again in a few minutes.');
    if (!bcrypt.compareSync(String(password || ''), a.password_hash)) { lockIfNeeded(a, a.failed_logins + 1); return fail('wrong password'); }
    db.prepare('DELETE FROM admin_challenges WHERE admin_id=?').run(a.id);                // only the newest code is ever valid
    const id = crypto.randomBytes(16).toString('hex');
    db.prepare('INSERT INTO admin_challenges(id,admin_id,code_hash,expires_at,last_sent_at) VALUES (?,?,?,?,?)').run(id, a.id, '-', 0, 0);
    try { await sendCode(a, id, req); }
    catch (e) { db.prepare('DELETE FROM admin_challenges WHERE id=?').run(id); console.error('Sign-in email failed:', e.message); return bad(res, 502, 'Could not send the sign-in code by email. Check the mail settings and try again.'); }
    audit('admin:' + a.id, 'admin.login_code_sent', a.id, null, null, null, ip(req));
    res.json(reply(a, id));
  }));
  const getChallenge = (id) => { const c = db.prepare('SELECT * FROM admin_challenges WHERE id=?').get(String(id || '')); return c && db.prepare('SELECT * FROM admins WHERE id=?').get(c.admin_id) ? { c, a: db.prepare('SELECT * FROM admins WHERE id=?').get(c.admin_id) } : null; };
  r.post('/login/resend', limit(10), wrap(async (req, res) => {
    const x = getChallenge(req.body.challenge); if (!x) return bad(res, 401, 'Sign-in expired. Start again.');
    if (Date.now() - x.c.last_sent_at < COOLDOWN_MS) return bad(res, 429, 'Please wait a moment before requesting another code.');
    if (x.c.sends >= MAX_SENDS) { db.prepare('DELETE FROM admin_challenges WHERE id=?').run(x.c.id); return bad(res, 429, 'Too many codes requested. Start again.'); }
    db.prepare('UPDATE admin_challenges SET sends=sends+1 WHERE id=?').run(x.c.id);
    try { await sendCode(x.a, x.c.id, req); } catch (e) { return bad(res, 502, 'Could not send the sign-in code by email.'); }
    res.json(reply(x.a, x.c.id));
  }));
  // Step 2: the emailed code. Single use, expires, limited attempts.
  r.post('/login/verify', limit(30), wrap((req, res) => {
    const x = getChallenge(req.body.challenge); if (!x) return bad(res, 401, 'Sign-in expired. Start again.');
    const { c, a } = x; const burn = () => db.prepare('DELETE FROM admin_challenges WHERE id=?').run(c.id);
    if (c.expires_at < Date.now()) { burn(); return bad(res, 401, 'The code has expired. Start again.'); }
    if (a.locked_until > Date.now()) return bad(res, 429, 'Too many attempts. Try again in a few minutes.');
    if (!bcrypt.compareSync(String(req.body.code || '').trim(), c.code_hash)) {
      db.prepare('UPDATE admin_challenges SET attempts=attempts+1 WHERE id=?').run(c.id);
      lockIfNeeded(a, a.failed_logins + 1); audit('anonymous', 'admin.login_failed', a.email, 'wrong emailed code', null, null, ip(req)); raise(`Wrong sign-in code from ${ip(req)}`);
      if (c.attempts + 1 >= MAX_TRIES) { burn(); return bad(res, 401, 'Too many wrong codes. Start again.'); }
      return bad(res, 401, 'Incorrect code');
    }
    burn(); db.prepare('UPDATE admins SET failed_logins=0 WHERE id=?').run(a.id);
    const token = jwt.sign({ sub: a.id, aud: 'admin', n: a.session_nonce }, ADMIN_SECRET, { expiresIn: '30m', algorithm: 'HS256' });
    res.setHeader('Set-Cookie', `${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/admin-api; Max-Age=1800${cookieSecure}`);
    if (!seenIps.has(ip(req))) { seenIps.add(ip(req)); raise(`Super Admin signed in from new address ${ip(req)}`); }
    audit('admin:' + a.id, 'admin.login', a.id, null, null, null, ip(req));
    res.json({ ok: true });
  }));

  r.use((req, res, next) => {
    const tok = parseCookies(req.headers.cookie)[COOKIE];
    let p; try { p = jwt.verify(tok, ADMIN_SECRET, { audience: 'admin', algorithms: ['HS256'] }); } catch { return bad(res, 401, 'Not signed in'); }
    if (!['GET', 'HEAD'].includes(req.method) && req.headers['x-csrf'] !== '1') return bad(res, 403, 'CSRF check failed');
    const a = db.prepare('SELECT id,email,session_nonce FROM admins WHERE id=?').get(p.sub);
    if (!a || a.session_nonce !== p.n) return bad(res, 401, 'Not signed in');
    req.admin = a; req.actor = 'admin:' + a.id; next();
  });
  r.post('/logout', (req, res) => { db.prepare('UPDATE admins SET session_nonce=session_nonce+1 WHERE id=?').run(req.admin.id); audit(req.actor, 'admin.logout', req.admin.id, null, null, null, ip(req)); res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/admin-api${cookieSecure}`); res.json({ ok: true }); });
  r.get('/me', (req, res) => res.json(req.admin));

  const needReason = (req, res) => { const t = String(req.body.reason || '').trim(); if (!t) { bad(res, 400, 'A reason is required'); return null; } return t; };

  // Dashboard — all figures computed from records
  r.get('/dashboard', wrap((req, res) => {
    const { status, type, from, to, payment } = req.query;
    let bizs = db.prepare('SELECT * FROM businesses').all();
    if (payment) { const ids = new Set(db.prepare('SELECT DISTINCT business_id FROM payments WHERE verification_state=?').all(String(payment)).map(x => x.business_id)); bizs = bizs.filter(b => ids.has(b.id)); }
    if (type) bizs = bizs.filter(b => b.type === type);
    if (from) bizs = bizs.filter(b => b.created_at >= from);
    if (to) bizs = bizs.filter(b => b.created_at <= to);
    const counts = { pending: 0, active: 0, expiring_soon: 0, expired: 0, suspended: 0, rejected: 0, none: 0, grace: 0 };
    let shown = 0;
    for (const b of bizs) { const s = entitlement(db, b.id).status; if (status && s !== status) continue; counts[s]++; shown++; }
    const rev = db.prepare("SELECT COALESCE(SUM(amount),0) t FROM payments WHERE verification_state='verified'").get().t;
    res.json({ totalBusinesses: shown, pendingApprovals: counts.pending, activeSubscriptions: counts.active + counts.expiring_soon + counts.grace,
      expiringSoon: counts.expiring_soon, expiredOrSuspended: counts.expired + counts.suspended, rejected: counts.rejected, subscriptionRevenue: rev, byStatus: counts });
  }));

  // Customers
  r.get('/customers', wrap((req, res) => {
    const q = `%${req.query.q || ''}%`;
    const rows = db.prepare(`SELECT b.id business_id,b.name,b.type,b.status account_status,b.created_at,u.id user_id,u.owner_name,u.phone,u.email
      FROM businesses b JOIN users u ON u.id=b.owner_user_id
      WHERE b.id LIKE ? OR u.id LIKE ? OR b.name LIKE ? OR u.owner_name LIKE ? OR u.phone LIKE ? OR u.email LIKE ? ORDER BY b.created_at DESC LIMIT 200`).all(q, q, q, q, q, q);
    audit(req.actor, 'customer.lookup', req.query.q || '*', null, null, null, ip(req));
    res.json(rows.map(x => ({ ...x, subscriptionStatus: entitlement(db, x.business_id).status })));
  }));
  r.get('/customers/:bid', wrap((req, res) => {
    const b = db.prepare('SELECT * FROM businesses WHERE id=?').get(req.params.bid);
    if (!b) return bad(res, 404, 'Not found');
    audit(req.actor, 'customer.view', b.id, null, null, null, ip(req));
    res.json({
      business: b, owner: db.prepare('SELECT id,phone,email,owner_name,status,created_at FROM users WHERE id=?').get(b.owner_user_id),
      subscription: (({ subscription, ...rest }) => rest)(entitlement(db, b.id)),
      subscriptions: db.prepare('SELECT * FROM subscriptions WHERE business_id=? ORDER BY created_at DESC').all(b.id),
      payments: db.prepare('SELECT * FROM payments WHERE business_id=? ORDER BY created_at DESC').all(b.id),
      devices: db.prepare('SELECT * FROM devices WHERE business_id=? ORDER BY registered_at DESC').all(b.id),
      timeline: db.prepare('SELECT action,actor,reason,created_at FROM audit_events WHERE target IN (?,?) OR target IN (SELECT id FROM subscriptions WHERE business_id=?) OR target IN (SELECT id FROM devices WHERE business_id=?) ORDER BY id DESC LIMIT 100').all(b.id, b.owner_user_id, b.id, b.id) });
  }));
  r.put('/customers/:bid', wrap((req, res) => {
    const reason = needReason(req, res); if (!reason) return;
    const b = db.prepare('SELECT * FROM businesses WHERE id=?').get(req.params.bid); if (!b) return bad(res, 404, 'Not found');
    const allowed = ['name', 'type', 'address', 'contact', 'gstin'];
    const sets = allowed.filter(k => k in req.body);
    if (!sets.length) return bad(res, 400, 'Nothing to update');
    if ('contact' in req.body) {
      req.body.contact = String(req.body.contact || '').trim().replace(/[ ()-]/g, '');
      if (!/^(?:\d{10}|\+[1-9]\d{9,14})$/.test(req.body.contact)) return bad(res, 400, 'Enter a valid contact phone number.');
    }
    db.prepare(`UPDATE businesses SET ${sets.map(k => k + '=?').join(',')} WHERE id=?`).run(...sets.map(k => req.body[k]), b.id);
    if ('contact' in req.body) db.prepare('UPDATE users SET phone=? WHERE id=?').run(req.body.contact, b.owner_user_id);
    audit(req.actor, 'customer.updated', b.id, reason, b, req.body, ip(req));
    res.json({ ok: true });
  }));
  r.post('/customers/:bid/setup-invite', wrap(async (req, res) => {
    const b = db.prepare('SELECT id,owner_user_id FROM businesses WHERE id=?').get(req.params.bid);
    if (!b) return bad(res, 404, 'Not found');
    if (db.prepare('SELECT password_hash FROM users WHERE id=?').get(b.owner_user_id)?.password_hash) return bad(res, 409, 'This customer already has email sign-in enabled.');
    try {
      const result = await createSetupInvite(b.owner_user_id, req.body.email, req);
      audit(req.actor, 'customer.setup_invite_sent', b.id, null, null, { email: req.body.email }, ip(req));
      res.json(result);
    } catch (e) { return bad(res, e.status || 500, e.message || 'Could not send setup invite.'); }
  }));
  for (const [path, to, label] of [['suspend', 'suspended', 'account.suspended'], ['reinstate', 'active', 'account.reinstated']]) {
    r.post(`/customers/:bid/${path}`, wrap((req, res) => {
      const reason = needReason(req, res); if (!reason) return;
      const b = db.prepare('SELECT * FROM businesses WHERE id=?').get(req.params.bid); if (!b) return bad(res, 404, 'Not found');
      db.prepare('UPDATE businesses SET status=?, suspended_at=? WHERE id=?').run(to, to === 'suspended' ? nowIso() : null, b.id);
      audit(req.actor, label, b.id, reason, { status: b.status }, { status: to }, ip(req));
      notify(b.id, 'Account ' + (to === 'suspended' ? 'suspended' : 'reinstated'), reason);
      res.json({ ok: true });
    }));
  }

  // Approvals queue & subscription actions
  r.get('/approvals', wrap((req, res) => {
    res.json(db.prepare(`SELECT s.id subscription_id,s.plan,s.amount,s.created_at,s.admin_message,b.id business_id,b.name business_name,u.owner_name,u.phone,u.email,
      p.id payment_id,p.amount paid_amount,p.method,p.provider_ref,p.evidence,p.verification_state
      FROM subscriptions s JOIN businesses b ON b.id=s.business_id JOIN users u ON u.id=b.owner_user_id
      LEFT JOIN payments p ON p.subscription_id=s.id WHERE s.status='pending' ORDER BY s.created_at`).all());
  }));
  const getSub = (req, res) => { const s = db.prepare('SELECT * FROM subscriptions WHERE id=?').get(req.params.id); if (!s) bad(res, 404, 'Not found'); return s; };
  r.post('/subscriptions/:id/verify-payment', wrap((req, res) => {
    const s = getSub(req, res); if (!s) return;
    const p = db.prepare('SELECT * FROM payments WHERE subscription_id=?').get(s.id);
    if (!p) return bad(res, 409, 'No payment recorded');
    db.prepare("UPDATE payments SET verification_state='verified' WHERE id=?").run(p.id);
    audit(req.actor, 'payment.verified', p.id, req.body.note || 'Verified against gateway/bank record', { state: p.verification_state }, { state: 'verified' }, ip(req));
    res.json({ ok: true });
  }));
  r.post('/subscriptions/:id/approve', wrap((req, res) => {
    const s = getSub(req, res); if (!s) return;
    if (s.status !== 'pending') return bad(res, 409, 'Only pending requests can be approved');
    if (db.prepare('SELECT status FROM businesses WHERE id=?').get(s.business_id).status === 'suspended') return bad(res, 409, 'Account is suspended; reinstate it before approving');
    const p = db.prepare('SELECT * FROM payments WHERE subscription_id=?').get(s.id);
    if (!p || p.verification_state !== 'verified') return bad(res, 409, 'Verify the payment before approving (screenshots alone are not proof)');
    const price = Number(setting('plan_price'));
    if (price > 0 && !(p.amount >= price) && !String(req.body.overrideReason || '').trim()) return bad(res, 409, `Amount paid (${p.amount ?? 'unknown'}) is below the plan price (${price}). Provide overrideReason to approve anyway.`, { code: 'AMOUNT_BELOW_PRICE' });
    const months = Number(setting('plan_months'));
    const now = nowIso();
    // Renewal extends from the current term's end; first activation starts at approval time.
    const cur = db.prepare("SELECT MAX(end_date) e FROM subscriptions WHERE business_id=? AND status='active'").get(s.business_id).e;
    const start = cur && cur > now ? cur : now;
    const end = addMonths(start, months);
    db.prepare("UPDATE subscriptions SET status='active', start_date=?, end_date=?, approved_by=?, approved_at=?, admin_message=? WHERE id=?").run(start, end, req.admin.id, now, req.body.message || null, s.id);
    audit(req.actor, 'subscription.approved', s.id, req.body.overrideReason || req.body.reason || null, { status: 'pending' }, { status: 'active', start, end, paymentRef: p.provider_ref }, ip(req));
    notify(s.business_id, 'Subscription approved', `Active until ${end.slice(0, 10)}`);
    res.json({ ok: true, startDate: start, endDate: end });
  }));
  r.post('/subscriptions/:id/reject', wrap((req, res) => {
    const reason = needReason(req, res); if (!reason) return;
    const s = getSub(req, res); if (!s) return;
    if (s.status !== 'pending') return bad(res, 409, 'Only pending requests can be rejected');
    db.prepare("UPDATE subscriptions SET status='rejected', admin_message=? WHERE id=?").run(reason, s.id);
    db.prepare("UPDATE payments SET verification_state='rejected' WHERE subscription_id=?").run(s.id);
    audit(req.actor, 'subscription.rejected', s.id, reason, { status: 'pending' }, { status: 'rejected' }, ip(req));
    notify(s.business_id, 'Subscription request rejected', reason);
    res.json({ ok: true });
  }));
  r.post('/subscriptions/:id/clarify', wrap((req, res) => {
    const s = getSub(req, res); if (!s) return;
    const msg = String(req.body.message || '').trim(); if (!msg) return bad(res, 400, 'message required');
    db.prepare('UPDATE subscriptions SET admin_message=? WHERE id=?').run(msg, s.id);
    audit(req.actor, 'subscription.clarification_requested', s.id, msg, null, null, ip(req));
    notify(s.business_id, 'More information needed', msg);
    res.json({ ok: true });
  }));
  const transition = (name, from, to) => r.post(`/subscriptions/:id/${name}`, wrap((req, res) => {
    const reason = needReason(req, res); if (!reason) return;
    const s = getSub(req, res); if (!s) return;
    if (!from.includes(s.status)) return bad(res, 409, `Cannot ${name} a ${s.status} subscription`);
    db.prepare('UPDATE subscriptions SET status=?, admin_message=?, disabled_at=? WHERE id=?').run(to, reason, to === 'active' ? null : (s.disabled_at || nowIso()), s.id);
    audit(req.actor, `subscription.${{ suspend: 'suspended', reinstate: 'reinstated', revoke: 'revoked' }[name]}`, s.id, reason, { status: s.status }, { status: to }, ip(req));
    notify(s.business_id, `Subscription ${to}`, reason);
    res.json({ ok: true });
  }));
  transition('suspend', ['active'], 'suspended');
  transition('reinstate', ['suspended'], 'active');
  transition('revoke', ['active', 'suspended', 'pending'], 'revoked');
  r.put('/subscriptions/:id/dates', wrap((req, res) => { // manual override, always audited with reason
    const reason = needReason(req, res); if (!reason) return;
    const s = getSub(req, res); if (!s) return;
    const { startDate, endDate } = req.body;
    if (!startDate || !endDate || isNaN(Date.parse(startDate)) || isNaN(Date.parse(endDate)) || endDate <= startDate) return bad(res, 400, 'Valid startDate < endDate required');
    db.prepare('UPDATE subscriptions SET start_date=?, end_date=? WHERE id=?').run(startDate, endDate, s.id);
    audit(req.actor, 'subscription.dates_overridden', s.id, reason, { start: s.start_date, end: s.end_date }, { start: startDate, end: endDate }, ip(req));
    res.json({ ok: true });
  }));

  // Devices
  r.get('/devices', wrap((req, res) => {
    res.json(db.prepare(`SELECT d.*,b.name business_name FROM devices d JOIN businesses b ON b.id=d.business_id ${req.query.business_id ? 'WHERE d.business_id=?' : ''} ORDER BY d.registered_at DESC LIMIT 500`).all(...(req.query.business_id ? [req.query.business_id] : [])));
  }));
  r.post('/devices/:id/revoke', wrap((req, res) => {
    const reason = needReason(req, res); if (!reason) return;
    const d = db.prepare("SELECT * FROM devices WHERE id=? AND status='active'").get(req.params.id);
    if (!d) return bad(res, 404, 'Active device not found');
    db.prepare("UPDATE devices SET status='revoked', revoked_reason=? WHERE id=?").run(reason, d.id);
    audit(req.actor, 'device.revoked', d.id, reason, { status: 'active' }, { status: 'revoked' }, ip(req));
    notify(d.business_id, 'Device revoked', `${d.label || d.id}: ${reason}`);
    res.json({ ok: true });
  }));
  r.get('/security-events', wrap((req, res) => res.json(db.prepare('SELECT * FROM security_events ORDER BY id DESC LIMIT 200').all())));

  // App releases, support, settings, audit, exports
  r.get('/releases', (req, res) => res.json(db.prepare('SELECT * FROM releases ORDER BY id DESC').all()));
  r.post('/releases', wrap((req, res) => {
    const { version, minSupported, notes, apkUrl } = req.body;
    if (!version) return bad(res, 400, 'version required');
    db.prepare('INSERT INTO releases(version,min_supported,notes,apk_url,created_at) VALUES (?,?,?,?,?)').run(version, minSupported || 0, notes || '', apkUrl || '', nowIso());
    audit(req.actor, 'release.published', version, null, null, { minSupported }, ip(req));
    res.status(201).json({ ok: true });
  }));
  r.get('/support', (req, res) => res.json(db.prepare('SELECT s.*,b.name business_name FROM support_requests s JOIN businesses b ON b.id=s.business_id ORDER BY s.created_at DESC LIMIT 200').all()));
  r.post('/support/:id/resolve', wrap((req, res) => { db.prepare("UPDATE support_requests SET status='resolved' WHERE id=?").run(req.params.id); audit(req.actor, 'support.resolved', req.params.id, null, null, null, ip(req)); res.json({ ok: true }); }));
  r.get('/settings', (req, res) => res.json(Object.fromEntries(db.prepare('SELECT key,value FROM settings').all().map(x => [x.key, x.value]))));
  r.put('/settings', wrap((req, res) => {
    const allowed = ['plan_months', 'reminder_days', 'max_devices', 'grace_days', 'offline_window_hours', 'plan_price', 'payment_instructions', 'support_contact', 'receipt_footer_default'];
    const numeric = ['plan_months', 'max_devices', 'grace_days', 'offline_window_hours', 'plan_price'];
    for (const [k, v] of Object.entries(req.body)) {
      if (!allowed.includes(k)) return bad(res, 400, 'Unknown setting ' + k);
      if (numeric.includes(k) && !(Number.isFinite(Number(v)) && Number(v) >= 0 && String(v).trim() !== '')) return bad(res, 400, k + ' must be a non-negative number');
      if (k === 'plan_months' && !(Number(v) >= 1)) return bad(res, 400, 'plan_months must be at least 1');
      if (k === 'max_devices' && !(Number(v) >= 1 && Number(v) <= 20)) return bad(res, 400, 'max_devices must be 1-20');
      if (k === 'reminder_days' && !/^\d+(,\d+)*$/.test(String(v))) return bad(res, 400, 'reminder_days must look like 30,15,7,1');
      if (String(v).length > 1000) return bad(res, 400, k + ' too long');
      const old = setting(k);
      db.prepare('UPDATE settings SET value=? WHERE key=?').run(String(v), k);
      audit(req.actor, 'settings.changed', k, null, { value: old }, { value: String(v) }, ip(req));
    }
    res.json({ ok: true });
  }));
  r.get('/audit', (req, res) => res.json(db.prepare('SELECT * FROM audit_events ORDER BY id DESC LIMIT ?').all(Math.min(+req.query.limit || 200, 1000))));
  r.get('/export/subscriptions.csv', wrap((req, res) => {
    const rows = db.prepare(`SELECT s.id,s.business_id,b.name,u.owner_name,u.phone,u.email,s.plan,s.amount,s.status,s.start_date,s.end_date,s.approved_by,s.approved_at
      FROM subscriptions s JOIN businesses b ON b.id=s.business_id JOIN users u ON u.id=b.owner_user_id ORDER BY s.created_at`).all();
    const esc = (v) => { v = String(v ?? ''); return /^[=+\-@]/.test(v) ? `"'${v}"` : /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v; };
    audit(req.actor, 'export.subscriptions', null, null, null, null, ip(req));
    res.type('text/csv').send(['id,business_id,name,owner_name,phone,email,plan,amount,status,start_date,end_date,approved_by,approved_at', ...rows.map(x => Object.values(x).map(esc).join(','))].join('\n'));
  }));

  app.use('/admin-api', r);
};

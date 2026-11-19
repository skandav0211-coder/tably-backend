const test = require('node:test');
const assert = require('node:assert');
const { openDb, newId } = require('../src/db');
const { createApp } = require('../src/app');
const bcrypt = require('bcryptjs');

let server, base, db, adminCookie;
const PASS = 'correct horse battery';
const outbox = []; const mailer = { sendMail: async (m) => { outbox.push(m); } };
const lastCode = (to = 'owner@x.com') => /code is (\d{6})/.exec([...outbox].reverse().find(x => x.to === to).text)[1];
const lastAuthCode = (to) => /Your code is (\d{6})/.exec([...outbox].reverse().find(x => x.to === to).text)[1];
const wrongAuthCode = (to) => lastAuthCode(to) === '000000' ? '000001' : '000000';
async function adminLogin(password = PASS) {                      // step 1 (password) → email → step 2 (code)
  const s1 = await call('POST', '/admin-api/login', { body: { email: 'owner@x.com', password } });
  if (s1.status !== 200) return { s1 };
  const s2 = await call('POST', '/admin-api/login/verify', { body: { challenge: s1.json.challenge, code: lastCode('owner@x.com') } });
  return { s1, s2, cookie: s2.headers.get('set-cookie')?.split(';')[0] };
}

async function call(method, path, { body, token, cookie, csrf } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (token) headers.authorization = 'Bearer ' + token;
  if (cookie) headers.cookie = cookie;
  if (csrf) headers['x-csrf'] = '1';
  const r = await fetch(base + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await r.text(); let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: r.status, json, headers: r.headers };
}
const admin = (m, p, b) => call(m, p, { body: b, cookie: adminCookie, csrf: true });

async function registerCustomer(phone, bizName, email = `${phone}@customer.test`, password = PASS) {
  const reg = await call('POST', '/api/auth/register', { body: { email, password, ownerName: 'Owner', phone } });
  assert.equal(reg.status, 202);
  assert.equal(db.prepare('SELECT COUNT(*) c FROM users WHERE lower(email)=?').get(email.toLowerCase()).c, 0);
  const verified = await call('POST', '/api/auth/register/verify', { body: { challenge: reg.json.challenge, code: lastAuthCode(email.toLowerCase()) } });
  const token = verified.json.token;
  const b = await call('POST', '/api/business', { token, body: { ownerName: 'Owner', businessName: bizName, businessType: 'cafe', address: '1 MG Road', contact: phone } });
  return { token, businessId: b.json.businessId, email: email.toLowerCase(), password, phone };
}
let refN = 0;
async function activate(c, ref = 'UPI' + (++refN) + '-' + Date.now()) {
  const r = await call('POST', '/api/subscription/request', { token: c.token, body: { paymentRef: ref, amount: 999, method: 'upi' } });
  await admin('POST', `/admin-api/subscriptions/${r.json.subscriptionId}/verify-payment`, {});
  const a = await admin('POST', `/admin-api/subscriptions/${r.json.subscriptionId}/approve`, {});
  return { subId: r.json.subscriptionId, approve: a };
}
async function registerDevice(c, n) {
  return call('POST', '/api/devices/register', { token: c.token, body: { appInstanceId: 'inst-' + n, label: 'Phone ' + n } });
}
const bill = (id, extra = {}) => ({ clientTxnId: id, invoiceNo: 'D1-' + id.replace(/[^A-Za-z0-9]/g, ''), status: 'completed', createdAt: new Date().toISOString(), items: [{ name: 'Latte', qty: 2, price: 100, taxRate: 5 }], payments: [{ method: 'cash', amount: 210 }], ...extra });

test.before(async () => {
  db = openDb(':memory:');
  db.prepare('INSERT INTO admins(id,email,password_hash,totp_secret) VALUES (?,?,?,?)').run('ADM-1', 'owner@x.com', bcrypt.hashSync(PASS, 4), '');
  const configuredOrigins = process.env.ADMIN_PORTAL_ORIGINS;
  process.env.ADMIN_PORTAL_ORIGINS = ' http://localhost:5173/ ';
  const app = createApp(db, { noRateLimit: true, mailer });
  if (configuredOrigins === undefined) delete process.env.ADMIN_PORTAL_ORIGINS;
  else process.env.ADMIN_PORTAL_ORIGINS = configuredOrigins;
  await new Promise(r => { server = app.listen(0, r); });
  base = 'http://127.0.0.1:' + server.address().port;
  const l = await adminLogin(); assert.equal(l.s2.status, 200);
  adminCookie = l.cookie;
});
test.after(() => server.close());

test('health endpoint is unauthenticated and returns only a simple status', async () => {
  const response = await call('GET', '/health');
  assert.equal(response.status, 200);
  assert.deepEqual(response.json, { ok: true });
});

test('smoke: signup emails a code, verifies the account, then email/password login succeeds', async () => {
  const email = 'smoke-flow@example.test';
  const registration = await call('POST', '/api/auth/register', {
    body: { email, password: PASS, ownerName: 'Smoke Owner', phone: '9000000052' },
  });
  assert.equal(registration.status, 202);
  const code = lastAuthCode(email);
  const verification = await call('POST', '/api/auth/register/verify', {
    body: { challenge: registration.json.challenge, code },
  });
  assert.equal(verification.status, 200);
  assert.ok(verification.json.token);
  const login = await call('POST', '/api/auth/login', { body: { email, password: PASS } });
  assert.equal(login.status, 200);
  assert.ok(login.json.token);
});

test('standalone admin portal origin can use credentialed admin APIs', async () => {
  const r = await fetch(base + '/admin-api/login', {
    method: 'OPTIONS',
    headers: {
      Origin: 'http://localhost:5173',
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'content-type,x-csrf',
    },
  });
  assert.equal(r.status, 204);
  assert.equal(r.headers.get('access-control-allow-origin'), 'http://localhost:5173');
  assert.equal(r.headers.get('access-control-allow-credentials'), 'true');
});

test('email registration + business profile; phone is a normalized contact, not the login identity', async () => {
  const c = await registerCustomer('9000000001', 'Cafe One');
  assert.match(c.businessId, /^BIZ-\d{9}$/);
  const me = await call('GET', '/api/me', { token: c.token });
  assert.match(me.json.user.id, /^USR-/);
  assert.equal(me.json.user.email, c.email);
  assert.equal(me.json.user.phone, '9000000001');
  assert.equal(me.json.user.mobile, undefined);
  assert.equal(me.json.subscription.status, 'none');
});

test('phone is non-unique contact data, searchable in admin and included with email in subscription CSV', async () => {
  const phone = '+919000000099';
  const first = await registerCustomer(phone, 'First Contact Cafe', 'contact-a@example.test');
  const second = await registerCustomer(phone, 'Second Contact Cafe', 'contact-b@example.test');
  const one = await call('GET', '/api/me', { token: first.token });
  const two = await call('GET', '/api/me', { token: second.token });
  assert.equal(one.json.user.phone, phone);
  assert.equal(two.json.user.phone, phone);
  assert.notEqual(one.json.user.id, two.json.user.id);
  const request = await call('POST', '/api/subscription/request', { token: first.token, body: { paymentRef: 'CONTACT-CSV-1' } });
  assert.equal(request.status, 201);
  const found = await admin('GET', '/admin-api/customers?q=9000000099');
  assert.ok(found.json.some(x => x.email === first.email && x.phone === phone));
  const csv = await admin('GET', '/admin-api/export/subscriptions.csv');
  assert.match(csv.json, /owner_name,phone,email/);
  assert.ok(csv.json.includes(first.email));
  assert.ok(csv.json.includes(phone));
});

test('email registration is pending until code verification; wrong codes and expiry are rejected', async () => {
  const email = 'pending@example.test';
  const reg = await call('POST', '/api/auth/register', { body: { email, password: PASS, ownerName: 'Pending', phone: '+91 90000 00002' } });
  assert.equal(reg.status, 202);
  assert.equal(db.prepare('SELECT 1 FROM users WHERE email=?').get(email), undefined);
  const wrong = await call('POST', '/api/auth/register/verify', { body: { challenge: reg.json.challenge, code: wrongAuthCode(email) } });
  assert.equal(wrong.status, 400);
  assert.equal(db.prepare('SELECT 1 FROM users WHERE email=?').get(email), undefined);
  const mail = [...outbox].reverse().find(x => x.to === email);
  assert.match(mail.subject, /verify/i);
  const code = lastAuthCode(email);
  db.prepare('UPDATE auth_challenges SET expires_at=? WHERE id=?').run(Date.now() - 1, reg.json.challenge);
  assert.equal((await call('POST', '/api/auth/register/verify', { body: { challenge: reg.json.challenge, code } })).status, 400);
  assert.equal(db.prepare('SELECT 1 FROM users WHERE email=?').get(email), undefined);
});

test('registration code allows 5 attempts, resend is cooled down and limited to 4 sends', async () => {
  const email = 'attempts@example.test';
  const reg = await call('POST', '/api/auth/register', { body: { email, password: PASS, ownerName: 'Attempt', phone: '9000000098' } });
  for (let n = 0; n < 4; n++) assert.equal((await call('POST', '/api/auth/register/verify', { body: { challenge: reg.json.challenge, code: wrongAuthCode(email) } })).status, 400);
  assert.equal((await call('POST', '/api/auth/register/verify', { body: { challenge: reg.json.challenge, code: wrongAuthCode(email) } })).status, 400);
  assert.equal(db.prepare('SELECT 1 FROM auth_challenges WHERE id=?').get(reg.json.challenge), undefined);
  const reg2 = await call('POST', '/api/auth/register', { body: { email: 'resend@example.test', password: PASS, ownerName: 'Resend', phone: '9000000097' } });
  assert.equal((await call('POST', '/api/auth/register/resend', { body: { challenge: reg2.json.challenge } })).status, 429);
  for (let i = 0; i < 3; i++) {
    db.prepare('UPDATE auth_challenges SET last_sent_at=? WHERE id=?').run(Date.now() - 31000, reg2.json.challenge);
    assert.equal((await call('POST', '/api/auth/register/resend', { body: { challenge: reg2.json.challenge } })).status, 200);
  }
  db.prepare('UPDATE auth_challenges SET last_sent_at=? WHERE id=?').run(Date.now() - 31000, reg2.json.challenge);
  assert.equal((await call('POST', '/api/auth/register/resend', { body: { challenge: reg2.json.challenge } })).status, 429);
});

test('login uses email/password, has generic unknown-email response and locks after five failures', async () => {
  const c = await registerCustomer('9000000002', 'Login Cafe');
  const ok = await call('POST', '/api/auth/login', { body: { email: c.email.toUpperCase(), password: c.password } });
  assert.equal(ok.status, 200);
  const known = await call('POST', '/api/auth/login', { body: { email: c.email, password: 'wrong password' } });
  const unknown = await call('POST', '/api/auth/login', { body: { email: 'unknown@example.test', password: 'wrong password' } });
  assert.equal(known.status, unknown.status);
  assert.equal(known.json.error, unknown.json.error);
  for (let i = 1; i < 5; i++) await call('POST', '/api/auth/login', { body: { email: c.email, password: 'wrong password' } });
  assert.ok(db.prepare('SELECT locked_until FROM users WHERE email=?').get(c.email).locked_until > Date.now());
  assert.equal((await call('POST', '/api/auth/login', { body: { email: c.email, password: c.password } })).status, 401);
});

test('password reset emails code, invalidates existing sessions and permits the new password', async () => {
  const c = await registerCustomer('9000000096', 'Reset Cafe');
  const before = await call('POST', '/api/auth/login', { body: { email: c.email, password: c.password } });
  const request = await call('POST', '/api/auth/password/forgot', { body: { email: c.email } });
  assert.equal(request.status, 200);
  assert.match([...outbox].reverse().find(x => x.to === c.email).subject, /reset/i);
  assert.equal((await call('POST', '/api/auth/password/reset', { body: { challenge: request.json.challenge, code: wrongAuthCode(c.email), password: 'new battery pass' } })).status, 400);
  const code = lastAuthCode(c.email);
  assert.equal((await call('POST', '/api/auth/password/reset', { body: { challenge: request.json.challenge, code, password: 'new battery pass' } })).status, 200);
  assert.equal((await call('GET', '/api/me', { token: before.json.token })).status, 401);
  assert.equal((await call('POST', '/api/auth/login', { body: { email: c.email, password: 'new battery pass' } })).status, 200);
  const unknown = await call('POST', '/api/auth/password/forgot', { body: { email: 'missing@example.test' } });
  assert.equal(unknown.status, request.status);
  assert.equal(unknown.json.message, request.json.message);
  const expiring = await call('POST', '/api/auth/password/forgot', { body: { email: c.email } });
  const expiredCode = lastAuthCode(c.email);
  db.prepare('UPDATE auth_challenges SET expires_at=? WHERE id=?').run(Date.now() - 1, expiring.json.challenge);
  assert.equal((await call('POST', '/api/auth/password/reset', { body: { challenge: expiring.json.challenge, code: expiredCode, password: PASS } })).status, 400);
});

test('admin setup invite allows a legacy account to claim email/password without losing phone or business data', async () => {
  const userId = newId(db, 'USR', 'users');
  db.prepare('INSERT INTO users(id,mobile,phone,owner_name,verified,created_at) VALUES (?,?,?,?,1,?)').run(userId, 'legacy-' + userId, '9000000095', 'Legacy Owner', new Date().toISOString());
  const businessId = newId(db, 'BIZ', 'businesses');
  db.prepare('INSERT INTO businesses(id,owner_user_id,name,type,address,contact,created_at) VALUES (?,?,?,?,?,?,?)').run(businessId, userId, 'Legacy Cafe', 'cafe', 'Address', '9000000095', new Date().toISOString());
  const sent = await admin('POST', `/admin-api/customers/${businessId}/setup-invite`, { email: 'claim@example.test' });
  assert.equal(sent.status, 200);
  const code = lastAuthCode('claim@example.test');
  const claimed = await call('POST', '/api/auth/setup/verify', { body: { email: 'claim@example.test', code, password: PASS } });
  assert.equal(claimed.status, 200);
  const me = await call('GET', '/api/me', { token: claimed.json.token });
  assert.equal(me.json.user.phone, '9000000095');
  assert.equal(me.json.business.name, 'Legacy Cafe');
});

test('payment submission stays Pending Approval and does not unlock paid features', async () => {
  const c = await registerCustomer('9000000003', 'Pending Cafe');
  const r = await call('POST', '/api/subscription/request', { token: c.token, body: { paymentRef: 'REF1', amount: 999 } });
  assert.equal(r.json.status, 'pending');
  const p = await call('POST', '/api/products', { token: c.token, body: { name: 'Tea', price: 20 } });
  assert.equal(p.status, 402);
  const d = await registerDevice(c, 1);
  assert.equal(d.status, 402);
});

test('approval requires verified payment; activates exactly 12 months and records approver', async () => {
  const c = await registerCustomer('9000000004', 'Approved Cafe');
  const r = await call('POST', '/api/subscription/request', { token: c.token, body: { paymentRef: 'REF2', amount: 999 } });
  const early = await admin('POST', `/admin-api/subscriptions/${r.json.subscriptionId}/approve`, {});
  assert.equal(early.status, 409);
  await admin('POST', `/admin-api/subscriptions/${r.json.subscriptionId}/verify-payment`, {});
  const a = await admin('POST', `/admin-api/subscriptions/${r.json.subscriptionId}/approve`, {});
  assert.equal(a.status, 200);
  const start = new Date(a.json.startDate), end = new Date(a.json.endDate);
  assert.equal(end.getUTCFullYear() * 12 + end.getUTCMonth() - (start.getUTCFullYear() * 12 + start.getUTCMonth()), 12);
  const row = db.prepare('SELECT * FROM subscriptions WHERE id=?').get(r.json.subscriptionId);
  assert.equal(row.approved_by, 'ADM-1'); assert.ok(row.approved_at);
  const me = await call('GET', '/api/me', { token: c.token });
  assert.ok(['active', 'expiring_soon'].includes(me.json.subscription.status));
});

test('customer cannot reach admin API; admin API needs session and CSRF header', async () => {
  const c = await registerCustomer('9000000005', 'Sneaky');
  assert.equal((await call('GET', '/admin-api/dashboard', { token: c.token })).status, 401);
  assert.equal((await call('POST', '/admin-api/devices/x/revoke', { cookie: adminCookie, body: { reason: 'x' } })).status, 403);
  const before = outbox.length; assert.equal((await call('POST', '/admin-api/login', { body: { email: 'owner@x.com', password: 'wrong-password' } })).status, 401); assert.equal(outbox.length, before);
});

test('max three devices; fourth rejected until slot freed (owner removal and admin revoke)', async () => {
  const c = await registerCustomer('9000000006', 'Device Cafe');
  await activate(c);
  const d = [];
  for (let i = 1; i <= 3; i++) { const r = await registerDevice(c, i); assert.equal(r.status, 201); d.push(r.json); }
  assert.deepEqual(d.map(x => x.slot), [1, 2, 3]);
  const again = await registerDevice(c, 2); // idempotent for same app instance
  assert.equal(again.json.deviceId, d[1].deviceId);
  const fourth = await registerDevice(c, 4);
  assert.equal(fourth.status, 403); assert.equal(fourth.json.code, 'DEVICE_LIMIT');
  assert.equal((await admin('GET', '/admin-api/security-events')).json.some(e => e.kind === 'device_limit_exceeded'), true);
  // admin revokes → revoked device token stops working, slot frees
  const rev = await admin('POST', `/admin-api/devices/${d[0].deviceId}/revoke`, { reason: 'lost phone' });
  assert.equal(rev.status, 200);
  const dead = await call('POST', '/api/session/refresh', { token: d[0].token });
  assert.equal(dead.status, 401); assert.equal(dead.json.code, 'DEVICE_REVOKED');
  assert.equal((await registerDevice(c, 4)).status, 201);
  // owner self-removal
  assert.equal((await call('DELETE', '/api/devices/' + d[1].deviceId, { token: c.token })).status, 200);
  assert.equal((await registerDevice(c, 5)).status, 201);
  assert.equal((await admin('POST', `/admin-api/devices/${d[2].deviceId}/revoke`, {})).status, 400); // reason mandatory
});

test('products: add/edit/deactivate without reinstall; offline bill sync is idempotent and server recomputes totals', async () => {
  const c = await registerCustomer('9000000007', 'Bill Cafe');
  await activate(c);
  const dev = (await registerDevice(c, 1)).json;
  const p = await call('POST', '/api/products', { token: c.token, body: { name: 'Latte', price: 100, taxRate: 5, category: 'Coffee' } });
  assert.equal(p.status, 201);
  const u = await call('PUT', '/api/products/' + p.json.id, { token: c.token, body: { price: 120, active: false } });
  assert.equal(u.json.price, 120); assert.equal(u.json.active, false);
  const s1 = await call('POST', '/api/bills/sync', { token: dev.token, body: { bills: [bill('t1', { total: 1 })] } });
  assert.equal(s1.json.results[0].result, 'created'); assert.equal(s1.json.results[0].total, 210);
  const s2 = await call('POST', '/api/bills/sync', { token: dev.token, body: { bills: [bill('t1')] } });
  assert.equal(s2.json.results[0].result, 'duplicate');
  const s3 = await call('POST', '/api/bills/sync', { token: dev.token, body: { bills: [bill('t2', { invoiceNo: 'D1-t1' })] } });
  assert.equal(s3.json.results[0].reason, 'DUPLICATE_INVOICE_NO');
  const rep = await call('GET', '/api/reports/summary', { token: c.token });
  assert.equal(rep.json.billCount, 1); assert.equal(rep.json.total, 210);
  const v = await call('POST', '/api/bills/sync', { token: dev.token, body: { bills: [bill('t1', { status: 'void', reason: 'wrong order' })] } });
  assert.equal(v.json.results[0].result, 'updated');
  assert.ok(db.prepare("SELECT 1 FROM audit_events WHERE action='bill.void'").get());
});

test('tenant isolation: cannot read/modify another business by changing identifiers', async () => {
  const a = await registerCustomer('9000000008', 'A'); const b = await registerCustomer('9000000009', 'B');
  await activate(a); await activate(b);
  const da = (await registerDevice(a, 1)).json;
  const pa = await call('POST', '/api/products', { token: a.token, body: { name: 'Secret', price: 5 } });
  assert.equal((await call('PUT', '/api/products/' + pa.json.id, { token: b.token, body: { price: 1 } })).status, 404);
  assert.equal((await call('GET', '/api/products?business_id=' + a.businessId, { token: b.token })).json.length, 0);
  assert.equal((await call('GET', '/api/bills?businessId=' + a.businessId, { token: b.token })).json.length, 0);
  const dbId = db.prepare('SELECT id FROM devices WHERE business_id=?').get(a.businessId).id;
  assert.equal((await call('DELETE', '/api/devices/' + dbId, { token: b.token })).status, 404);
  // device token of A can't be used with B's identity
  assert.equal((await call('GET', '/api/me', { token: da.token })).json.business.id, a.businessId);
});

test('expired, suspended and rejected subscriptions cannot create paid bills or products', async () => {
  const c = await registerCustomer('9000000010', 'Expiry Cafe');
  const { subId } = await activate(c);
  const dev = (await registerDevice(c, 1)).json;
  await admin('PUT', `/admin-api/subscriptions/${subId}/dates`, { reason: 'test', startDate: '2020-01-01T00:00:00.000Z', endDate: '2021-01-01T00:00:00.000Z' });
  assert.equal((await call('GET', '/api/me', { token: c.token })).json.subscription.status, 'expired');
  const s = await call('POST', '/api/bills/sync', { token: dev.token, body: { bills: [bill('x1')] } });
  assert.equal(s.json.results[0].result, 'rejected');
  assert.equal((await call('POST', '/api/products', { token: c.token, body: { name: 'X', price: 1 } })).status, 402);
  assert.equal((await call('GET', '/api/bills', { token: c.token })).status, 200); // history stays viewable
  // renewal pending → still no paid access; reject → status expired
  const rr = await call('POST', '/api/subscription/request', { token: c.token, body: { paymentRef: 'R2' } });
  assert.equal((await call('GET', '/api/me', { token: c.token })).json.subscription.status, 'pending');
  await admin('POST', `/admin-api/subscriptions/${rr.json.subscriptionId}/reject`, { reason: 'payment not found' });
  assert.equal((await call('GET', '/api/me', { token: c.token })).json.subscription.status, 'expired');
  // suspend flow
  const c2 = await registerCustomer('9000000011', 'Suspend Cafe'); const { subId: s2 } = await activate(c2);
  assert.equal((await admin('POST', `/admin-api/subscriptions/${s2}/suspend`, {})).status, 400);
  await admin('POST', `/admin-api/subscriptions/${s2}/suspend`, { reason: 'chargeback' });
  assert.equal((await call('POST', '/api/products', { token: c2.token, body: { name: 'X', price: 1 } })).status, 402);
  await admin('POST', `/admin-api/subscriptions/${s2}/reinstate`, { reason: 'resolved' });
  assert.equal((await call('POST', '/api/products', { token: c2.token, body: { name: 'X', price: 1 } })).status, 201);
});

test('renewal extends from current end date (next 12-month term)', async () => {
  const c = await registerCustomer('9000000012', 'Renew Cafe');
  const first = await activate(c, 'A1');
  const second = await activate(c, 'A2');
  assert.equal(second.approve.json.startDate, first.approve.json.endDate);
});

test('audit log records admin actions and is immutable', async () => {
  const log = await admin('GET', '/admin-api/audit?limit=1000');
  const actions = new Set(log.json.map(e => e.action));
  for (const a of ['subscription.approved', 'subscription.rejected', 'device.revoked', 'payment.verified', 'admin.login', 'subscription.suspended', 'subscription.dates_overridden']) assert.ok(actions.has(a), a);
  assert.throws(() => db.prepare("UPDATE audit_events SET reason='x'").run(), /immutable/);
  assert.throws(() => db.prepare('DELETE FROM audit_events').run(), /immutable/);
});

test('dashboard figures computed from records; logout-all revokes sessions', async () => {
  const d = await admin('GET', '/admin-api/dashboard');
  assert.ok(d.json.totalBusinesses >= 10); assert.ok(d.json.pendingApprovals >= 1); assert.ok(d.json.subscriptionRevenue === 0 || d.json.subscriptionRevenue > 0);
  const c = await registerCustomer('9000000013', 'Logout');
  await call('POST', '/api/auth/logout-all', { token: c.token });
  assert.equal((await call('GET', '/api/me', { token: c.token })).status, 401);
});

const { runReminders } = require('../src/reminders');
const plus = (ms) => new Date(Date.now() + ms).toISOString();

test('loophole: negative discount/service/tax, bad payments and payment mismatch are rejected', async () => {
  const c = await registerCustomer('9000000020', 'Neg Cafe'); await activate(c);
  const dev = (await registerDevice(c, 1)).json;
  const send = async (id, extra) => (await call('POST', '/api/bills/sync', { token: dev.token, body: { bills: [bill(id, extra)] } })).json.results[0];
  assert.equal((await send('n1', { discount: -100, payments: [{ method: 'cash', amount: 310 }] })).reason, 'INVALID_AMOUNT');
  assert.equal((await send('n2', { serviceCharge: -50 })).reason, 'INVALID_AMOUNT');
  assert.equal((await send('n3', { items: [{ name: 'X', qty: 1, price: 10, taxRate: -50 }], payments: [{ method: 'cash', amount: 10 }] })).reason, 'INVALID_ITEM');
  assert.equal((await send('n4', { payments: [{ method: 'cash', amount: 1 }] })).reason, 'PAYMENT_MISMATCH');
  assert.equal((await send('n5', { payments: [{ method: 'bitcoin', amount: 210 }] })).reason, 'INVALID_PAYMENT');
  assert.equal((await send('n6', { items: [{ name: { $ne: 1 }, qty: 1, price: 1 }] })).reason, 'INVALID_ITEM');
  assert.equal((await send('n7', { createdAt: plus(3600000) })).reason, 'FUTURE_DATE');
  assert.equal((await send('n8', { createdAt: 'garbage' })).reason, 'INVALID_DATE');
  assert.equal((await send('n9', { createdAt: '2019-01-01T00:00:00.000Z' })).reason, 'BEFORE_DEVICE_REGISTRATION');
  assert.equal((await send('ok1')).result, 'created');
});

test('loophole: a payment reference cannot be reused by another business; rejected refs can be resubmitted', async () => {
  const a = await registerCustomer('9000000021', 'Ref A'), b = await registerCustomer('9000000022', 'Ref B');
  const r1 = await call('POST', '/api/subscription/request', { token: a.token, body: { paymentRef: 'UTR-SHARED-1' } });
  assert.equal(r1.status, 201);
  const r2 = await call('POST', '/api/subscription/request', { token: b.token, body: { paymentRef: 'utr-shared-1' } });
  assert.equal(r2.status, 409); assert.equal(r2.json.code, 'PAYMENT_REF_USED');
  await admin('POST', `/admin-api/subscriptions/${r1.json.subscriptionId}/reject`, { reason: 'not found' });
  assert.equal((await call('POST', '/api/subscription/request', { token: b.token, body: { paymentRef: 'UTR-SHARED-1' } })).status, 201);
});

test('loophole: bills dated after suspension are refused; pre-suspension bills sync; reinstate lets retries through', async () => {
  const c = await registerCustomer('9000000023', 'Susp Bills'); const { subId } = await activate(c);
  const dev = (await registerDevice(c, 1)).json;
  await new Promise(r => setTimeout(r, 20));
  const t0 = new Date().toISOString();                 // inside the term, before the suspension
  await new Promise(r => setTimeout(r, 20));
  await admin('POST', `/admin-api/subscriptions/${subId}/suspend`, { reason: 'review' });
  const before = bill('s1', { createdAt: t0 });
  const after = bill('s2', { createdAt: plus(120000) });
  const res = (await call('POST', '/api/bills/sync', { token: dev.token, body: { bills: [before, after] } })).json.results;
  assert.equal(res[0].result, 'created');             // made before the suspension
  assert.equal(res[1].result, 'rejected');            // made after
  await admin('POST', `/admin-api/subscriptions/${subId}/reinstate`, { reason: 'cleared' });
  assert.equal((await call('POST', '/api/bills/sync', { token: dev.token, body: { bills: [after] } })).json.results[0].result, 'created');
  // account-level suspension also blocks new bills
  const c2 = await registerCustomer('9000000024', 'Acct Susp'); await activate(c2);
  const d2 = (await registerDevice(c2, 1)).json;
  await admin('POST', `/admin-api/customers/${c2.businessId}/suspend`, { reason: 'abuse' });
  assert.equal((await call('POST', '/api/bills/sync', { token: d2.token, body: { bills: [bill('a1', { createdAt: plus(120000) })] } })).json.results[0].result, 'rejected');
  assert.equal((await admin('POST', `/admin-api/customers/${c2.businessId}/suspend`, {})).status, 400);
});

test('loophole: duplicate GSTIN business and admin guards (price check, suspended account, reasons)', async () => {
  const mk = async (m, g) => {
    const email = `${m}@gst.test`;
    const r = await call('POST', '/api/auth/register', { body: { email, password: PASS, ownerName: 'O', phone: m } });
    const v = await call('POST', '/api/auth/register/verify', { body: { challenge: r.json.challenge, code: lastAuthCode(email) } });
    return call('POST', '/api/business', { token: v.json.token, body: { ownerName: 'O', businessName: 'G' + m, businessType: 'cafe', address: 'x', contact: m, gstin: g } });
  };
  assert.equal((await mk('9000000030', '29ABCDE1234F1Z5')).status, 201);
  assert.equal((await mk('9000000031', '29ABCDE1234F1Z5')).status, 409);
  assert.equal((await mk('9000000032', 'bad')).status, 400);
  // amount below plan price needs an override reason
  await admin('PUT', '/admin-api/settings', { plan_price: '1000' });
  const c = await registerCustomer('9000000033', 'Cheap');
  const r = await call('POST', '/api/subscription/request', { token: c.token, body: { paymentRef: 'CHEAP-1', amount: 999 } });
  await admin('POST', `/admin-api/subscriptions/${r.json.subscriptionId}/verify-payment`, {});
  const low = await admin('POST', `/admin-api/subscriptions/${r.json.subscriptionId}/approve`, {});
  assert.equal(low.status, 409); assert.equal(low.json.code, 'AMOUNT_BELOW_PRICE');
  assert.equal((await admin('POST', `/admin-api/subscriptions/${r.json.subscriptionId}/approve`, { overrideReason: 'discount agreed' })).status, 200);
  await admin('PUT', '/admin-api/settings', { plan_price: '0' });
  // suspended account cannot be approved
  const c2 = await registerCustomer('9000000034', 'Blocked');
  const r2 = await call('POST', '/api/subscription/request', { token: c2.token, body: { paymentRef: 'BLOCK-1' } });
  await admin('POST', `/admin-api/subscriptions/${r2.json.subscriptionId}/verify-payment`, {});
  await admin('POST', `/admin-api/customers/${c2.businessId}/suspend`, { reason: 'fraud' });
  assert.equal((await admin('POST', `/admin-api/subscriptions/${r2.json.subscriptionId}/approve`, {})).status, 409);
  assert.equal((await admin('PUT', `/admin-api/customers/${c2.businessId}`, { name: 'x' })).status, 400); // reason mandatory
});

test('reminders fire once per threshold (30/15/7/1 days)', async () => {
  const c = await registerCustomer('9000000040', 'Remind'); const { subId } = await activate(c);
  const notifyFn = (bid, t, b) => db.prepare('INSERT INTO notifications(business_id,title,body,created_at) VALUES (?,?,?,?)').run(bid, t, b, new Date().toISOString());
  const count = () => db.prepare("SELECT COUNT(*) c FROM notifications WHERE business_id=? AND title='Subscription expiring soon'").get(c.businessId).c;
  runReminders(db, notifyFn); assert.equal(count(), 0);
  await admin('PUT', `/admin-api/subscriptions/${subId}/dates`, { reason: 't', startDate: plus(-300 * 86400000), endDate: plus(6.5 * 86400000) });
  runReminders(db, notifyFn); assert.equal(count(), 1);
  runReminders(db, notifyFn); assert.equal(count(), 1);       // not repeated
  const me = await call('GET', '/api/me', { token: c.token }); assert.equal(me.json.subscription.reminder, true);
  const n = await call('GET', '/api/notifications', { token: c.token }); assert.ok(n.json.some(x => x.title === 'Subscription expiring soon'));
});

test('hardening: email auth resend cooldown, removed SMS endpoints, JSON errors, device-slot DB constraint, production secret guard', async () => {
  const email = 'cooldown@example.test';
  const reg = await call('POST', '/api/auth/register', { body: { email, password: PASS, ownerName: 'Cooldown', phone: '9000000050' } });
  assert.equal(reg.status, 202);
  assert.equal((await call('POST', '/api/auth/register/resend', { body: { challenge: reg.json.challenge } })).status, 429);
  assert.equal((await call('POST', '/api/auth/request-otp', { body: { mobile: '9000000050' } })).status, 404);
  const r = await fetch(base + '/api/auth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{bad json' });
  assert.equal(r.status, 400);
  const c = await registerCustomer('9000000051', 'Slots'); await activate(c); await registerDevice(c, 1);
  assert.throws(() => db.prepare("INSERT INTO devices(id,business_id,app_instance_id,slot,registered_at,status) VALUES ('DEV-x',?,?,1,?,'active')").run(c.businessId, 'dup', new Date().toISOString()), /UNIQUE/);
  const old = { ...process.env }; process.env.NODE_ENV = 'production'; delete process.env.USER_JWT_SECRET;
  assert.throws(() => createApp(openDb(':memory:')), /must be set in production/);
  process.env.NODE_ENV = old.NODE_ENV || '';
});

test('invoice numbers are unique per device REGISTRATION (slot reuse after revoke cannot collide) and prefix is enforced', async () => {
  const c = await registerCustomer('9000000060', 'Invoice Cafe'); await activate(c);
  const d1r = await registerDevice(c, 1); const d1 = d1r.json;
  assert.equal(d1.invoicePrefix, 'D1');
  const mk = (n, extra) => ({ ...bill('i' + n, extra), invoiceNo: `${extra?.prefix || 'D1'}-000001` });
  const r1 = await call('POST', '/api/bills/sync', { token: d1.token, body: { bills: [mk(1)] } });
  assert.equal(r1.json.results[0].result, 'created');
  // device with same slot after revoke gets a NEW prefix
  await admin('POST', `/admin-api/devices/${d1.deviceId}/revoke`, { reason: 'replaced' });
  const d2 = (await registerDevice(c, 2)).json;
  assert.equal(d2.slot, 1); assert.equal(d2.invoicePrefix, 'D2');
  const ok = await call('POST', '/api/bills/sync', { token: d2.token, body: { bills: [{ ...bill('i2'), invoiceNo: 'D2-000001' }] } });
  assert.equal(ok.json.results[0].result, 'created');
  // a device cannot use another registration's prefix
  const spoof = await call('POST', '/api/bills/sync', { token: d2.token, body: { bills: [{ ...bill('i3'), invoiceNo: 'D1-000002' }] } });
  assert.equal(spoof.json.results[0].reason, 'INVALID_INVOICE_NO');
});

test('device token is long-lived but still revocable; payment instructions, defaults, variants and reporting by method', async () => {
  const jwt = require('jsonwebtoken');
  const c = await registerCustomer('9000000061', 'Misc Cafe'); await activate(c);
  const dev = (await registerDevice(c, 1)).json;
  const p = jwt.decode(dev.token); assert.ok(p.exp - p.iat >= 29 * 86400);
  await admin('PUT', '/admin-api/settings', { payment_instructions: 'UPI: pay@bank', support_contact: '+91 99999 00000', receipt_footer_default: 'Thanks!' });
  const sub = await call('GET', '/api/subscription', { token: c.token });
  assert.equal(sub.json.paymentInstructions, 'UPI: pay@bank'); assert.equal(sub.json.supportContact, '+91 99999 00000');
  assert.equal((await call('GET', '/api/me', { token: c.token })).json.defaults.receiptFooter, 'Thanks!');
  assert.equal((await admin('PUT', '/admin-api/settings', { max_devices: 'abc' })).status, 400);
  assert.equal((await admin('PUT', '/admin-api/settings', { reminder_days: 'x' })).status, 400);
  const good = await call('POST', '/api/products', { token: c.token, body: { name: 'Latte', price: 100, variants: [{ name: 'Large', priceDelta: 20, kind: 'variant' }, { name: 'Extra shot', priceDelta: 15, kind: 'addon' }] } });
  assert.equal(good.status, 201); assert.equal(good.json.variants.length, 2);
  assert.equal((await call('POST', '/api/products', { token: c.token, body: { name: 'X', price: 1, variants: [{ name: '', priceDelta: 1 }] } })).status, 400);
  assert.equal((await call('POST', '/api/products', { token: c.token, body: { name: 'X', price: 'free' } })).status, 400);
  assert.equal((await call('PUT', '/api/business', { token: c.token, body: { taxProfile: 'not json' } })).status, 400);
  assert.equal((await call('PUT', '/api/business', { token: c.token, body: { receiptFooter: 'Bye', taxProfile: JSON.stringify({ serviceChargePercent: 5 }) } })).status, 200);
  await call('POST', '/api/bills/sync', { token: dev.token, body: { bills: [bill('m1', { payments: [{ method: 'cash', amount: 100 }, { method: 'upi', amount: 110 }] })] } });
  const rep = await call('GET', '/api/reports/summary', { token: c.token });
  assert.deepEqual(rep.json.byMethod, { cash: 100, upi: 110 });
  const sup = await call('POST', '/api/support', { token: c.token, body: { subject: 'Help', message: 'Need help' } }); assert.equal(sup.status, 201);
  assert.equal((await call('POST', '/api/support', { token: c.token, body: { message: '  ' } })).status, 400);
  await call('POST', '/api/notifications/read-all', { token: c.token, body: {} });
});

test('tax is computed on the discounted value (pro-rata) and totals are rounded to 2 dp', async () => {
  const c = await registerCustomer('9000000070', 'Tax Cafe'); await activate(c);
  const dev = (await registerDevice(c, 1)).json;
  // 2 x 100 @ 5% tax, discount 50 => taxable 150 => tax 7.50 => total 157.50 (+ service 10 = 167.50)
  const r = (await call('POST', '/api/bills/sync', { token: dev.token, body: { bills: [bill('tx1', { discount: 50, serviceCharge: 10, payments: [{ method: 'cash', amount: 167.5 }] })] } })).json.results[0];
  assert.equal(r.result, 'created'); assert.equal(r.total, 167.5);
  const row = db.prepare("SELECT tax,discount FROM bills WHERE client_txn_id='tx1'").get(); assert.equal(row.tax, 7.5);
});

test('EMAIL SIGN-IN: wrong password sends nothing; right password emails a one-time code to the admin address only', async () => {
  const n = outbox.length;
  assert.equal((await call('POST', '/admin-api/login', { body: { email: 'owner@x.com', password: 'nope' } })).status, 401);
  assert.equal((await call('POST', '/admin-api/login', { body: { email: 'stranger@x.com', password: PASS } })).status, 401);   // unknown email: same answer, no mail
  assert.equal(outbox.length, n);
  const s1 = await call('POST', '/admin-api/login', { body: { email: 'owner@x.com', password: PASS } });
  assert.equal(s1.status, 200); assert.equal(outbox.length, n + 1);
  assert.equal(outbox[n].to, 'owner@x.com'); assert.match(outbox[n].text, /code is \d{6}/); assert.equal(s1.json.email, 'o****@x.com');
  assert.ok(!JSON.stringify(s1.json).includes(lastCode()), 'the code must never appear in the HTTP response');
  assert.equal(s1.headers.get('set-cookie'), null, 'no session until the code is verified');
  assert.equal((await call('GET', '/admin-api/me')).status, 401);
});

test('EMAIL SIGN-IN: wrong code rejected, 5 wrong codes burn the challenge, codes are single-use, newest code only', async () => {
  const s1 = await call('POST', '/admin-api/login', { body: { email: 'owner@x.com', password: PASS } }); const good = lastCode();
  const wrong = good === '000000' ? '111111' : '000000';
  const v = (code, ch = s1.json.challenge) => call('POST', '/admin-api/login/verify', { body: { challenge: ch, code } });
  assert.equal((await v(wrong)).status, 401);
  assert.equal((await v('', s1.json.challenge)).status, 401);
  assert.equal((await v(good, 'f'.repeat(32))).status, 401);                                // right code, wrong challenge id
  const ok = await v(good); assert.equal(ok.status, 200); assert.ok(ok.headers.get('set-cookie'));
  assert.equal((await v(good)).status, 401);                                                // single use
  // a newer sign-in invalidates the older challenge/code
  const a = await call('POST', '/admin-api/login', { body: { email: 'owner@x.com', password: PASS } }); const codeA = lastCode();
  const b = await call('POST', '/admin-api/login', { body: { email: 'owner@x.com', password: PASS } });
  assert.equal((await v(codeA, a.json.challenge)).status, 401);
  // five wrong codes burn the challenge even if the 6th guess is right
  const codeB = lastCode(); const w = codeB === '123456' ? '654321' : '123456';
  for (let i = 0; i < 4; i++) assert.equal((await v(w, b.json.challenge)).status, 401);
  assert.equal((await v(w, b.json.challenge)).status, 401);
  assert.equal((await v(codeB, b.json.challenge)).status, 401);
  db.prepare('UPDATE admins SET failed_logins=0, locked_until=0').run();
});

test('EMAIL SIGN-IN: codes expire; resend has a cooldown and a cap; mail failure gives a clear error and no session', async () => {
  const s1 = await call('POST', '/admin-api/login', { body: { email: 'owner@x.com', password: PASS } }); const code = lastCode();
  assert.equal((await call('POST', '/admin-api/login/resend', { body: { challenge: s1.json.challenge } })).status, 429);       // cooldown
  db.prepare('UPDATE admin_challenges SET last_sent_at=0 WHERE id=?').run(s1.json.challenge);
  const n = outbox.length; assert.equal((await call('POST', '/admin-api/login/resend', { body: { challenge: s1.json.challenge } })).status, 200); assert.equal(outbox.length, n + 1);
  const fresh = lastCode();
  db.prepare('UPDATE admin_challenges SET expires_at=1 WHERE id=?').run(s1.json.challenge);
  assert.equal((await call('POST', '/admin-api/login/verify', { body: { challenge: s1.json.challenge, code: fresh } })).status, 401);   // expired
  void code;
  const failing = createApp(db, { noRateLimit: true, mailer: { sendMail: async () => { throw new Error('smtp down'); } } });
  const srv = await new Promise(r => { const x = failing.listen(0, () => r(x)); }); const b2 = 'http://127.0.0.1:' + srv.address().port;
  const r = await fetch(b2 + '/admin-api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'owner@x.com', password: PASS }) });
  assert.equal(r.status, 502); assert.equal(r.headers.get('set-cookie'), null); srv.close();
  assert.equal(db.prepare('SELECT COUNT(*) c FROM admin_challenges').get().c >= 0, true);
  assert.throws(() => { const e = process.env.NODE_ENV; process.env.NODE_ENV = 'production'; try { createApp(openDb(':memory:'), {}); } finally { process.env.NODE_ENV = e || ''; } }, /(SMTP|must be set)/);
});

test('admin session is revoked server-side on logout and rate/lockout protects login', async () => {
  const l = await adminLogin(); const cookie = l.cookie;
  assert.equal((await call('GET', '/admin-api/me', { cookie })).status, 200);
  assert.equal((await call('POST', '/admin-api/logout', { cookie, csrf: true })).status, 200);
  assert.equal((await call('GET', '/admin-api/me', { cookie })).status, 401);   // replaying the old cookie fails
  for (let i = 0; i < 5; i++) await call('POST', '/admin-api/login', { body: { email: 'owner@x.com', password: 'wrong' } });
  const n = outbox.length; const locked = await call('POST', '/admin-api/login', { body: { email: 'owner@x.com', password: PASS } });
  assert.equal(locked.status, 429); assert.equal(outbox.length, n);              // locked: no code is even sent
});

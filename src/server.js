const { openDb, newId } = require('./db');
const { createApp } = require('./app');
const { createMailer } = require('./mailer');
const { runReminders } = require('./reminders');
const bcrypt = require('bcryptjs');

const db = openDb();
const mailer = createMailer();
if (!mailer) { console.error('Production needs SMTP so the Super Admin can receive sign-in codes. Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM.'); process.exit(1); }
// One-time Super Admin bootstrap (owner-only; no public sign-up route exists). Sign-in codes go to ADMIN_EMAIL.
if (!db.prepare('SELECT 1 FROM admins').get()) {
  const { ADMIN_EMAIL, ADMIN_PASSWORD } = process.env;
  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    if (ADMIN_PASSWORD.length < 12) { console.error('ADMIN_PASSWORD must be at least 12 characters'); process.exit(1); }
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(ADMIN_EMAIL)) { console.error('ADMIN_EMAIL must be a valid email address'); process.exit(1); }
    db.prepare('INSERT INTO admins(id,email,password_hash,totp_secret) VALUES (?,?,?,?)').run(newId(db, 'ADM', 'admins'), ADMIN_EMAIL.toLowerCase(), bcrypt.hashSync(ADMIN_PASSWORD, 12), '');
    console.log(`Super Admin created. After the password, a sign-in code is emailed to ${ADMIN_EMAIL}.`);
  } else console.warn('No admin exists. Set ADMIN_EMAIL and ADMIN_PASSWORD (>=12 chars) and restart once.');
}
const app = createApp(db, { mailer, alert: async (m) => {
  console.warn('[ADMIN ALERT]', m);
  if (process.env.ALERT_WEBHOOK_URL) { try { await fetch(process.env.ALERT_WEBHOOK_URL, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text: m }) }); } catch {} }
} });
const notify = (bid, title, body) => db.prepare('INSERT INTO notifications(business_id,title,body,created_at) VALUES (?,?,?,?)').run(bid, title, body, new Date().toISOString());
setInterval(() => { try { runReminders(db, notify); } catch (e) { console.error(e); } }, 60 * 60 * 1000).unref();
runReminders(db, notify);
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Tably backend on :${port} (mail: ${mailer.kind})`));

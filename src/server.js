const { openDb, newId } = require('./db');
const { createApp } = require('./app');
const { createMailer } = require('./mailer');
const { runReminders } = require('./reminders');
const { validateProductionEnv } = require('./config');
const bcrypt = require('bcryptjs');

if (process.env.NODE_ENV === 'production') validateProductionEnv(process.env);
const mailer = createMailer();
const db = openDb();
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
const reminderTimer = setInterval(() => { try { runReminders(db, notify); } catch (e) { console.error(e); } }, 60 * 60 * 1000);
reminderTimer.unref();
runReminders(db, notify);
const port = process.env.PORT || 3000;
const host = process.env.HOST || (process.env.NODE_ENV === 'production' ? '127.0.0.1' : '0.0.0.0');
const server = app.listen(port, host, () => console.log(`Tably backend on ${host}:${port} (mail: ${mailer.kind})`));

let shuttingDown = false;
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  clearInterval(reminderTimer);
  console.log(`Received ${signal}; shutting down`);
  server.close((error) => {
    try {
      if (db.pragma('journal_mode', { simple: true }).toLowerCase() === 'wal') {
        db.pragma('wal_checkpoint(TRUNCATE)');
      }
      db.close();
    } catch (closeError) {
      console.error('Database shutdown failed:', closeError.message);
      process.exitCode = 1;
    }
    if (error) {
      console.error('HTTP server shutdown failed:', error.message);
      process.exitCode = 1;
    }
    process.exit(process.exitCode || 0);
  });
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

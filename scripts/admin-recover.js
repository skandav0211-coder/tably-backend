// Host-only recovery (not reachable from any app/web endpoint). Resets the password and optionally the email codes go to.
// Usage: ADMIN_NEW_PASSWORD='at-least-12-chars' [ADMIN_NEW_EMAIL=you@example.com] node scripts/admin-recover.js
const { openDb } = require('../src/db'); const bcrypt = require('bcryptjs');
const db = openDb(); const a = db.prepare('SELECT * FROM admins LIMIT 1').get();
if (!a) { console.error('No admin'); process.exit(1); }
const pw = process.env.ADMIN_NEW_PASSWORD; if (!pw || pw.length < 12) { console.error('Set ADMIN_NEW_PASSWORD (>=12 chars)'); process.exit(1); }
const email = (process.env.ADMIN_NEW_EMAIL || a.email).toLowerCase();
db.prepare('UPDATE admins SET password_hash=?, email=?, session_nonce=session_nonce+1, failed_logins=0, locked_until=0 WHERE id=?').run(bcrypt.hashSync(pw, 12), email, a.id);
db.prepare('DELETE FROM admin_challenges').run();
db.prepare("INSERT INTO audit_events(actor,action,target,reason,created_at) VALUES ('host','admin.recovered',?,?,?)").run(a.id, 'CLI recovery', new Date().toISOString());
console.log('Reset done. Sign-in codes will be emailed to', email);

// SQLite for the dev build; schema is plain SQL and ports directly to PostgreSQL (SRS §8).
const Database = require('better-sqlite3');
const crypto = require('crypto');

function openDb(file = process.env.DB_FILE || 'billing.db') {
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, mobile TEXT UNIQUE, email TEXT, phone TEXT, legacy_email TEXT,
    password_hash TEXT, email_verified INTEGER DEFAULT 0, owner_name TEXT,
    verified INTEGER DEFAULT 0, status TEXT DEFAULT 'active', token_version INTEGER DEFAULT 0,
    failed_logins INTEGER DEFAULT 0, locked_until INTEGER DEFAULT 0, created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS businesses (
    id TEXT PRIMARY KEY, owner_user_id TEXT UNIQUE NOT NULL REFERENCES users(id),
    name TEXT NOT NULL, type TEXT, address TEXT, contact TEXT, gstin TEXT,
    currency TEXT DEFAULT 'INR', tax_profile TEXT, receipt_footer TEXT, logo TEXT,
    status TEXT DEFAULT 'active', created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY, business_id TEXT NOT NULL REFERENCES businesses(id),
    plan TEXT NOT NULL, amount REAL, status TEXT NOT NULL,
    start_date TEXT, end_date TEXT, approved_by TEXT, approved_at TEXT,
    admin_message TEXT, created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS payments (
    id TEXT PRIMARY KEY, business_id TEXT NOT NULL, subscription_id TEXT NOT NULL,
    amount REAL, method TEXT, provider_ref TEXT, evidence TEXT,
    verification_state TEXT DEFAULT 'unverified', created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY, business_id TEXT NOT NULL REFERENCES businesses(id),
    app_instance_id TEXT NOT NULL, slot INTEGER, label TEXT, registered_at TEXT NOT NULL,
    last_seen_at TEXT, status TEXT DEFAULT 'active', revoked_reason TEXT);
  CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY, business_id TEXT NOT NULL, category TEXT, name TEXT NOT NULL,
    sku TEXT, description TEXT, price REAL NOT NULL, tax_rate REAL DEFAULT 0,
    available INTEGER DEFAULT 1, active INTEGER DEFAULT 1, favourite INTEGER DEFAULT 0,
    variants TEXT, updated_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS bills (
    id TEXT PRIMARY KEY, client_txn_id TEXT NOT NULL, business_id TEXT NOT NULL,
    device_id TEXT, invoice_no TEXT NOT NULL, status TEXT NOT NULL,
    cashier TEXT, customer_name TEXT, customer_mobile TEXT, table_no TEXT, notes TEXT,
    items TEXT NOT NULL, subtotal REAL, discount REAL, tax REAL, service_charge REAL, total REAL,
    payments TEXT, created_at TEXT NOT NULL, synced_at TEXT NOT NULL,
    UNIQUE (business_id, client_txn_id), UNIQUE (business_id, invoice_no));
  CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
    target TEXT, reason TEXT, before TEXT, after TEXT, ip TEXT, created_at TEXT NOT NULL);
  CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events
    BEGIN SELECT RAISE(ABORT,'audit events are immutable'); END;
  CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events
    BEGIN SELECT RAISE(ABORT,'audit events are immutable'); END;
  CREATE TABLE IF NOT EXISTS admins (
    id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    totp_secret TEXT NOT NULL, failed_logins INTEGER DEFAULT 0, locked_until INTEGER DEFAULT 0);
  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT, business_id TEXT NOT NULL, title TEXT, body TEXT, read INTEGER DEFAULT 0, created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS admin_challenges (id TEXT PRIMARY KEY, admin_id TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER DEFAULT 0, sends INTEGER DEFAULT 1, last_sent_at INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS releases (
    id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT NOT NULL, min_supported INTEGER DEFAULT 0,
    notes TEXT, apk_url TEXT, created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS support_requests (
    id TEXT PRIMARY KEY, business_id TEXT NOT NULL, subject TEXT, message TEXT,
    status TEXT DEFAULT 'open', created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, business_id TEXT, kind TEXT, detail TEXT, created_at TEXT NOT NULL);
  `);
  // Lightweight migrations for databases created by earlier builds
  for (const [t, c, d] of [['subscriptions','disabled_at','TEXT'],['businesses','suspended_at','TEXT'],['devices','entitled_until','TEXT'],
      ['admins','session_nonce','INTEGER DEFAULT 0'],['devices','reg_seq','INTEGER'],
      ['users','phone','TEXT'],['users','legacy_email','TEXT'],['users','password_hash','TEXT'],
      ['users','email_verified','INTEGER DEFAULT 0'],['users','failed_logins','INTEGER DEFAULT 0'],
      ['users','locked_until','INTEGER DEFAULT 0']]) {
    try { db.exec(`ALTER TABLE ${t} ADD COLUMN ${c} ${d}`); } catch { /* already exists */ }
  }
  db.transaction(() => {
    db.exec('UPDATE users SET phone=mobile WHERE phone IS NULL AND mobile IS NOT NULL');
    db.exec('UPDATE users SET legacy_email=email, email=NULL WHERE password_hash IS NULL AND email IS NOT NULL AND legacy_email IS NULL');
    db.exec('CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email ON users(lower(email)) WHERE email IS NOT NULL');
    db.exec(`CREATE TABLE IF NOT EXISTS auth_challenges (
      id TEXT PRIMARY KEY, user_id TEXT, email TEXT NOT NULL, purpose TEXT NOT NULL,
      code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER DEFAULT 0,
      sends INTEGER DEFAULT 1, last_sent_at INTEGER NOT NULL, phone TEXT,
      owner_name TEXT, password_hash TEXT)`);
  })();
  db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS ux_device_slot ON devices(business_id, slot) WHERE status='active';
    CREATE UNIQUE INDEX IF NOT EXISTS ux_business_gstin ON businesses(gstin) WHERE gstin IS NOT NULL;
    CREATE INDEX IF NOT EXISTS ix_payment_ref ON payments(provider_ref);
    CREATE TABLE IF NOT EXISTS reminders_sent (subscription_id TEXT NOT NULL, days INTEGER NOT NULL, PRIMARY KEY (subscription_id, days));
  `);
  db.exec(`UPDATE devices SET reg_seq = (SELECT COUNT(*) FROM devices d2 WHERE d2.business_id=devices.business_id AND d2.rowid<=devices.rowid) WHERE reg_seq IS NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS ux_device_seq ON devices(business_id, reg_seq);`);
  const defaults = { plan_months: '12', reminder_days: '30,15,7,1', max_devices: '3',
    grace_days: '0', offline_window_hours: '72', plan_price: '0',
    payment_instructions: 'Pay by UPI/bank transfer as instructed by the provider, then submit the transaction reference.',
    support_contact: '', receipt_footer_default: 'Thank you! Visit again.' };
  const ins = db.prepare('INSERT OR IGNORE INTO settings(key,value) VALUES (?,?)');
  for (const [k, v] of Object.entries(defaults)) ins.run(k, v);
  return db;
}

// Non-sequential, unguessable IDs: PREFIX-<random 6 digits> with collision check (SRS §3.1).
function newId(db, prefix, table) {
  for (;;) {
    const id = `${prefix}-${String(crypto.randomInt(0, 1e9)).padStart(9, '0')}`;
    if (!db.prepare(`SELECT 1 FROM ${table} WHERE id=?`).get(id)) return id;
  }
}
module.exports = { openDb, newId };

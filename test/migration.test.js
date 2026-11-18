const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { openDb } = require('../src/db');

test('legacy user migration preserves data, copies mobile to phone and reserves old email as unverified contact', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tably-migration-'));
  const file = path.join(dir, 'legacy.db');
  let migrated;
  try {
    const old = new Database(file);
    old.exec(`CREATE TABLE users (
      id TEXT PRIMARY KEY, mobile TEXT UNIQUE NOT NULL, email TEXT, owner_name TEXT,
      verified INTEGER DEFAULT 0, status TEXT DEFAULT 'active', token_version INTEGER DEFAULT 0, created_at TEXT NOT NULL
    )`);
    old.prepare('INSERT INTO users(id,mobile,email,owner_name,verified,created_at) VALUES (?,?,?,?,1,?)')
      .run('USR-LEGACY', '9876543210', 'old-contact@example.test', 'Legacy Owner', new Date().toISOString());
    old.close();

    migrated = openDb(file);
    const row = migrated.prepare('SELECT * FROM users WHERE id=?').get('USR-LEGACY');
    assert.equal(row.mobile, '9876543210');
    assert.equal(row.phone, '9876543210');
    assert.equal(row.legacy_email, 'old-contact@example.test');
    assert.equal(row.email, null);
    assert.equal(row.password_hash, null);
    assert.ok(migrated.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='auth_challenges'").get());
  } finally {
    migrated?.close();
    for (const suffix of ['', '-wal', '-shm']) fs.rmSync(file + suffix, { force: true });
    fs.rmdirSync(dir);
  }
});

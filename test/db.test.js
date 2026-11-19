const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { openDb } = require('../src/db');
const Database = require('better-sqlite3');

test('SQLite creates its parent directory and keeps WAL, busy timeout, and foreign keys enabled', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tably-db-'));
  const file = path.join(root, 'nested', 'application.db');
  const db = openDb(file);
  try {
    assert.equal(db.pragma('journal_mode', { simple: true }), 'wal');
    assert.equal(db.pragma('busy_timeout', { simple: true }), 5000);
    assert.equal(db.pragma('foreign_keys', { simple: true }), 1);
    assert.equal(fs.existsSync(file), true);
  } finally {
    db.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('SQLite reports a clear writable-directory error', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tably-db-invalid-'));
  const fileInsteadOfDirectory = path.join(root, 'not-a-directory');
  fs.writeFileSync(fileInsteadOfDirectory, 'file');
  try {
    assert.throws(() => openDb(path.join(fileInsteadOfDirectory, 'app.db')), /SQLite database directory is not writable/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('backup CLI creates a readable consistent copy of the live SQLite database', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tably-backup-'));
  const source = path.join(root, 'source.db');
  const destination = path.join(root, 'backups', 'snapshot.db');
  const live = openDb(source);
  live.prepare("INSERT INTO settings(key,value) VALUES ('backup-check','present')").run();
  try {
    const output = execFileSync(process.execPath, [path.join(__dirname, '..', 'scripts', 'backup.js'), destination], {
      env: { ...process.env, DB_FILE: source },
      encoding: 'utf8',
    });
    assert.match(output, /Backup created:/);
    const backup = new Database(destination, { readonly: true });
    try {
      assert.equal(backup.prepare("SELECT value FROM settings WHERE key='backup-check'").get().value, 'present');
    } finally {
      backup.close();
    }
  } finally {
    live.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

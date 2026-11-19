const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { openDb } = require('../src/db');
const Database = require('better-sqlite3');
const { Readable } = require('node:stream');
const {
  validateBackupConfig,
  nextBackupTime,
  runBackupNow,
  startBackupScheduler,
  restoreBackup,
} = require('../src/backup');

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

test('Railway backup config requires production storage unless explicitly disabled', () => {
  assert.throws(() => validateBackupConfig({ NODE_ENV: 'production' }), /BACKUP_S3_ENDPOINT/);
  assert.equal(validateBackupConfig({ NODE_ENV: 'production', BACKUP_DISABLED: 'true' }).disabled, true);
  assert.equal(validateBackupConfig({ NODE_ENV: 'development' }).enabled, false);
  assert.throws(() => validateBackupConfig({
    NODE_ENV: 'production',
    BACKUP_S3_ENDPOINT: 'https://s3.example.test',
    BACKUP_S3_BUCKET: 'backups',
    BACKUP_S3_KEY_ID: 'id',
    BACKUP_S3_SECRET: 'secret',
    BACKUP_S3_REGION: 'auto',
    BACKUP_ENCRYPTION_KEY: 'too-short',
  }), /exactly 32 bytes/);
});

test('daily off-site backup uses 02:30 UTC and encrypted restore verifies SQLite integrity', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tably-offsite-backup-'));
  const sourcePath = path.join(root, 'source.db');
  const destinationPath = path.join(root, 'restored', 'billing.db');
  const live = openDb(sourcePath);
  live.prepare("INSERT INTO settings(key,value) VALUES ('offsite-check','preserved')").run();

  const config = {
    enabled: true,
    bucket: 'tably-backups',
    encryptionKey: Buffer.alloc(32, 23),
  };
  const storedObjects = [];
  let deletedKeys = [];
  const s3Client = {
    async send(command) {
      if (command.constructor.name === 'PutObjectCommand') {
        const chunks = [];
        for await (const chunk of command.input.Body) chunks.push(Buffer.from(chunk));
        storedObjects.push({
          Key: command.input.Key,
          LastModified: new Date('2026-01-02T00:00:00Z'),
          Body: Buffer.concat(chunks),
        });
        return {};
      }
      if (command.constructor.name === 'ListObjectsV2Command') {
        const older = Array.from({ length: 30 }, (_, index) => ({
          Key: `backups/tably-old-${index}`,
          LastModified: new Date(Date.UTC(2025, 0, index + 1)),
        }));
        return { Contents: [...older, ...storedObjects] };
      }
      if (command.constructor.name === 'DeleteObjectsCommand') {
        deletedKeys = command.input.Delete.Objects.map(({ Key }) => Key);
        return {};
      }
      if (command.constructor.name === 'GetObjectCommand') {
        const object = storedObjects.find(({ Key }) => Key === command.input.Key);
        if (!object) throw new Error('missing object');
        return { Body: Readable.from(object.Body) };
      }
      throw new Error(`Unexpected S3 command: ${command.constructor.name}`);
    },
  };

  try {
    assert.equal(
      nextBackupTime(new Date('2026-11-19T02:29:59.000Z')).toISOString(),
      '2026-11-19T02:30:00.000Z',
    );
    assert.equal(
      nextBackupTime(new Date('2026-11-19T02:30:00.000Z')).toISOString(),
      '2026-11-20T02:30:00.000Z',
    );

    const result = await runBackupNow({
      db: live,
      config,
      s3Client,
      now: new Date('2026-11-19T02:30:00.000Z'),
    });
    assert.match(result.key, /^backups\/tably-/);
    assert.equal(storedObjects.length, 1);
    assert.deepEqual(deletedKeys, ['backups/tably-old-0']);

    await restoreBackup({
      config,
      objectKey: result.key,
      destination: destinationPath,
      s3Client,
    });
    const restored = new Database(destinationPath, { readonly: true });
    try {
      assert.equal(restored.prepare("SELECT value FROM settings WHERE key='offsite-check'").get().value, 'preserved');
      assert.equal(restored.pragma('integrity_check', { simple: true }), 'ok');
    } finally {
      restored.close();
    }

    const originalBody = storedObjects[0].Body;
    storedObjects[0].Body = Buffer.from(originalBody);
    storedObjects[0].Body[25] ^= 0xff;
    await assert.rejects(() => restoreBackup({
      config,
      objectKey: result.key,
      destination: path.join(root, 'corrupt.db'),
      s3Client,
    }));
  } finally {
    live.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('scheduled backup failures are logged and sent to the configured alert hook', async () => {
  let scheduled;
  let delay;
  let alertMessage;
  const scheduler = startBackupScheduler({
    db: { backup: async () => { throw new Error('snapshot failed'); } },
    config: { enabled: true, bucket: 'bucket', encryptionKey: Buffer.alloc(32) },
    s3Client: { send: async () => { throw new Error('S3 should not be reached'); } },
    now: () => new Date('2026-11-19T02:29:59.000Z'),
    setTimer: (callback, milliseconds) => {
      scheduled = callback;
      delay = milliseconds;
      return { unref() {} };
    },
    clearTimer: () => {},
    alert: async (message) => { alertMessage = message; },
  });
  assert.equal(delay, 1000);
  scheduled();
  await scheduler.stop();
  assert.match(alertMessage, /Scheduled off-site backup failed: snapshot failed/);
});

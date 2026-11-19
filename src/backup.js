const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createGzip, createGunzip } = require('zlib');
const { pipeline } = require('stream/promises');
const { createReadStream, createWriteStream } = require('fs');
const Database = require('better-sqlite3');
const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  DeleteObjectsCommand,
} = require('@aws-sdk/client-s3');

const REQUIRED_BACKUP_VARS = [
  'BACKUP_S3_ENDPOINT',
  'BACKUP_S3_BUCKET',
  'BACKUP_S3_KEY_ID',
  'BACKUP_S3_SECRET',
  'BACKUP_S3_REGION',
  'BACKUP_ENCRYPTION_KEY',
];
const MAGIC = Buffer.from('TABLYBK1');
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const HEADER_LENGTH = MAGIC.length + IV_LENGTH;
const RETAIN_OBJECTS = 30;
const OBJECT_PREFIX = 'backups/tably-';

function validateBackupConfig(env = process.env) {
  if (env.BACKUP_DISABLED === 'true') return { enabled: false, disabled: true };

  const missing = REQUIRED_BACKUP_VARS.filter((name) => !env[name]);
  if (missing.length) {
    if (env.NODE_ENV === 'production') {
      throw new Error(`Off-site backups are required in production; set ${missing.join(', ')} or set BACKUP_DISABLED=true`);
    }
    return { enabled: false, disabled: false, missing };
  }
  if (!/^[\da-fA-F]{64}$/.test(env.BACKUP_ENCRYPTION_KEY)) {
    throw new Error('BACKUP_ENCRYPTION_KEY must be exactly 32 bytes encoded as 64 hexadecimal characters');
  }

  return {
    enabled: true,
    endpoint: env.BACKUP_S3_ENDPOINT,
    bucket: env.BACKUP_S3_BUCKET,
    keyId: env.BACKUP_S3_KEY_ID,
    secret: env.BACKUP_S3_SECRET,
    region: env.BACKUP_S3_REGION,
    encryptionKey: Buffer.from(env.BACKUP_ENCRYPTION_KEY, 'hex'),
  };
}

function createS3Client(config) {
  return new S3Client({
    endpoint: config.endpoint,
    region: config.region,
    forcePathStyle: true,
    credentials: { accessKeyId: config.keyId, secretAccessKey: config.secret },
  });
}

function checkIntegrity(databasePath) {
  const database = new Database(databasePath, { readonly: true, fileMustExist: true });
  try {
    const result = database.pragma('integrity_check', { simple: true });
    if (result !== 'ok') throw new Error(`SQLite integrity_check failed: ${String(result)}`);
  } finally {
    database.close();
  }
}

async function encryptGzipFile(gzipPath, encryptedPath, key) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const output = createWriteStream(encryptedPath, { flags: 'wx' });
  output.write(Buffer.concat([MAGIC, iv]));
  await pipeline(createReadStream(gzipPath), cipher, output);
  await fs.promises.appendFile(encryptedPath, cipher.getAuthTag());
}

async function retainNewestObjects(client, bucket) {
  const objects = [];
  let continuationToken;
  do {
    const page = await client.send(new ListObjectsV2Command({
      Bucket: bucket,
      Prefix: OBJECT_PREFIX,
      ...(continuationToken ? { ContinuationToken: continuationToken } : {}),
    }));
    objects.push(...(page.Contents || []).filter((object) => object.Key));
    if (page.IsTruncated && !page.NextContinuationToken) {
      throw new Error('S3 backup listing was truncated without a continuation token');
    }
    continuationToken = page.IsTruncated ? page.NextContinuationToken : undefined;
  } while (continuationToken);

  objects.sort((a, b) => new Date(b.LastModified || 0) - new Date(a.LastModified || 0));
  const stale = objects.slice(RETAIN_OBJECTS);
  for (let index = 0; index < stale.length; index += 1000) {
    const page = stale.slice(index, index + 1000);
    const response = await client.send(new DeleteObjectsCommand({
      Bucket: bucket,
      Delete: { Quiet: true, Objects: page.map(({ Key }) => ({ Key })) },
    }));
    if (response.Errors?.length) {
      throw new Error(`Could not delete ${response.Errors.length} expired backup object(s)`);
    }
  }
}

async function runBackupNow({ db, config, s3Client, now = new Date() }) {
  if (!config?.enabled) throw new Error('Off-site backup is not configured');
  const client = s3Client || createS3Client(config);
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tably-backup-'));
  const snapshotPath = path.join(tempDir, 'snapshot.db');
  const gzipPath = path.join(tempDir, 'snapshot.db.gz');
  const encryptedPath = path.join(tempDir, 'snapshot.db.gz.enc');

  try {
    await db.backup(snapshotPath);
    checkIntegrity(snapshotPath);
    await pipeline(createReadStream(snapshotPath), createGzip(), createWriteStream(gzipPath, { flags: 'wx' }));
    await encryptGzipFile(gzipPath, encryptedPath, config.encryptionKey);

    const timestamp = now.toISOString().replace(/[:.]/g, '-');
    const key = `${OBJECT_PREFIX}${timestamp}.db.gz.enc`;
    const contentLength = fs.statSync(encryptedPath).size;
    await client.send(new PutObjectCommand({
      Bucket: config.bucket,
      Key: key,
      Body: createReadStream(encryptedPath),
      ContentLength: contentLength,
      ContentType: 'application/octet-stream',
      Metadata: { format: 'tably-sqlite-backup-v1' },
    }));
    await retainNewestObjects(client, config.bucket);
    console.log(`Off-site SQLite backup uploaded: s3://${config.bucket}/${key} (${contentLength} bytes)`);
    return { key, contentLength };
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch (error) {
      console.error('Could not remove temporary backup files:', error.message);
    }
  }
}

function nextBackupTime(now = new Date()) {
  const next = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 2, 30, 0, 0));
  if (next <= now) next.setUTCDate(next.getUTCDate() + 1);
  return next;
}

function startBackupScheduler({
  db,
  config,
  alert = async () => {},
  s3Client,
  now = () => new Date(),
  setTimer = setTimeout,
  clearTimer = clearTimeout,
}) {
  if (!config?.enabled) return { stop: async () => {} };
  const client = s3Client || createS3Client(config);
  let timer;
  let running;
  let stopped = false;

  function schedule() {
    if (stopped) return;
    const current = now();
    const delay = Math.max(0, nextBackupTime(current).getTime() - current.getTime());
    timer = setTimer(() => {
      timer = undefined;
      running = runBackupNow({ db, config, s3Client: client, now: now() })
        .catch(async (error) => {
          const message = `Scheduled off-site backup failed: ${error.message}`;
          console.error(message);
          try {
            await alert(message);
          } catch (alertError) {
            console.error('Backup failure alert could not be delivered:', alertError.message);
          }
        })
        .finally(() => {
          running = undefined;
          schedule();
        });
    }, delay);
    timer.unref?.();
  }

  schedule();
  return {
    async stop() {
      stopped = true;
      if (timer) clearTimer(timer);
      if (running) await running;
    },
  };
}

async function restoreBackup({ config, objectKey, destination, s3Client }) {
  if (!config?.enabled) throw new Error('S3 backup configuration is required for restore');
  if (!objectKey || !destination) {
    throw new Error('Usage: npm run restore-backup -- <object-key> <destination-file>');
  }

  const client = s3Client || createS3Client(config);
  const targetPath = path.resolve(destination);
  const targetDir = path.dirname(targetPath);
  fs.mkdirSync(targetDir, { recursive: true });
  const tempDir = fs.mkdtempSync(path.join(targetDir, '.tably-restore-'));
  const encryptedPath = path.join(tempDir, 'backup.enc');
  const restoredPath = path.join(tempDir, 'restored.db');

  try {
    const response = await client.send(new GetObjectCommand({
      Bucket: config.bucket,
      Key: objectKey,
    }));
    if (!response.Body) throw new Error('S3 returned an empty backup object');
    await pipeline(response.Body, createWriteStream(encryptedPath, { flags: 'wx' }));

    const encryptedStat = fs.statSync(encryptedPath);
    if (encryptedStat.size < HEADER_LENGTH + TAG_LENGTH) throw new Error('Backup object is too small to be valid');
    const file = await fs.promises.open(encryptedPath, 'r');
    let header;
    let tag;
    try {
      header = Buffer.alloc(HEADER_LENGTH);
      tag = Buffer.alloc(TAG_LENGTH);
      await file.read(header, 0, header.length, 0);
      await file.read(tag, 0, tag.length, encryptedStat.size - TAG_LENGTH);
    } finally {
      await file.close();
    }
    if (!header.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error('Backup format is not recognized');

    const decipher = crypto.createDecipheriv('aes-256-gcm', config.encryptionKey, header.subarray(MAGIC.length));
    decipher.setAuthTag(tag);
    await pipeline(
      createReadStream(encryptedPath, { start: HEADER_LENGTH, end: encryptedStat.size - TAG_LENGTH - 1 }),
      decipher,
      createGunzip(),
      createWriteStream(restoredPath, { flags: 'wx' }),
    );
    checkIntegrity(restoredPath);

    fs.renameSync(restoredPath, targetPath);
    for (const suffix of ['-wal', '-shm']) fs.rmSync(`${targetPath}${suffix}`, { force: true });
    console.log(`Verified SQLite backup restored to ${targetPath}`);
    return targetPath;
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch (error) {
      console.error('Could not remove temporary restore files:', error.message);
    }
  }
}

module.exports = {
  REQUIRED_BACKUP_VARS,
  validateBackupConfig,
  checkIntegrity,
  nextBackupTime,
  runBackupNow,
  startBackupScheduler,
  restoreBackup,
};

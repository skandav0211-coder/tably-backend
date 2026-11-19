const { validateBackupConfig, restoreBackup } = require('../src/backup');

async function main() {
  const objectKey = process.argv[2];
  const destination = process.argv[3];
  if (!objectKey || !destination) {
    throw new Error('Usage: npm run restore-backup -- <object-key> <destination-file>');
  }
  const config = validateBackupConfig(process.env);
  if (!config.enabled) throw new Error('Set all BACKUP_S3_* variables and BACKUP_ENCRYPTION_KEY before restoring');
  await restoreBackup({ config, objectKey, destination });
}

main().catch((error) => {
  console.error(`Backup restore failed: ${error.message}`);
  process.exitCode = 1;
});

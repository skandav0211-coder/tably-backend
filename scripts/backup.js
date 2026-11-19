const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

async function main() {
  const destination = process.argv[2];
  if (!destination) throw new Error('Usage: npm run backup -- <destination-file>');
  const source = path.resolve(process.env.DB_FILE || 'billing.db');
  const target = path.resolve(destination);
  if (source === target) throw new Error('Backup destination must differ from DB_FILE');

  fs.mkdirSync(path.dirname(target), { recursive: true });
  const db = new Database(source, { fileMustExist: true });
  try {
    await db.backup(target);
  } finally {
    db.close();
  }
  const size = fs.statSync(target).size;
  console.log(`Backup created: ${target} (${size} bytes)`);
}

main().catch((error) => {
  console.error(`Backup failed: ${error.message}`);
  process.exitCode = 1;
});

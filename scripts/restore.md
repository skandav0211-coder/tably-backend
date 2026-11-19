# Restoring a Railway off-site backup

Restore only while the Railway service is stopped so SQLite has no open handles. The script validates AES-GCM authentication and SQLite integrity before replacing the target file.

1. Stop the Railway service and make a separate copy of the current `/data/billing.db` if it is accessible.
2. Ensure the service environment has the matching `BACKUP_S3_*` settings and the exact `BACKUP_ENCRYPTION_KEY` used when the backup was created.
   If `BACKUP_DISABLED=true`, temporarily unset it for the restore command.
3. Run this from a Railway shell or a trusted environment with access to the same S3 bucket and mounted volume:

   ```sh
   npm run restore-backup -- backups/tably-<timestamp>.db.gz.enc /data/billing.db
   ```

4. Start the service and verify `/health` and application data before discarding the old database copy.

Do not rotate or lose `BACKUP_ENCRYPTION_KEY` without retaining the prior key; encrypted backups are unrecoverable without it.

# Restoring a SQLite backup

1. Stop the service so no process has the database open:

   ```sh
   sudo systemctl stop tably
   ```

2. Verify the backup file and copy it over the configured `DB_FILE` (the production default is `/var/lib/tably/billing.db`):

   ```sh
   sudo cp /var/lib/tably/backups/<backup-file>.db /var/lib/tably/billing.db
   sudo chown tably:tably /var/lib/tably/billing.db
   sudo chmod 600 /var/lib/tably/billing.db
   ```

3. Remove stale SQLite sidecar files for the restored database:

   ```sh
   sudo rm -f /var/lib/tably/billing.db-wal /var/lib/tably/billing.db-shm
   ```

4. Start the service and verify the health endpoint:

   ```sh
   sudo systemctl start tably
   curl -fsS https://YOUR-SUBDOMAIN.duckdns.org/health
   ```

Keep the pre-restore database copy separately until the restored instance has been checked.

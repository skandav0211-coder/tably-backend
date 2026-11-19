# Tably Backend

Standalone Node.js 24 LTS + Express 5 API using synchronous `better-sqlite3`. SQLite stays local to the VM at `/var/lib/tably/billing.db`; no database calls, transactions, schema, or API behavior were converted. The Super Admin portal is deployed separately.

## Local development

```sh
nvm use
npm ci
cp .env.example .env
# Set ADMIN_EMAIL and ADMIN_PASSWORD (at least 12 characters).
npm start
```

By default the local API listens on `0.0.0.0:3000`; set `HOST=127.0.0.1` to bind only to loopback. Development defaults to console email and prints auth codes. To use SMTP locally, set `MAIL_TRANSPORT=smtp` and configure the SMTP variables. Run `npm test` and `npm run lint`.

The database directory is created if absent. SQLite is configured for WAL, a 5-second busy timeout, and foreign keys. Migrations continue to run synchronously at startup from `src/db.js`.

## Production deployment: Ubuntu VM behind Caddy

See [`deploy/setup-ubuntu.md`](deploy/setup-ubuntu.md) for exact commands, service setup, TLS, firewall rules, backups, updates, and secret rotation. The deployment:

- Runs Node as the unprivileged `tably` system user under systemd.
- Binds Express to `127.0.0.1:3000`; Caddy terminates HTTPS and proxies to the loopback service.
- Stores SQLite and backups under `/var/lib/tably`, outside the application checkout.
- Uses Brevo's HTTPS transactional email API by default. SMTP remains selectable with `MAIL_TRANSPORT=smtp`.

### First Super Admin bootstrap

Set `ADMIN_EMAIL` and a strong `ADMIN_PASSWORD` (at least 12 characters) in `/etc/tably.env` before the first start. If the `admins` table is empty, the service creates the initial Super Admin on startup. Admin login remains password plus a one-time email code. In production, all three signing secrets must be distinct, random, and at least 32 characters. Never put actual credentials in `.env.example` or commit an env file.

If the admin password needs recovery on the VM, stop the service and run the existing script against the same `DB_FILE`:

```sh
sudo systemctl stop tably
cd /opt/tably/backend
read -rsp 'New admin password: ' ADMIN_NEW_PASSWORD
printf '\n'
sudo -u tably env DB_FILE=/var/lib/tably/billing.db \
  ADMIN_NEW_PASSWORD="$ADMIN_NEW_PASSWORD" node scripts/admin-recover.js
unset ADMIN_NEW_PASSWORD
sudo systemctl start tably
```

The password is entered without echo and is not included literally in shell history. To change the email too, set `ADMIN_NEW_EMAIL` for that command. The script invalidates existing admin sessions and clears outstanding admin code challenges.

## Backups and restore

Create a consistent online backup with better-sqlite3:

```sh
sudo -u tably env DB_FILE=/var/lib/tably/billing.db npm run backup -- /var/lib/tably/backups/tably-$(date +%F-%H%M%S).db
```

[`deploy/backup.cron`](deploy/backup.cron) shows nightly backups, 14-day local retention, and an example off-VM copy command. Configure off-VM copying to infrastructure you control; a backup only on the VM does not protect against disk loss. Restore steps are documented in [`scripts/restore.md`](scripts/restore.md).

## CORS and app URLs

Set `ADMIN_PORTAL_ORIGINS` to a comma-separated list of exact portal origins, such as `https://admin.example.com`. Entries are trimmed and trailing slashes are removed; production wildcard entries are rejected. The mobile app is not a browser and does not need a CORS entry.

Set `VITE_API_BASE` in the separately deployed portal and `EXPO_PUBLIC_API_BASE` in the mobile app to the public HTTPS API origin. Admin session cookies are HttpOnly and SameSite=Strict; use HTTPS in production.

## Existing accounts and migrations

The SQLite startup migration is retained. It adds email-auth/contact columns, copies each legacy `users.mobile` value into `users.phone`, and preserves unverified legacy email as `legacy_email`. Back up the database before deploying new versions. Existing businesses, billing, devices, and subscriptions remain intact. Verify each legacy customer's identity out of band, then use **Send setup invite to email** from the Super Admin portal; the customer completes the invite in the mobile app to claim the account.

## Verification

```sh
npm ci
npm test
npm run lint
curl -fsS http://127.0.0.1:3000/health
```

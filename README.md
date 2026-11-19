# Tably Backend

Standalone Node.js 24 + Express 5 API using synchronous `better-sqlite3`. SQLite schema, transactions, database calls, and API behavior remain unchanged. The Super Admin portal is deployed separately.

## Local development

```sh
nvm use
npm ci
cp .env.example .env
# Set ADMIN_EMAIL and ADMIN_PASSWORD (at least 12 characters).
npm start
```

By default the API listens on `0.0.0.0:3000`. Development uses console email codes. To use SMTP locally, set `MAIL_TRANSPORT=smtp` and configure the SMTP variables. Run `npm test` and `npm run lint`.

The SQLite database directory is created and checked at startup. SQLite uses WAL, a 5-second busy timeout, and foreign keys. Migrations continue to run synchronously at startup from `src/db.js`.

## Railway deployment

`railway.json` configures `npm start`, the unauthenticated `/health` check, one replica, and restart-on-failure. Deploy this backend as a Railway service and:

1. Attach a Railway volume to the service, mounted at **`/data`**. SQLite is local-file storage; do not run multiple replicas or use an ephemeral path.
2. Set `DB_FILE=/data/billing.db`. The app creates the directory if needed and reports a clear startup error if it cannot write there.
3. Configure the production environment variables in the table below. Production requires distinct 32+ character auth secrets, an admin password, a working email transport, and off-site backup settings (unless backups are deliberately disabled).
4. Generate a Railway public domain and set the separate portal/mobile app API base URLs to that HTTPS origin. Set `ADMIN_PORTAL_ORIGINS` to the exact portal origin.
5. Deploy and verify `https://<your-railway-domain>/health` returns `{"ok":true}`.

Railway sends SIGTERM during redeploys. The app stops accepting requests, waits for an active scheduled backup, runs `PRAGMA wal_checkpoint(TRUNCATE)` when WAL is active, closes SQLite, and exits. `HOST` can be overridden, but defaults to `0.0.0.0` so Railway's proxy can connect.

### First Super Admin bootstrap and recovery

Set `ADMIN_EMAIL` and a strong `ADMIN_PASSWORD` (at least 12 characters) before the first start. If the `admins` table is empty, the service creates the initial Super Admin on startup. Admin login remains password plus a one-time email code. Store credentials in Railway's variables, not in Git.

To recover the Super Admin, use Railway's service shell (or run the command in an environment connected to the same mounted volume) with the app stopped:

```sh
ADMIN_NEW_PASSWORD='<new-password>' DB_FILE=/data/billing.db node scripts/admin-recover.js
```

Set `ADMIN_NEW_EMAIL` for an email change. The script invalidates existing admin sessions and clears outstanding admin code challenges. Avoid putting a real password in a saved shell history; use a one-off secure environment assignment.

## Scheduled encrypted off-site backups

The single Railway app process schedules a backup every day at **02:30 UTC**. The job uses `better-sqlite3`'s online `db.backup()` into a temporary file, verifies `PRAGMA integrity_check`, gzips the snapshot, encrypts it with AES-256-GCM, then uploads it to the configured S3-compatible bucket. It retains the newest 30 objects under `backups/`. A backup failure is logged and sent to `ALERT_WEBHOOK_URL` when configured. The encryption key is never uploaded; keep a secure, independent copy because backups cannot be restored without it.

All six `BACKUP_S3_*` / encryption variables in the table are required in production. In non-production the scheduler is skipped with a warning if backup variables are missing. Set `BACKUP_DISABLED=true` to deliberately disable backups in production; this is not recommended. `railway.json` sets one replica so multiple scheduled jobs do not race.

Restore an object to a destination file using:

```sh
npm run restore-backup -- backups/tably-<timestamp>.db.gz.enc /data/billing.db
```

Stop the Railway service before restoring the live database. The script downloads, decrypts, decompresses, verifies SQLite integrity, and atomically writes the destination. It removes stale `-wal` and `-shm` sidecars. Keep the prior database separately until the restored service is verified.

## Environment variables

| Variable | Required? | Example / default | Purpose / where to get it |
|---|---|---|---|
| `NODE_ENV` | Production | `production` | Set in Railway for production startup validation. |
| `PORT` | No | Railway-provided; local `3000` | HTTP port. Railway provides this automatically. |
| `HOST` | No | `0.0.0.0` | Bind address; keep the default for Railway's proxy. |
| `DB_FILE` | Railway | `/data/billing.db` | SQLite file on the attached Railway volume. |
| `USER_JWT_SECRET` | Yes in production | unique random 32+ characters | Generate with a password manager or `openssl rand -hex 32`. |
| `ADMIN_JWT_SECRET` | Yes in production | different unique random 32+ characters | Generate independently; rotating it invalidates admin sessions. |
| `ENTITLEMENT_SECRET` | Yes in production | different unique random 32+ characters | Generate independently. |
| `ADMIN_EMAIL` | First bootstrap | `owner@example.com` | Initial Super Admin address. |
| `ADMIN_PASSWORD` | Yes in production / first bootstrap | strong password, 12+ characters | Initial Super Admin password; keep it in Railway variables. |
| `MAIL_TRANSPORT` | No | Production defaults to `api`; local defaults to `console` | Choose `api` (Brevo) or `smtp`. |
| `MAIL_FROM` | Yes for email delivery | `verified-sender@example.com` | Verified sender address from Brevo, or sender address for SMTP. |
| `BREVO_API_KEY` | When API email is selected | Brevo API key | Create in the Brevo account; never commit it. |
| `SMTP_HOST` | When SMTP selected | `smtp.example.com` | SMTP host from your email provider. |
| `SMTP_PORT` | No | `587` | SMTP port; use the value supplied by your provider. |
| `SMTP_USER` | Optional for no-auth relay | Provider username | SMTP credential from your provider. |
| `SMTP_PASS` | When `SMTP_USER` is set | Provider password | SMTP credential from your provider. |
| `SMTP_SECURE` | No | `false` | Set to `1` for implicit TLS, commonly port 465. |
| `ADMIN_PORTAL_ORIGINS` | Recommended | `https://admin.example.com` | Exact comma-separated origin(s) of the separately hosted portal. |
| `ALERT_WEBHOOK_URL` | No | Empty | HTTPS webhook URL for alert notifications, including backup failures. |
| `BACKUP_DISABLED` | No | `false` | Set to `true` only to explicitly disable production backups. |
| `BACKUP_S3_ENDPOINT` | Unless backups disabled | `https://<provider-endpoint>` | Endpoint URL from the chosen S3-compatible storage provider. |
| `BACKUP_S3_BUCKET` | Unless backups disabled | `<private-bucket>` | Bucket name created with the storage provider. |
| `BACKUP_S3_KEY_ID` | Unless backups disabled | `<access-key-id>` | S3 access key ID with permission to list, upload, download, and delete backup objects. |
| `BACKUP_S3_SECRET` | Unless backups disabled | `<secret-access-key>` | Secret for the S3 access key; keep private. |
| `BACKUP_S3_REGION` | Unless backups disabled | Provider-specific, e.g. `auto` | Region value required by the S3-compatible provider. |
| `BACKUP_ENCRYPTION_KEY` | Unless backups disabled | 64 hex characters | Generate with `openssl rand -hex 32`; store separately from the bucket credentials. |
| `ADMIN_NEW_PASSWORD` | Recovery only | 12+ character password | Temporary input to `scripts/admin-recover.js`; do not leave configured. |
| `ADMIN_NEW_EMAIL` | Optional recovery only | `new-owner@example.com` | Optional replacement email for the recovery command. |

## Email codes and customer migration

Production defaults to Brevo's HTTPS transactional email API. SMTP remains available with `MAIL_TRANSPORT=smtp`. In development, codes are printed to the backend console. Registration and reset codes expire after 10 minutes, allow five attempts and up to four total sends with a 30-second resend cooldown. Admin sign-in remains password plus emailed code.

The SQLite startup migration is retained. It adds email-auth/contact columns, copies each legacy `users.mobile` value into `users.phone`, and preserves unverified legacy email as `legacy_email`. Back up the database before deploying database-affecting releases. Existing businesses, billing, devices, and subscriptions remain intact. Verify each legacy customer's identity out of band, then use **Send setup invite to email** from the Super Admin portal.

## Verification

```sh
npm ci
npm test
npm run lint
curl -fsS http://127.0.0.1:3000/health
```

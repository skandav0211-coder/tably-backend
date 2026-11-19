# Deploy Tably on a single Ubuntu VM

This deployment keeps SQLite on a persistent local disk, runs Node behind Caddy, and binds the API to loopback in production. Substitute the repository URL and DuckDNS hostname below.

## 1. Prepare Ubuntu and build tools

```sh
sudo apt update
sudo apt install -y ca-certificates curl gnupg git build-essential python3 make g++
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
sudo apt install -y nodejs
node --version
npm --version
```

`better-sqlite3` is a native Node addon. `npm ci` may use a prebuilt binary; build-essential, Python, make, and g++ are installed so it can compile when a matching prebuilt binary is unavailable (including some ARM environments).

## 2. Create the service account and persistent data directory

```sh
sudo useradd --system --create-home --home-dir /opt/tably --shell /usr/sbin/nologin tably
sudo install -d -o tably -g tably -m 0750 /opt/tably /var/lib/tably /var/lib/tably/backups
```

## 3. Clone and install

```sh
sudo -u tably git clone https://github.com/<YOUR-ORG>/tably-backend.git /opt/tably/backend
cd /opt/tably/backend
sudo -u tably npm ci --omit=dev
```

If a native module build fails, install the build tools from step 1 and rerun `npm ci --omit=dev`. Keep `/var/lib/tably` outside the Git checkout so database files and backups persist across updates.

## 4. Configure production secrets

Create `/etc/tably.env` with the following shape, replacing every placeholder. Generate three distinct random secrets (for example with `openssl rand -hex 32`). Use the Brevo API key and a sender address verified in Brevo.

```sh
sudo install -o root -g root -m 0600 /dev/null /etc/tably.env
sudo nano /etc/tably.env
```

```dotenv
NODE_ENV=production
PORT=3000
HOST=127.0.0.1
DB_FILE=/var/lib/tably/billing.db
USER_JWT_SECRET=<distinct-random-secret-at-least-32-characters>
ADMIN_JWT_SECRET=<different-random-secret-at-least-32-characters>
ENTITLEMENT_SECRET=<another-random-secret-at-least-32-characters>
ADMIN_EMAIL=owner@example.com
ADMIN_PASSWORD=<strong-password-at-least-12-characters>
MAIL_TRANSPORT=api
BREVO_API_KEY=<brevo-api-key>
MAIL_FROM=<verified-sender@example.com>
ADMIN_PORTAL_ORIGINS=https://admin.example.com
ALERT_WEBHOOK_URL=
```

The initial `ADMIN_EMAIL` and `ADMIN_PASSWORD` create the first Super Admin on first startup when no admin exists. Store the resulting secrets in your password manager. The env file is read by systemd and is not part of this repository.

For SMTP instead of Brevo, set `MAIL_TRANSPORT=smtp`, `SMTP_HOST`, `SMTP_PORT` (defaults to 587), `SMTP_USER` (optional for a no-auth relay), `SMTP_PASS` when using a username, `SMTP_SECURE=1` for implicit TLS, and `MAIL_FROM`. Cloud providers that block SMTP egress require the API transport.

## 5. Install the systemd unit

```sh
sudo install -o root -g root -m 0644 deploy/tably.service /etc/systemd/system/tably.service
sudo systemctl daemon-reload
sudo systemctl enable tably
sudo systemctl start tably
sudo systemctl status tably --no-pager
```

The unit runs as the `tably` user, restricts writes to `/var/lib/tably`, restarts on failure, and reads `/etc/tably.env`.

## 6. Install and configure Caddy

```sh
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install -y caddy
```

Point the DuckDNS hostname at the VM's public IP. Replace the placeholder host in `deploy/Caddyfile`, then install and reload:

```sh
sudo install -o root -g root -m 0644 deploy/Caddyfile /etc/caddy/Caddyfile
sudo nano /etc/caddy/Caddyfile
sudo systemctl enable --now caddy
sudo systemctl reload caddy
```

Caddy obtains and renews HTTPS certificates automatically when DNS and inbound connectivity are correct.

## 7. Firewall and health check

For UFW:

```sh
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

Do not expose port 3000 publicly; the app listens only on `127.0.0.1`. On Oracle Cloud images, also allow inbound TCP ports 80 and 443 in the cloud security list/network security group.

```sh
curl -fsS https://YOUR-SUBDOMAIN.duckdns.org/health
```

Expected response: `{"ok":true}`.

## 8. Backups and updates

Configure nightly backup and 14-day retention using `deploy/backup.cron`. Set up the documented off-VM copy line with your own SSH destination; a backup only on the VM does not protect against VM or disk loss. Restore instructions are in `scripts/restore.md`.

To update:

```sh
cd /opt/tably/backend
sudo -u tably git pull --ff-only
sudo -u tably npm ci --omit=dev
sudo systemctl restart tably
sudo systemctl status tably --no-pager
curl -fsS https://YOUR-SUBDOMAIN.duckdns.org/health
```

Back up the database before deploying database-affecting releases. Existing startup migrations still run automatically on boot.

## Rotate secrets

Generate and set a new secret in `/etc/tably.env`, then restart the service. Rotating JWT/session signing secrets invalidates tokens signed with the previous values, so customers and the admin must sign in again. Rotate `BREVO_API_KEY` in Brevo and update the env file if the key is exposed; restart after replacement. Change the Super Admin password through the admin recovery procedure below if needed.

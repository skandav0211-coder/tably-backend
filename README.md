# Tably Backend

Standalone Node 22 + Express 5 API and SQLite database. This repository owns the API, authentication, subscriptions, devices, billing records, audit log, and email delivery. The Super Admin portal is deployed separately.

## Run locally

```sh
npm ci
cp .env.example .env
# Set ADMIN_EMAIL and ADMIN_PASSWORD (at least 12 characters).
npm start
```

The API listens on `http://localhost:3000`. In development, verification and reset codes are printed to the server console. Run `npm test` for backend and migration tests.

## Production

Deploy this repository as a Node 22 service. Configure:

- `NODE_ENV=production`, `PORT` (normally supplied by the host)
- `DB_FILE` pointing to a persistent mounted volume; SQLite data must survive restarts and deployments
- Distinct strong values for `USER_JWT_SECRET`, `ADMIN_JWT_SECRET`, and `ENTITLEMENT_SECRET`
- `ADMIN_EMAIL` and `ADMIN_PASSWORD` for first-time Super Admin bootstrap
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_SECURE`, and `MAIL_FROM`
- `ADMIN_PORTAL_ORIGINS` as a comma-separated allowlist of exact portal origins, e.g. `https://admin.example.com`

Use the API's HTTPS origin as `VITE_API_BASE` in the Super Admin portal and `EXPO_PUBLIC_API_BASE` in the mobile app. For the portal's cookie-based sign-in, host the API and portal on the same site (for example `api.example.com` and `admin.example.com`) and allow the portal origin above. Never commit `.env` or database files.

The API is now independent of the portal build and does not serve portal files. Admin endpoints remain under `/admin-api`.

## Existing database

The SQLite startup migration is retained. It adds email-auth/contact columns, copies each legacy `users.mobile` value to `users.phone`, and preserves unverified legacy email as `legacy_email`. Back up the persistent database before first deployment. Existing businesses, billing, devices, and subscriptions remain intact. Verify each legacy customer's identity out of band, then use **Send setup invite to email** from the Super Admin portal; the customer completes the invite in the mobile app to claim the account.

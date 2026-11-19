const test = require('node:test');
const assert = require('node:assert/strict');
const { validateProductionEnv } = require('../src/config');
const { createMailer } = require('../src/mailer');
const { createApp } = require('../src/app');
const { openDb } = require('../src/db');

const validProductionEnv = () => ({
  NODE_ENV: 'production',
  USER_JWT_SECRET: 'u'.repeat(40),
  ADMIN_JWT_SECRET: 'a'.repeat(40),
  ENTITLEMENT_SECRET: 'e'.repeat(40),
  ADMIN_PASSWORD: 'strong-admin-password',
});

test('production validation rejects missing, short, repeated, example secrets and weak admin passwords', () => {
  const missing = validProductionEnv();
  delete missing.USER_JWT_SECRET;
  assert.throws(() => validateProductionEnv(missing), /USER_JWT_SECRET must be set/);

  const short = validProductionEnv();
  short.ADMIN_JWT_SECRET = 'short';
  assert.throws(() => validateProductionEnv(short), /at least 32 characters/);

  const repeated = validProductionEnv();
  repeated.ADMIN_JWT_SECRET = repeated.USER_JWT_SECRET;
  assert.throws(() => validateProductionEnv(repeated), /must be different values/);

  const example = validProductionEnv();
  example.USER_JWT_SECRET = 'replace-this-user-jwt-secret-with-32-random-characters';
  assert.throws(() => validateProductionEnv(example), /from .env.example/);

  const weakPassword = validProductionEnv();
  weakPassword.ADMIN_PASSWORD = 'too-short';
  assert.throws(() => validateProductionEnv(weakPassword), /ADMIN_PASSWORD/);

  const missingPassword = validProductionEnv();
  delete missingPassword.ADMIN_PASSWORD;
  assert.throws(() => validateProductionEnv(missingPassword), /ADMIN_PASSWORD must be set/);
});

test('production CORS configuration rejects wildcard origins', () => {
  const keys = ['NODE_ENV', 'ADMIN_PORTAL_ORIGINS', 'USER_JWT_SECRET', 'ADMIN_JWT_SECRET', 'ENTITLEMENT_SECRET', 'ADMIN_PASSWORD'];
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  for (const [key, value] of Object.entries(validProductionEnv())) process.env[key] = value;
  process.env.ADMIN_PORTAL_ORIGINS = 'https://*.example.com';
  const db = openDb(':memory:');
  try {
    assert.throws(() => createApp(db, { mailer: { sendMail: async () => {} } }), /wildcard origins/);
  } finally {
    db.close();
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test('mailer defaults to console locally and selects configured SMTP', () => {
  assert.equal(createMailer({ NODE_ENV: 'development' }).kind, 'console');
  assert.equal(createMailer({
    NODE_ENV: 'development',
    SMTP_HOST: 'smtp.example.test',
    SMTP_PORT: '587',
    SMTP_USER: 'mailer',
    SMTP_PASS: 'password',
    MAIL_FROM: 'sender@example.test',
  }).kind, 'smtp');
});

test('Brevo API sends the branded inline logo and does not expose credentials in errors', async () => {
  let request;
  const mailer = createMailer({
    NODE_ENV: 'production',
    MAIL_TRANSPORT: 'api',
    MAIL_FROM: 'verified@example.test',
    BREVO_API_KEY: 'test-secret-key',
  }, async (url, options) => {
    request = { url, options };
    return { ok: true, status: 201 };
  });
  await mailer.sendMail({
    to: 'customer@example.test',
    subject: 'Test code',
    text: 'Code body',
    html: '<img src="cid:tably-logo">',
    attachments: [{ filename: 'tably.png', path: require('node:path').join(__dirname, '..', 'assets', 'logo-mark.png'), cid: 'tably-logo' }],
  });
  assert.equal(mailer.kind, 'api');
  assert.equal(request.url, 'https://api.brevo.com/v3/smtp/email');
  assert.equal(request.options.headers['api-key'], 'test-secret-key');
  const payload = JSON.parse(request.options.body);
  assert.equal(payload.sender.email, 'verified@example.test');
  assert.equal(payload.to[0].email, 'customer@example.test');
  assert.equal(payload.attachment[0].contentId, 'tably-logo');
  assert.ok(Buffer.from(payload.attachment[0].content, 'base64').length > 0);

  const failed = createMailer({
    NODE_ENV: 'production',
    MAIL_TRANSPORT: 'api',
    MAIL_FROM: 'verified@example.test',
    BREVO_API_KEY: 'never-log-this',
  }, async () => ({ ok: false, status: 503 }));
  await assert.rejects(() => failed.sendMail({ to: 'a@b.test', subject: 's', text: 't', html: 'h' }), (error) => {
    assert.match(error.message, /HTTP 503/);
    assert.doesNotMatch(error.message, /never-log-this/);
    return true;
  });
});

test('selected email transports fail fast when required configuration is missing', () => {
  assert.throws(() => createMailer({ NODE_ENV: 'production' }), /MAIL_FROM/);
  assert.throws(() => createMailer({
    NODE_ENV: 'production',
    MAIL_TRANSPORT: 'api',
    MAIL_FROM: 'sender@example.test',
  }), /BREVO_API_KEY/);
  assert.throws(() => createMailer({
    NODE_ENV: 'production',
    MAIL_TRANSPORT: 'smtp',
    MAIL_FROM: 'sender@example.test',
  }), /SMTP_HOST/);
});

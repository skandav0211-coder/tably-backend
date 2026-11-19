const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');

const logoPath = path.join(__dirname, '..', 'assets', 'logo-mark.png');

function selectedTransport(env) {
  const configured = env.MAIL_TRANSPORT;
  if (configured) return configured;
  if (env.NODE_ENV === 'production') return 'api';
  return env.SMTP_HOST ? 'smtp' : 'console';
}

function validateMailerConfig(env = process.env) {
  const transport = selectedTransport(env);
  if (transport === 'console' && env.NODE_ENV !== 'production') return transport;
  if (!['api', 'smtp'].includes(transport)) {
    throw new Error('MAIL_TRANSPORT must be api or smtp (console is development-only)');
  }
  if (transport === 'api' && !env.MAIL_FROM) throw new Error('MAIL_FROM must be set when MAIL_TRANSPORT=api');
  if (transport === 'api' && !env.BREVO_API_KEY) throw new Error('BREVO_API_KEY must be set when MAIL_TRANSPORT=api');
  if (transport === 'smtp') {
    const missing = ['SMTP_HOST'].filter((key) => !env[key]);
    if (!env.MAIL_FROM && !env.SMTP_USER) missing.push('MAIL_FROM (or SMTP_USER)');
    if (env.SMTP_USER && !env.SMTP_PASS) missing.push('SMTP_PASS');
    if (missing.length) throw new Error(`Set ${missing.join(', ')} when MAIL_TRANSPORT=smtp`);
  }
  return transport;
}

function apiAttachment(attachment) {
  const content = attachment.content || fs.readFileSync(attachment.path).toString('base64');
  return {
    name: attachment.filename,
    content,
    ...(attachment.cid ? { contentId: attachment.cid } : {}),
  };
}

function createMailer(env = process.env, fetchImpl = globalThis.fetch) {
  const transportKind = validateMailerConfig(env);
  if (transportKind === 'api') {
    if (typeof fetchImpl !== 'function') throw new Error('Fetch is required for the Brevo email API transport');
    return {
      kind: 'api',
      async sendMail({ to, subject, text, html, attachments = [] }) {
        const response = await fetchImpl('https://api.brevo.com/v3/smtp/email', {
          method: 'POST',
          headers: { 'api-key': env.BREVO_API_KEY, 'content-type': 'application/json' },
          body: JSON.stringify({
            sender: { email: env.MAIL_FROM, name: 'Tably' },
            to: [{ email: to }],
            subject,
            textContent: text,
            htmlContent: html,
            ...(attachments.length ? { attachment: attachments.map(apiAttachment) } : {}),
          }),
        });
        if (!response.ok) throw new Error(`Brevo email API returned HTTP ${response.status}`);
      },
    };
  }
  if (transportKind === 'smtp') {
    const port = Number(env.SMTP_PORT || 587);
    const transport = nodemailer.createTransport({ host: env.SMTP_HOST, port, secure: env.SMTP_SECURE === '1' || port === 465,
      auth: env.SMTP_USER ? { user: env.SMTP_USER, pass: env.SMTP_PASS } : undefined });
    return { kind: 'smtp', sendMail: (m) => transport.sendMail({ from: env.MAIL_FROM || env.SMTP_USER, ...m }), verify: () => transport.verify() };
  }
  return { kind: 'console', sendMail: async (m) => { console.log(`[DEV MAIL] to=${m.to} | ${m.subject}\n${m.text}\n`); } };
}

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function signInCodeEmail({ to, code, minutes, ip, when }) {
  const text = `Your Tably Super Admin sign-in code is ${code}\n\nIt expires in ${minutes} minutes and works once.\nRequested from ${ip || 'unknown address'} at ${when}.\n\nIf this was not you, someone knows your password: change it immediately (see the recovery steps in the README) and do not share this code with anyone.`;
  const html = `<div style="font-family:Arial,Helvetica,sans-serif;background:#faf7f2;padding:28px"><div style="max-width:460px;margin:auto;background:#fff;border-radius:16px;padding:28px;border:1px solid #eadfd3">
<img src="cid:tably-logo" width="64" alt="Tably" style="display:block;margin:0 auto 12px"><h2 style="text-align:center;margin:0 0 4px;color:#2b2523">Your sign-in code</h2>
<p style="text-align:center;color:#6b5f58;margin:0 0 18px">Use this code to finish signing in to the Tably admin portal.</p>
<div style="text-align:center;font-size:36px;letter-spacing:10px;font-weight:700;color:#d9731c;background:#fff4e8;border-radius:12px;padding:16px 0">${esc(code)}</div>
<p style="color:#6b5f58;font-size:13px;margin:18px 0 0">Expires in ${minutes} minutes and works once.<br>Requested from ${esc(ip || 'unknown address')} at ${esc(when)}.</p>
<p style="color:#b42318;font-size:13px">Not you? Someone knows your password. Change it immediately and never share this code.</p></div></div>`;
  return { to, subject: 'Your Tably sign-in code', text, html, attachments: [{ filename: 'tably.png', path: path.join(__dirname, '..', 'assets', 'logo-mark.png'), cid: 'tably-logo' }] };
}
function authCodeEmail({ to, code, minutes, purpose }) {
  const isReset = purpose === 'reset';
  const subject = isReset ? 'Reset your Tably password' : purpose === 'setup' ? 'Set up your Tably account' : 'Verify your Tably email';
  const heading = isReset ? 'Password reset code' : purpose === 'setup' ? 'Account setup code' : 'Verify your email';
  const action = isReset ? 'Use this code to reset your Tably password.' : purpose === 'setup' ? 'Use this code to set up your Tably account.' : 'Use this code to verify your email and finish creating your Tably account.';
  const text = `${action}\n\nYour code is ${code}. It expires in ${minutes} minutes and works once. If you did not request this, you can ignore this email.`;
  const html = `<div style="font-family:Arial,Helvetica,sans-serif;background:#faf7f2;padding:28px"><div style="max-width:460px;margin:auto;background:#fff;border-radius:16px;padding:28px;border:1px solid #eadfd3">
<img src="cid:tably-logo" width="64" alt="Tably" style="display:block;margin:0 auto 12px"><h2 style="text-align:center;margin:0 0 4px;color:#2b2523">${heading}</h2>
<p style="text-align:center;color:#6b5f58;margin:0 0 18px">${esc(action)}</p>
<div style="text-align:center;font-size:36px;letter-spacing:10px;font-weight:700;color:#d9731c;background:#fff4e8;border-radius:12px;padding:16px 0">${esc(code)}</div>
<p style="color:#6b5f58;font-size:13px;margin:18px 0 0">Expires in ${minutes} minutes and works once. If you did not request this, ignore this email.</p></div></div>`;
  return { to, subject, text, html, attachments: [{ filename: 'tably.png', path: path.join(__dirname, '..', 'assets', 'logo-mark.png'), cid: 'tably-logo' }] };
}
module.exports = { createMailer, validateMailerConfig, signInCodeEmail, authCodeEmail };

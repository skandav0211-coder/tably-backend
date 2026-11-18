const path = require('path');
const nodemailer = require('nodemailer');

// Sends real email through SMTP when SMTP_HOST is set. Without SMTP it only prints to the console in development
// and returns null in production (the server then refuses to start, because admins could not receive sign-in codes).
function createMailer(env = process.env) {
  if (env.SMTP_HOST) {
    const port = Number(env.SMTP_PORT || 587);
    const transport = nodemailer.createTransport({ host: env.SMTP_HOST, port, secure: env.SMTP_SECURE === '1' || port === 465,
      auth: env.SMTP_USER ? { user: env.SMTP_USER, pass: env.SMTP_PASS } : undefined });
    return { kind: 'smtp', send: (m) => transport.sendMail({ from: env.MAIL_FROM || env.SMTP_USER, ...m }), verify: () => transport.verify() };
  }
  if (env.NODE_ENV === 'production') return null;
  return { kind: 'console', send: async (m) => { console.log(`[DEV MAIL] to=${m.to} | ${m.subject}\n${m.text}\n`); } };
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
module.exports = { createMailer, signInCodeEmail, authCodeEmail };

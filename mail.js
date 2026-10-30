'use strict';
// Email codes. Set RESEND_API_KEY and MAIL_FROM (for example "Izel <hello@yourdomain.com>").
module.exports = function mail(E) {
  const ready = () => !!E.RESEND_API_KEY;
  async function send(to, subject, text) {
    if (!E.RESEND_API_KEY) throw new Error('No email provider configured');
    const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: 'Bearer ' + E.RESEND_API_KEY.trim(), 'Content-Type': 'application/json' }, body: JSON.stringify({ from: E.MAIL_FROM || 'Izel <onboarding@resend.dev>', to: [to], subject, text }) });
    if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error('Email ' + r.status + (d.message ? ': ' + d.message : '')); }
  }
  return { send, ready };
};

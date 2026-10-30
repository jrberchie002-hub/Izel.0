'use strict';
// Email codes. Set RESEND_API_KEY and MAIL_FROM (for example "Izel <hello@yourdomain.com>").
module.exports = function mail(E) {
  const ready = () => !!(E.BREVO_API_KEY && E.BREVO_SENDER) || !!E.RESEND_API_KEY;
  async function send(to, subject, text) {
    if (E.BREVO_API_KEY && E.BREVO_SENDER) {
      const b = await fetch('https://api.brevo.com/v3/smtp/email', { method: 'POST', headers: { 'api-key': E.BREVO_API_KEY.trim(), 'Content-Type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ sender: { name: 'Izel', email: E.BREVO_SENDER.trim() }, to: [{ email: to }], subject, textContent: text }) });
      if (!b.ok) { const d = await b.json().catch(() => ({})); throw new Error('Email ' + b.status + (d.message ? ': ' + d.message : '')); }
      return;
    }
    if (!E.RESEND_API_KEY) throw new Error('No email provider configured');
    const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: 'Bearer ' + E.RESEND_API_KEY.trim(), 'Content-Type': 'application/json' }, body: JSON.stringify({ from: E.MAIL_FROM || 'Izel <onboarding@resend.dev>', to: [to], subject, text }) });
    if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error('Email ' + r.status + (d.message ? ': ' + d.message : '')); }
  }
  return { send, ready };
};

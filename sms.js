'use strict';
// SMS providers: Hubtel, Arkesel, mNotify. Set the keys of ONE of them in the environment.
const phoneKey = (p) => String(p).replace(/\D/g, '');
module.exports = function sms(E) {
  const from = () => String(E.SMS_SENDER || 'Izel').slice(0, 11);
  const ready = () => !!((E.HUBTEL_SMS_CLIENT_ID && E.HUBTEL_SMS_CLIENT_SECRET) || E.ARKESEL_API_KEY || E.MNOTIFY_API_KEY);
  async function send(to, text) {
    const n = phoneKey(to);
    if (E.HUBTEL_SMS_CLIENT_ID && E.HUBTEL_SMS_CLIENT_SECRET) {
      const r = await fetch('https://sms.hubtel.com/v1/messages/send', { method: 'POST', headers: { Authorization: 'Basic ' + Buffer.from(E.HUBTEL_SMS_CLIENT_ID.trim() + ':' + E.HUBTEL_SMS_CLIENT_SECRET.trim()).toString('base64'), 'Content-Type': 'application/json' }, body: JSON.stringify({ From: from(), To: n, Content: text }) });
      if (!r.ok) throw new Error('Hubtel ' + r.status); return;
    }
    if (E.ARKESEL_API_KEY) {
      const r = await fetch('https://sms.arkesel.com/api/v2/sms/send', { method: 'POST', headers: { 'api-key': E.ARKESEL_API_KEY.trim(), 'Content-Type': 'application/json' }, body: JSON.stringify({ sender: from(), message: text, recipients: [n] }) });
      const d = await r.json().catch(() => ({})); if (!r.ok || (d.status && String(d.status).toLowerCase() !== 'success')) throw new Error('Arkesel: ' + (d.message || r.status)); return;
    }
    if (E.MNOTIFY_API_KEY) {
      const r = await fetch('https://api.mnotify.com/api/sms/quick?key=' + encodeURIComponent(E.MNOTIFY_API_KEY.trim()), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ recipient: [n], sender: from(), message: text }) });
      if (!r.ok) throw new Error('mNotify ' + r.status); return;
    }
    throw new Error('No SMS provider configured');
  }
  return { send, ready };
};

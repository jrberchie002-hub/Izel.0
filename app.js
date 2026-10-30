'use strict';
const crypto = require('crypto');
const R = require('./rules');
  const SHOW = require('./showcase');

module.exports = function makeApp(E, store, smsImpl, fetchImpl) {
  const sms = smsImpl || require('./sms')(E);
  const mailer = require('./mail')(E);
  const doFetch = fetchImpl || fetch;
  const SECRET = E.AUTH_SECRET || 'dev-secret-change-me';
  const DEV = E.OTP_DEV === '1', OTPN = Math.min(10, Math.max(4, +E.OTP_LENGTH || 6));
  const devCode = () => '1234567890'.slice(0, OTPN);
  const ADMINS = String(E.ADMIN_PHONES || '').split(',').map(s => normPhone(s)).filter(Boolean).concat(String(E.ADMIN_EMAILS || '').split(',').map(s => normEmail(s)).filter(Boolean).map(s => 'e:' + s));
  const now = () => Date.now();
  const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
  const rid = (p) => p + crypto.randomBytes(8).toString('hex');
  const b64u = (b) => Buffer.from(b).toString('base64url');
  function sign(p) { const body = b64u(JSON.stringify(p)); return body + '.' + crypto.createHmac('sha256', SECRET).update(body).digest('base64url'); }
  function unsign(t) { try { const [b, s] = String(t).split('.'); const ok = crypto.createHmac('sha256', SECRET).update(b).digest('base64url'); if (s !== ok) return null; const p = JSON.parse(Buffer.from(b, 'base64url').toString()); return p.exp > now() ? p : null; } catch (e) { return null; } }
  function normEmail(e) { e = String(e || '').trim().toLowerCase(); return /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/.test(e) ? e : ''; }
  function ident(b) { if (b && b.email) { const e = normEmail(b.email); return e ? 'e:' + e : ''; } return normPhone(b && b.phone); }
  function normPhone(p) { let d = String(p || '').replace(/\D/g, ''); if (d.length === 10 && d[0] === '0') d = '233' + d.slice(1); return d.length >= 11 && d.length <= 15 ? d : ''; }
  const cors = () => { const o = E.ALLOWED_ORIGINS ? E.ALLOWED_ORIGINS : '*'; return { 'Access-Control-Allow-Origin': o, 'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Kind', 'Access-Control-Allow-Methods': 'GET,POST,PUT,OPTIONS', 'Access-Control-Max-Age': '600' }; };
  const out = (status, obj, h) => ({ status, headers: Object.assign({ 'Content-Type': 'application/json' }, cors(), h || {}), body: JSON.stringify(obj) });
  const err = (status, msg, extra) => out(status, Object.assign({ error: msg }, extra || {}));
  const isAdmin = (u) => !!(u && (u.roles || []).includes('admin'));
  const str = (x, n) => String(x == null ? '' : x).slice(0, n || 200);
  const sigOf = (m) => [m.from, m.t, m.x].join('|');
  const clone = (o) => JSON.parse(JSON.stringify(o));

  /* ---------- auth ---------- */
  async function authed(req) {
    const h = req.headers || {}, a = String(h.authorization || h.Authorization || '');
    const tok = a.startsWith('Bearer ') ? a.slice(7) : (req.query && req.query.t) || '';
    const p = unsign(tok); if (!p) return null;
    const u = await store.get('users', p.uid); if (!u) return null;
    const f = (await store.get('flags', u.id)) || {}; if (f.banned) return null;
    return u;
  }
  const OV = String(E.OVERRIDE_CODE || '').trim(), isOv = (b) => !!OV && b && b.email && String(b.email).trim() === OV;
  async function sendOtp(body) {
    if (isOv(body)) return out(200, { ok: true, exists: true, override: true });
    const phone = ident(body); if (!phone) return err(400, body.email ? 'Enter a valid email address' : 'Enter a valid phone number');
    const rec = (await store.get('otps', phone)) || { sent: [] }; rec.sent = (rec.sent || []).filter(t => t > now() - 600000);
    if (rec.sent.length >= 3) return err(429, 'Too many codes. Wait a few minutes and try again.');
    const code = DEV ? devCode() : String(crypto.randomInt(0, 10 ** OTPN)).padStart(OTPN, '0');
    rec.h = sha(code + SECRET + phone); rec.exp = now() + 300000; rec.tries = 0; rec.sent.push(now());
    if (!DEV) {
      const msg = 'Your Izel code is ' + code + '. It expires in 5 minutes. Never share it.';
      if (phone.startsWith('e:')) { if (!mailer.ready()) return err(503, 'Email sign-in is not set up yet. Use your phone number.'); try { await mailer.send(phone.slice(2), 'Your Izel code', msg); } catch (e) { return err(502, 'Could not send the code: ' + e.message); } }
      else { if (!sms.ready()) return err(503, 'Phone codes are not switched on yet. Please use your email.'); try { await sms.send(phone, msg); } catch (e) { return err(502, 'Could not send the code: ' + e.message); } }
    }
    await store.put('otps', phone, rec);
    const exists = await store.get('phones', phone);
    return out(200, { ok: true, exists: !!exists, devCode: DEV ? code : undefined });
  }
  async function verifyOtp(body) {
    if (isOv(body)) {
      const rec = (await store.get('otps', 'ov')) || { n: 0, at: now() }; if (rec.at < now() - 600000) { rec.n = 0; rec.at = now(); }
      if (rec.n >= 5) return err(429, 'Too many tries. Wait ten minutes.');
      if (String(body.code || '').trim() !== OV) { rec.n++; await store.put('otps', 'ov', rec); return err(400, 'That code is not right. Try again.'); }
      const ad = ADMINS.find(a => a.startsWith('e:')) || ADMINS[0]; if (!ad) return err(400, 'Add your email to ADMIN_EMAILS first.');
      return loginAs(ad, { mode: 'up', adult: true, name: 'Izel Team' });
    }
    const phone = ident(body), code = str(body.code, 12).trim(); if (!phone) return err(400, body.email ? 'Enter a valid email address' : 'Enter a valid phone number');
    if (body.mode === 'up' && body.adult !== true) return err(400, 'You must be 18 or older to use Izel.');
    const rec = await store.get('otps', phone); if (!rec || !rec.h || rec.exp < now()) return err(400, 'That code has expired. Ask for a new one.');
    if (rec.tries >= 5) return err(429, 'Too many tries. Ask for a new code.');
    if (sha(code + SECRET + phone) !== rec.h) { rec.tries++; await store.put('otps', phone, rec); return err(400, 'That code is not right. Try again.'); }
    await store.del('otps', phone);
    return loginAs(phone, body);
  }
  async function loginAs(phone, body) {
    let ph = await store.get('phones', phone), u = ph ? await store.get('users', ph.uid) : null, isNew = false;
    if (!u) {
      if (body.mode === 'in') return err(404, 'No account for that ' + (phone.startsWith('e:') ? 'email' : 'number') + '. Create one first.', { code: 'no_account' });
      const name = str(body.name, 60).trim() || 'Izel user'; isNew = true;
      const isAd = ADMINS.includes(phone), id = isAd && !(await store.get('users', 'u_admin')) ? 'u_admin' : 'u_' + sha(phone).slice(0, 10);
      u = { id, name: isAd ? 'Izel Team' : name, roles: isAd ? ['admin'] : [], createdAt: now(), adult: true };
      if (phone.startsWith('e:')) u.email = phone.slice(2); else u.phone = phone;
      { const c = String(body.contact || '').replace(/\D/g, ''); if (c.length >= 9 && c.length <= 15) u.phone = c; }
      await store.put('users', id, u, id); await store.put('phones', phone, { uid: id });
      if (!isAd) await starterChats(u);
    } else if (ADMINS.includes(phone) && !isAdmin(u)) { u.roles = (u.roles || []).concat('admin'); await store.put('users', u.id, u, u.id); }
    const f = (await store.get('flags', u.id)) || {}; if (f.banned) return err(403, 'This account was removed for breaking Izel’s rules.');
    return out(200, { ok: true, isNew, token: sign({ uid: u.id, exp: now() + 30 * 864e5 }), user: u });
  }

  /* ---------- Google and Apple sign-in ---------- */
  function b64d(x) { return Buffer.from(x.replace(/-/g, '+').replace(/_/g, '/'), 'base64'); }
  async function socialIdentity(provider, body) {
    const tok = String(body.credential || '');
    if (provider === 'google') {
      if (!E.GOOGLE_CLIENT_ID) return { error: 'Google sign-in is not switched on yet.' };
      const r = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(tok)); const j = await r.json().catch(() => ({}));
      if (!r.ok || j.aud !== E.GOOGLE_CLIENT_ID || !(j.email_verified === 'true' || j.email_verified === true) || !j.email) return { error: 'Google sign-in failed. Try again.' };
      return { email: String(j.email).toLowerCase(), name: j.name };
    }
    if (!E.APPLE_CLIENT_ID) return { error: 'Apple sign-in is not switched on yet.' };
    const p = tok.split('.'); if (p.length !== 3) return { error: 'Apple sign-in failed. Try again.' };
    let head, pay; try { head = JSON.parse(b64d(p[0]).toString()); pay = JSON.parse(b64d(p[1]).toString()); } catch (e) { return { error: 'Apple sign-in failed. Try again.' }; }
    const keys = await (await fetch('https://appleid.apple.com/auth/keys')).json().catch(() => ({ keys: [] })), jwk = (keys.keys || []).find(k => k.kid === head.kid);
    if (!jwk) return { error: 'Apple sign-in failed. Try again.' };
    const ok = crypto.verify('RSA-SHA256', Buffer.from(p[0] + '.' + p[1]), crypto.createPublicKey({ key: jwk, format: 'jwk' }), b64d(p[2]));
    if (!ok || pay.iss !== 'https://appleid.apple.com' || pay.aud !== E.APPLE_CLIENT_ID || pay.exp * 1000 < now() || !pay.email) return { error: 'Apple sign-in failed. Try again.' };
    return { email: String(pay.email).toLowerCase(), name: str(body.name, 60) };
  }
  async function socialLogin(provider, body) {
    const id = await socialIdentity(provider, body); if (id.error) return err(400, id.error);
    const phone = 'e:' + id.email, ph = await store.get('phones', phone);
    if (!ph && body.mode === 'up' && body.adult !== true) return err(400, 'You must be 18 or older to use Izel.');
    return loginAs(phone, Object.assign({}, body, { name: body.name || id.name }));
  }

  /* ---------- views of records ---------- */
  function pubUser(u) { return { id: u.id, name: u.name, org: u.org, caretaker: u.caretaker, photo: u.photo, guest: false, respH: u.respH, rtMs: u.rtMs, rterms: u.rterms, roles: (u.roles || []).includes('admin') ? ['admin'] : [], kyc: u.kyc ? { status: u.kyc.status } : undefined, agent: u.agent ? { status: u.agent.status, areas: u.agent.areas, rating: u.agent.rating, jobs: u.agent.jobs, bio: u.agent.bio, on: u.agent.on, reviews: u.agent.reviews } : undefined }; }
  const PUBLIC = new Set(['listings', 'partners', 'asks']);
  const PRIV_COLLS = new Set(['phones', 'otps', 'pays', 'payouts', 'flags', 'media', 'vw', 'meta', 'vearn', 'vtries']);
  const PULL = ['users', 'listings', 'chats', 'visits', 'tours', 'dealRooms', 'deals', 'holds', 'reports', 'services', 'partners', 'notifs', 'saved', 'queue', 'asks', 'agreements'];

  async function pull(me, since) {
    try { await settleOverdue(); } catch (e) {}
    const rows = await store.since(since, PULL), admin = isAdmin(me);
    const L = new Map((await store.list('listings')).map(r => [r.id, r.data]));
    let cursor = since; rows.forEach(r => { if (r.u > cursor) cursor = r.u; });
    const data = {}; PULL.forEach(c => data[c] = []);
    const needL = new Set(), needU = new Set();
    const add = (c, id, d) => { data[c].push({ id, d }); };
    for (const r of rows) {
      const d = r.data, c = r.c, id = r.id;
      if (c === 'users') continue;
      if (c === 'listings') { if (admin || d.status === 'live' || d.owner === me.id) { add(c, id, d); needU.add(d.owner); } continue; }
      if (c === 'partners' || c === 'asks' || c === 'queue') { add(c, id, d); continue; }
      if (c === 'notifs' || c === 'saved') { if (id === me.id || (admin && c === 'notifs' && id === 'u_admin')) add(c, id, d); continue; }
      if (c === 'chats') { if (admin || d.a === me.id || d.b === me.id) { add(c, id, d); needU.add(d.a); needU.add(d.b); if (d.listing) needL.add(d.listing); } continue; }
      if (c === 'visits') { const l = L.get(d.listing); if (admin || d.seeker === me.id || d.agent === me.id || (l && l.owner === me.id)) { add(c, id, d); needU.add(d.seeker); if (d.agent) needU.add(d.agent); needL.add(d.listing); } continue; }
      if (c === 'tours') { if (admin || d.seeker === me.id || d.agent === me.id) { add(c, id, d); needU.add(d.seeker); if (d.agent) needU.add(d.agent); (d.listings || []).forEach(x => needL.add(x)); } continue; }
      if (c === 'dealRooms' || c === 'deals') { if (admin || d.seeker === me.id || d.owner === me.id) { add(c, id, d); needU.add(d.seeker); needU.add(d.owner); needL.add(d.listing); } continue; }
      if (c === 'agreements') { if (admin || d.seeker === me.id || d.owner === me.id) { add(c, id, d); needU.add(d.seeker); needU.add(d.owner); needL.add(d.listing); } continue; }
      if (c === 'holds') { const l = L.get(d.listing); if (admin || d.seeker === me.id || (l && l.owner === me.id)) { add(c, id, d); needU.add(d.seeker); needL.add(d.listing); } continue; }
      if (c === 'reports') { if (admin || d.by === me.id) add(c, id, d); continue; }
      if (c === 'services') { if (admin || d.by === me.id) add(c, id, d); continue; }
    }
    const have = new Set(data.listings.map(x => x.id));
    needL.forEach(id => { const l = L.get(id); if (l && !have.has(id) && (admin || l.status === 'live' || l.owner === me.id || true)) { add('listings', id, l); needU.add(l.owner); have.add(id); } });
    needU.add(me.id);
    const changedU = rows.filter(r => r.c === 'users').map(r => r.id); changedU.forEach(id => needU.add(id));
    for (const id of needU) { if (!id) continue; const u = await store.get('users', id); if (!u) continue; if (!changedU.includes(id) && since > 0 && id !== me.id && !rows.some(r => r.id !== id)) {} add('users', id, id === me.id || admin ? u : pubUser(u)); }
    const f = (await store.get('flags', me.id)) || {};
    return { cursor, data, me: { strikes: f.strikes || 0, blocked: f.blocked || 0, banned: !!f.banned } };
  }

  /* ---------- helpers for writes ---------- */
  async function flag(uid, fn) { const f = (await store.get('flags', uid)) || {}; fn(f); await store.put('flags', uid, f); return f; }
  async function notify(uid, x) { const n = (await store.get('notifs', uid)) || { id: uid, list: [] }; n.list.unshift({ t: now(), x: str(x, 220) }); n.list = n.list.slice(0, 60); await store.put('notifs', uid, n, uid); }
  async function strike(me, reason, chat) {
    const own = (await store.list('listings')).filter(r => r.data.owner === me.id);
    const f = await flag(me.id, f => { f.strikes = (f.strikes || 0) + 1; if (f.strikes >= 2) f.blocked = now() + 864e5; if (f.strikes >= 4 || (own.length && f.strikes >= 2)) f.banned = true; });
    let n = 0; for (const r of own) { if (r.data.status === 'live') { r.data.status = 'suspended'; await store.put('listings', r.id, r.data, me.id); n++; } }
    const rep = { id: rid('r'), by: 'system', target: me.id, listing: chat && chat.listing || null, reason, t: now(), status: n ? 'actioned' : 'open' };
    await store.put('reports', rep.id, rep); await notify('u_admin', 'Contact sharing blocked from ' + me.name + (n ? '. ' + n + ' listing(s) taken down.' : '.'));
    return f;
  }
  const FREQS = ['monthly', 'quarterly', 'upfront'], DURS = [6, 12, 18, 24, 36];
  function dueNow(rent, dur, freq) { const n = freq === 'monthly' ? 1 : freq === 'quarterly' ? 3 : dur, svc = Math.round(rent * .05); return { n, rentDue: rent * n, deposit: rent, service: svc * n, svcMonthly: svc, total: rent * n + rent + svc * n }; }
  function cleanSig(g) { if (!g || typeof g !== 'object') return null; if (g.type === 'typed') { const t = str(g.text, 60).trim(); return t.length >= 2 ? { type: 'typed', text: t } : null; } if (g.type === 'drawn' && typeof g.img === 'string' && /^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(g.img) && g.img.length <= 90000) return { type: 'drawn', img: g.img }; return null; }
  function cleanTerms(t) { t = t || {}; return { dur: DURS.includes(+t.dur) ? +t.dur : 12, freq: FREQS.includes(t.freq) ? t.freq : 'monthly', clauses: (Array.isArray(t.clauses) ? t.clauses : []).slice(0, 10).map(x => str(x, 120)), note: str(t.note || '', 300) }; }
  function roomBase(l, r) { const n = r.n || 1; if (r.pre && !r.full) return Math.max(50, Math.round(l.price * (l.type === 'hostel' ? .25 : .1))); return (l.type === 'rent' || l.type === 'stay') ? l.price * n : (l.type === 'sale' || l.type === 'land') ? Math.round(l.price * .1) : l.price; }
  async function mediaOk(uid, ids) { for (const id of ids.filter(Boolean)) { if (!/^m_/.test(String(id))) continue; const m = await store.get('media', id); if (!m || m.owner !== uid || m.state !== 'ok') return id; } return null; }

  /* ---------- per-collection write rules ---------- */
  const W = {};
  W.users = async (me, id, d, ex) => {
    if (id === me.id) {
      const u = ex ? clone(ex) : { id }, admin = isAdmin(me);
      if (typeof d.name === 'string') u.name = str(d.name, 60).trim() || u.name;
      if (d.photo !== undefined) { if (d.photo && await mediaOk(me.id, [d.photo])) return { ok: false, reason: 'photo not uploaded' }; u.photo = d.photo || undefined; }
      if (Array.isArray(d.roles)) u.roles = d.roles.filter(x => ['seeker', 'owner', 'agent'].includes(x)).concat(admin ? ['admin'] : []);
      if (d.caretaker !== undefined) u.caretaker = !!d.caretaker;
      if (d.sig !== undefined) { const g = cleanSig(d.sig); if (g) u.sig = g; else if (!d.sig) u.sig = undefined; }
      if (d.rterms && typeof d.rterms === 'object') { const f = (Array.isArray(d.rterms.freqs) ? d.rterms.freqs : []).filter(x => FREQS.includes(x)); u.rterms = { freqs: f.length ? f : FREQS.slice(), clauses: (Array.isArray(d.rterms.clauses) ? d.rterms.clauses : []).slice(0, 10).map(x => str(x, 120)), rules: (Array.isArray(d.rterms.rules) ? d.rterms.rules : []).slice(0, 12).map(x => str(x, 140)) }; }
      if (d.phone !== undefined) { const c = String(d.phone || '').replace(/\D/g, ''); u.phone = c.length >= 9 && c.length <= 15 ? c : undefined; }
      if (Array.isArray(d.rtMs)) u.rtMs = d.rtMs.filter(x => typeof x === 'number' && x >= 0).slice(-20);
      if (d.respH) u.respH = Math.min(99, Math.max(1, +d.respH || 3));
      if (d.agent && typeof d.agent === 'object') {
        const a = u.agent || { status: 'pending', rating: 0, jobs: 0, reviews: [] };
        if (Array.isArray(d.agent.areas)) a.areas = d.agent.areas.map(x => str(x, 40)).slice(0, 10); if (d.agent.bio !== undefined) a.bio = str(d.agent.bio, 600); if (d.agent.on !== undefined) a.on = !!d.agent.on; u.agent = a;
        if (admin && d.agent.status) { a.status = d.agent.status; if (d.agent.rating) a.rating = +d.agent.rating; }
      }
      if (d.kyc && typeof d.kyc === 'object' && (!u.kyc || u.kyc.status === 'redo')) {
        const k = d.kyc, bad = await mediaOk(me.id, [k.id, k.selfie, k.vid]); if (bad) return { ok: false, reason: 'verification files not uploaded yet' };
        u.kyc = { status: 'pending', name: str(k.name, 80), type: str(k.type, 30), id: k.id, selfie: k.selfie, vid: k.vid, dur: +k.dur || 0, t: now() };
        await notify('u_admin', 'Identity check waiting: ' + u.name);
      }
      await store.put('users', id, u, id); return { ok: true, d: u };
    }
    if (!ex) return { ok: false, reason: 'not allowed' };
    if (isAdmin(me)) { const u = clone(ex); if (d.kyc && d.kyc.status && u.kyc) { u.kyc.status = d.kyc.status; u.kyc.why = str(d.kyc.why, 200); } if (d.agent && u.agent && d.agent.status) { u.agent.status = d.agent.status; if (d.agent.rating) u.agent.rating = +d.agent.rating; } if (d.org !== undefined) u.org = !!d.org; await store.put('users', id, u, id); return { ok: true, d: pubUser(u) }; }
    // anyone with a finished tour may add a review to that agent
    if (ex.agent && d.agent && Array.isArray(d.agent.reviews)) {
      const tours = (await store.list('tours')).filter(r => r.data.seeker === me.id && r.data.agent === id && r.data.status === 'done'), u = clone(ex), have = new Set((u.agent.reviews || []).map(r => r.t + r.name));
      const fresh = d.agent.reviews.filter(r => r && !have.has(r.t + r.name)).slice(0, 1);
      if (!fresh.length || !tours.length) return { ok: true, d: pubUser(ex), ignored: true };
      const r = fresh[0]; if (R.leaks(r.text || '')) return { ok: false, reason: 'Remove contact details from your review.' };
      u.agent.reviews = [{ name: str(r.name, 40), stars: Math.min(5, Math.max(1, +r.stars || 5)), text: str(r.text, 400), tags: (r.tags || []).slice(0, 6).map(x => str(x, 30)), t: now() }].concat(u.agent.reviews || []);
      u.agent.jobs = (u.agent.jobs || 0) + 1; u.agent.rating = Math.round(u.agent.reviews.reduce((a, x) => a + x.stars, 0) / u.agent.reviews.length * 10) / 10;
      await store.put('users', id, u, id);
      if (r.tags && r.tags.includes('Asked for money')) { const rep = { id: rid('r'), by: me.id, target: id, listing: null, reason: 'Reviewer says the agent asked for money', t: now(), status: 'open' }; await store.put('reports', rep.id, rep); }
      return { ok: true, d: pubUser(u) };
    }
    return { ok: true, d: pubUser(ex), ignored: true };
  };

  W.listings = async (me, id, d, ex) => {
    const admin = isAdmin(me);
    if (!ex) {
      if (d.owner !== me.id) return { ok: false, reason: 'not your listing' };
      const f = (await store.get('flags', me.id)) || {}; if (f.banned) return { ok: false, reason: 'account removed' };
      if (!me.kyc || me.kyc.status === 'redo') return { ok: false, reason: 'Verify yourself first' };
      if ((me.aiHits || 0) >= 2) return { ok: false, reason: 'Your account is under review' };
      if (!d.title || !(d.price > 0) || !['rent', 'sale', 'hostel', 'stay', 'land'].includes(d.type)) return { ok: false, reason: 'incomplete listing' };
      if (R.leaks(d.title + ' ' + (d.desc || '') + ' ' + (d.note || ''))) return { ok: false, reason: 'Remove phone numbers or contact details from your listing.' };
      const media = (d.imgs || []).map(i => i.mid).concat([d.video && d.video.mid]), bad = await mediaOk(me.id, media); if (bad) return { ok: false, reason: 'A photo or video has not finished uploading (' + bad + ')' };
      if (!d.video || !d.video.mid) return { ok: false, reason: 'A video is required' };
      const l = clone(d); l.owner = me.id; l.status = 'review'; l.rv = 0; l.views = 0; l.verified = { owner: false, visited: false }; delete l.reserved; l.submitted = now(); l.t = now();
      l.title = str(l.title, 120); l.desc = str(l.desc, 3000); await store.put('listings', id, l, me.id);
      await notify('u_admin', 'New listing to review: ' + l.title); return { ok: true, d: l };
    }
    if (admin) { const l = Object.assign({}, ex, d, { owner: ex.owner }); if (ex.reserved && !d.reserved) l.reserved = ex.reserved; await store.put('listings', id, l, ex.owner); if (d.status && d.status !== ex.status) await notify(ex.owner, d.status === 'live' ? '"' + ex.title + '" is now live on Izel.' : d.status === 'rejected' ? '"' + ex.title + '" was not approved. The team will explain why.' : '"' + ex.title + '" status: ' + d.status); return { ok: true, d: l }; }
    if (ex.owner === me.id) {
      const l = clone(ex);
      if (d.status && ['live', 'paused'].includes(d.status) && ['live', 'paused'].includes(ex.status)) l.status = d.status;
      if (+d.price > 0) l.price = +d.price; if (Array.isArray(d.days)) l.days = d.days.filter(x => x >= 0 && x <= 6); if (Array.isArray(d.blocked)) l.blocked = d.blocked.slice(0, 120).map(x => str(x, 10)); if (d.group) l.group = { ok: !!d.group.ok, max: Math.min(8, Math.max(1, +d.group.max || 1)) }; if (d.viewFee !== undefined) l.viewFee = Math.max(0, +d.viewFee || 0);
      await store.put('listings', id, l, me.id); return { ok: true, d: l };
    }
    return { ok: true, d: ex, ignored: true };
  };

  async function activeChats(l) { const cut = now() - 72 * 36e5; return (await store.list('chats')).map(r => r.data).filter(c => c.listing === l.id && c.kind === 'enq' && !c.ended && (c.msgs || []).some(m => m.from === c.a) && c.msgs[c.msgs.length - 1].t > cut); }
  W.chats = async (me, id, d, ex) => {
    const c = ex ? clone(ex) : null;
    if (!c) {
      if (d.a !== me.id) return { ok: false, reason: 'not allowed' }; const other = await store.get('users', d.b); if (!other) return { ok: false, reason: 'unknown person' };
      if (!['enq', 'deal', 'agent', 'support'].includes(d.kind)) return { ok: false, reason: 'bad chat' };
      if (d.listing) { const l = await store.get('listings', d.listing); if (!l) return { ok: false, reason: 'unknown listing' }; if (d.kind === 'enq' && l.owner !== d.b) return { ok: false, reason: 'not the owner' };
        if (d.kind === 'enq' && !['stay', 'hostel'].includes(l.type)) { if (l.reserved && l.reserved.by !== me.id) return { ok: false, reason: 'reserved' }; const A = await activeChats(l); if (A.length >= 5 && !A.some(x => x.a === me.id)) return { ok: false, reason: 'Owner is talking to 5 people. Join the queue.', code: 'full' }; } }
    } else if (c.a !== me.id && c.b !== me.id && !isAdmin(me)) return { ok: false, reason: 'not allowed' };
    const base = c || { id, a: d.a, b: d.b, listing: d.listing || null, kind: d.kind, msgs: [], seen: {} };
    const have = new Set(base.msgs.map(sigOf)), mine = base.msgs.filter(m => m.from === me.id).map(m => m.x);
    const f = (await store.get('flags', me.id)) || {}; let rejected = null;
    for (const m of (d.msgs || [])) {
      if (have.has(sigOf(m))) continue;
      if (!m || typeof m.x !== 'string' || m.x.length > 1000) continue;
      if (m.from === 'sys') { base.msgs.push({ from: 'sys', t: +m.t || now(), x: str(m.x, 300) }); have.add(sigOf(m)); continue; }
      if (m.from !== me.id) continue;
      if (f.blocked && f.blocked > now()) { rejected = 'Chat paused for 24 hours'; continue; }
      if (R.leaks(m.x) || R.splitLeak(mine, m.x)) { await strike(me, 'Shared contact details in chat', base); rejected = 'blocked'; break; }
      base.msgs.push({ from: me.id, t: +m.t || now(), x: m.x }); mine.push(m.x); have.add(sigOf(m));
    }
    base.msgs.sort((a, b) => a.t - b.t); base.msgs = base.msgs.slice(-500);
    if (!rejected && (base.kind === 'enq' || base.kind === 'agent')) { const oth = base.a === me.id ? base.b : base.a, ou = await store.get('users', oth); const last = base.msgs[base.msgs.length - 1];
      if (ou && ou.showcase && last && last.from === me.id && (!ex || base.msgs.length > ex.msgs.length)) { const pool = base.kind === 'agent' ? ['Great, what time can we meet at the first stop?', 'Thank you. Please confirm each owner before we move, and tell me if anything looks different from the photos.', 'Perfect. I will bring a friend along. Payment stays inside Izel, right?'] : SHOW.bot[BOTK(String(last.x).toLowerCase())], n = base.msgs.filter(m => m.from === oth).length; base.msgs.push({ from: oth, t: now() + 1, x: pool[n % pool.length] }); } }
    if (d.seen && d.seen[me.id]) { base.seen = base.seen || {}; base.seen[me.id] = +d.seen[me.id] || now(); }
    if (d.closed) base.closed = true; if (d.dmNote) base.dmNote = 1;
    await store.put('chats', id, base, base.a);
    const other = base.a === me.id ? base.b : base.a; if (base.msgs.length && !rejected && (!ex || base.msgs.length > ex.msgs.length)) {}
    return rejected ? { ok: rejected !== 'blocked' ? true : false, d: base, reason: rejected === 'blocked' ? 'Phone numbers and outside contact are not allowed on Izel.' : rejected, strike: rejected === 'blocked' } : { ok: true, d: base };
  };

  W.visits = async (me, id, d, ex) => {
    const l = await store.get('listings', d.listing || (ex && ex.listing)); if (!l) return { ok: false, reason: 'unknown listing' };
    if (!ex) {
      if (d.seeker !== me.id) return { ok: false, reason: 'not allowed' }; if (!['requested', 'room'].includes(d.status)) return { ok: false, reason: 'bad status' }; if (l.status !== 'live' || l.owner === me.id) return { ok: false, reason: 'not available' };
      if (l.reserved && l.reserved.by !== me.id) return { ok: false, reason: 'reserved' };
      const v = { id, seeker: me.id, listing: l.id, date: str(d.date, 10), slot: str(d.slot, 40), status: d.status, t: now(), tour: d.tour || null, fee: l.viewFee || 0, party: 1 };
      if (d.status === 'requested') { if (!/^\d{4}-\d{2}-\d{2}$/.test(v.date)) return { ok: false, reason: 'pick a date' }; const g = l.group || { ok: false, max: 1 }; v.party = Math.min(g.ok ? g.max : 1, Math.max(1, +d.party || 1)); if (Array.isArray(l.days) && l.days.length && l.days.indexOf(new Date(v.date + 'T12:00:00Z').getUTCDay()) < 0) return { ok: false, reason: 'The owner is not open that day' }; }
      const need = d.status === 'requested' ? (l.viewFee || R.PLEDGE) : 0;
      if (d.status === 'requested' && need) { const r = await usePay(me, d.payRef, need, 'visit:' + id); if (!r.ok) return r; v.payRef = d.payRef; v.fee = need; v.share = Math.round(need * R.OWNER_PCT) / 100; }
      if (d.agent) { const a = await store.get('users', d.agent); if (!a || !a.agent || a.agent.status !== 'approved') return { ok: false, reason: 'agent not available' }; v.agent = d.agent; }
      await store.put('visits', id, v, me.id); await notify(l.owner, U_(me) + ' wants to view ' + l.title + (v.date ? ' on ' + v.date + '.' : '.') + (v.party > 1 ? ' ' + v.party + ' people.' : '') + (v.agent ? ' An Izel agent will come along.' : ''));
      return { ok: true, d: v };
    }
    const v = clone(ex), isS = ex.seeker === me.id, isO = l.owner === me.id, admin = isAdmin(me);
    const to = d.status, from = ex.status;
    if (isS) {
      if (to === 'cancelled' && ['requested', 'confirmed', 'room', 'reserved'].includes(from)) v.status = 'cancelled';
      else if (from === 'reserved' && to === 'requested') { if (!/^\d{4}-\d{2}-\d{2}$/.test(d.date || '')) return { ok: false, reason: 'pick a date' }; const g = l.group || { ok: false, max: 1 }; v.date = d.date; v.slot = str(d.slot, 40); v.party = Math.min(g.ok ? g.max : 1, Math.max(1, +d.party || 1)); v.status = 'requested'; if (d.agent && !v.agent) { const a = await store.get('users', d.agent); if (a && a.agent && a.agent.status === 'approved') v.agent = d.agent; } await notify(l.owner, U_(me) + ' reserved ' + l.title + ' and wants to view it on ' + v.date + '.'); }
      if (d.agent && !v.agent && ['requested', 'room', 'reserved'].includes(v.status)) { const a = await store.get('users', d.agent); if (a && a.agent && a.agent.status === 'approved') v.agent = d.agent; }
    }
    if (isO || admin) {
      if (from === 'requested' && to === 'confirmed') { v.status = 'confirmed'; await notify(ex.seeker, U_(await store.get('users', l.owner)) + ' confirmed your viewing of ' + l.title + '. Location unlocked.'); }
      else if (from === 'requested' && to === 'cancelled') v.status = 'cancelled';
      else if (from === 'arrived' && to === 'cancelled') v.status = 'cancelled';
    }
    await store.put('visits', id, v, ex.seeker); return { ok: true, d: v };
  };
  const U_ = (u) => (u && u.name) || 'Someone';

  W.dealRooms = async (me, id, d, ex) => {
    const l = await store.get('listings', d.listing || (ex && ex.listing)); if (!l) return { ok: false, reason: 'unknown listing' };
    if (!ex) {
      if (d.seeker !== me.id || l.owner !== d.owner || l.owner === me.id) return { ok: false, reason: 'not allowed' };
      const vv = await store.get('visits', d.visit); if (!vv || vv.seeker !== me.id) return { ok: false, reason: 'no visit' };
      const r = { id, visit: d.visit, listing: l.id, seeker: me.id, owner: l.owner, mode: d.mode === 'quick' ? 'quick' : 'room', pre: !!d.pre, full: !!d.full, stage: d.mode === 'quick' ? 'agreed' : 'offer', n: Math.max(1, +d.n || 1), hist: [], turn: 'seeker', check: { docs: false, terms: false }, chat: d.chat, t: now() };
      if (r.stage === 'agreed') r.agreed = roomBase(l, r);
      await store.put('dealRooms', id, r, me.id); await notify(l.owner, U_(me) + ' opened a deal room for ' + l.title + '.'); return { ok: true, d: r };
    }
    if (ex.seeker !== me.id && ex.owner !== me.id && !isAdmin(me)) return { ok: false, reason: 'not allowed' };
    const r = clone(ex), isS = me.id === ex.seeker, side = isS ? 'seeker' : 'owner';
    if (ex.stage === 'paid') return { ok: true, d: ex, ignored: true };
    if (isS && d.n && ex.stage !== 'agreed' || isS && d.n && ex.mode === 'quick') { if (!r.hist.length || ex.mode === 'quick') r.n = Math.max(1, Math.min(60, +d.n || 1)); if (ex.mode === 'quick') r.agreed = roomBase(l, r); }
    if (isS && d.in && d.out) { r.in = str(d.in, 10); r.out = str(d.out, 10); r.n = Math.max(1, Math.min(60, +d.n || 1)); }
    const have = new Set(r.hist.map(h => h.from + h.t + h.amt));
    for (const h of (d.hist || [])) { if (have.has(h.from + h.t + h.amt)) continue; if (h.from !== side || !(+h.amt > 0) || +h.amt > 1e9) continue; if (ex.stage !== 'offer') continue; const last = r.hist[r.hist.length - 1]; if (last && last.from === side) continue; r.hist.push(l.type === 'rent' && h.terms ? { from: side, amt: Math.round(+h.amt), t: +h.t || now(), terms: cleanTerms(h.terms) } : { from: side, amt: Math.round(+h.amt), t: +h.t || now() }); r.turn = side === 'seeker' ? 'owner' : 'seeker'; await notify(side === 'seeker' ? ex.owner : ex.seeker, U_(me) + (side === 'seeker' ? ' offered ' : ' countered with ') + 'GH₵' + Math.round(+h.amt) + ' for ' + l.title + '.'); }
    if (l.type === 'rent' && isS && d.holdPct && ex.stage === 'offer') { const pct = Math.round(+d.holdPct); if (pct < 35 || pct > 60) return { ok: false, reason: 'Deposit must be between 35% and 60%' }; const tt = cleanTerms(d.terms), dd = dueNow(l.price, tt.dur, tt.freq); r.terms = Object.assign({ rent: l.price }, tt); r.holdPct = pct; r.n = tt.dur; r.agreed = Math.round(dd.total * pct / 100); r.stage = 'agreed'; r.turn = ''; r.check = { docs: true, terms: true }; }
    if (l.type === 'rent' && side === 'seeker' && r.stage === 'offer' && r.hist.length) {
      const lh = r.hist[r.hist.length - 1], ou = await store.get('users', ex.owner);
      if (ou && ou.showcase && lh.from === 'seeker' && lh.terms) {
        if (lh.amt >= l.price * .93) { r.stage = 'agreed'; r.terms = Object.assign({ rent: lh.amt }, lh.terms); r.agreed = dueNow(lh.amt, lh.terms.dur, lh.terms.freq).total; r.turn = ''; await notify(ex.seeker, U_(ou) + ' accepted your offer of GH₵' + lh.amt + ' a month. Next: payment.'); }
        else { const ca = Math.max(Math.round(lh.amt), Math.round((l.price + lh.amt) / 2 / 10) * 10); r.hist.push({ from: 'owner', amt: ca, t: now() + 1, terms: lh.terms }); r.turn = 'seeker'; await notify(ex.seeker, U_(ou) + ' countered with GH₵' + ca + ' a month for ' + l.title + '.'); }
      }
    }
    if (l.type === 'rent' && d.stage === 'agreed' && ex.stage === 'offer' && r.stage === 'offer' && r.hist.length && r.hist[r.hist.length - 1].terms) { const lh = r.hist[r.hist.length - 1]; if (lh.from !== side) { r.stage = 'agreed'; r.terms = Object.assign({ rent: lh.amt }, lh.terms); r.agreed = dueNow(lh.amt, lh.terms.dur, lh.terms.freq).total; r.n = lh.terms.dur; r.turn = ''; await notify(side === 'seeker' ? ex.owner : ex.seeker, 'Agreed at GH₵' + lh.amt + ' a month. Next: payment in the deal room.'); } else return { ok: false, reason: 'Nothing to accept yet', d: ex }; }
    if (d.stage === 'agreed' && ex.stage === 'offer' && r.stage === 'offer') { const last = r.hist[r.hist.length - 1], base = roomBase(l, r), a = Math.round(+d.agreed); if (last && last.from !== side && a === last.amt) { r.stage = 'agreed'; r.agreed = a; r.turn = ''; await notify(side === 'seeker' ? ex.owner : ex.seeker, 'Agreed at GH₵' + a + '. Next: payment in the deal room.'); } else if (isS && a === base) { r.stage = 'agreed'; r.agreed = a; r.turn = ''; } else return { ok: false, reason: 'That amount was not offered', d: ex }; }
    if (isS && d.check && r.stage === 'agreed') r.check = { docs: !!d.check.docs, terms: !!d.check.terms };
    await store.put('dealRooms', id, r, ex.seeker); return { ok: true, d: r };
  };

  async function usePay(me, ref, amount, usedFor) { const p = await store.get('pays', String(ref || '')); if (!p || p.user !== me.id) return { ok: false, reason: 'Payment not found' }; if (p.status !== 'ok') return { ok: false, reason: 'Payment not confirmed' }; if (p.used && p.used !== usedFor) return { ok: false, reason: 'Payment already used' }; if (Math.abs(p.amount - amount) > 0.5) return { ok: false, reason: 'Payment amount does not match' }; p.used = usedFor; await store.put('pays', ref, p); return { ok: true }; }

  W.deals = async (me, id, d, ex) => {
    if (ex) return { ok: true, d: ex, ignored: true };
    const room = (await store.list('dealRooms')).map(r => r.data).find(r => r.id === d.room); if (!room || room.seeker !== me.id) return { ok: false, reason: 'no deal room' };
    if (room.stage !== 'agreed') return { ok: false, reason: 'Deal is not agreed yet' };
    const l = await store.get('listings', room.listing), amt = room.agreed || roomBase(l, room);
    const p = await usePay(me, d.payRef, amt, 'deal:' + id); if (!p.ok) return p;
    const f = R.feeOf(l.type, amt), deal = { cert: 'IZ-' + sha(id + SECRET).slice(0, 8).toUpperCase(), id, seeker: me.id, owner: l.owner, listing: l.id, amount: amt, fee: f.fee, proc: f.proc, payout: f.payout, t: now(), status: 'paid', room: room.id, payRef: d.payRef, payoutStatus: 'pending' };
    await store.put('deals', id, deal, me.id);
    room.stage = 'paid'; room.paidAt = now(); await store.put('dealRooms', room.id, room, room.seeker);
    const v = await store.get('visits', room.visit); if (v) { v.status = v.status === 'room' ? 'reserved' : (v.status === 'visited' || v.status === 'deal') ? 'deal' : v.status; await store.put('visits', v.id, v, v.seeker); }
    await notify(l.owner, 'Payment of GH₵' + amt + ' received for ' + l.title + '. You will get GH₵' + f.payout + ' within 24 hours.');
    if (!['stay', 'hostel'].includes(l.type)) {
      l.reserved = { by: me.id, t: now() }; l.status = 'taken'; l.takenAt = now(); await store.put('listings', l.id, l, l.owner);
      for (const r of await store.list('chats')) { const c = r.data; if (c.listing === l.id && c.kind === 'enq' && c.a !== me.id && !c.ended) { c.ended = true; c.msgs.push({ from: 'sys', t: now(), x: 'This place was reserved by someone else.' }); await store.put('chats', c.id, c, c.a); await notify(c.a, l.title + ' was reserved by someone else. We will tell you if it opens up again.'); } }
    }
    return { ok: true, d: deal };
  };

  W.holds = async (me, id, d, ex) => {
    if (ex) return { ok: true, d: ex, ignored: true };
    const l = await store.get('listings', d.listing); if (!l || !l.hostel || d.seeker !== me.id) return { ok: false, reason: 'not allowed' }; const h = l.hostel; let amt = 0;
    if (d.kind === 'bed') { const t = h.types[+d.ti]; if (!t || t.left < 1) return { ok: false, reason: 'No beds left in that room type' }; amt = Math.round(t.price * .25); }
    else if (d.kind === 'hold' || d.kind === 'store') { const m = Math.min(12, Math.max(1, +d.m || 1)), n = Math.min(20, Math.max(1, +d.n || 1)), low = h.types.reduce((a, t) => Math.min(a, t.price), 1e9), monthly = l.per === 'semester' ? low / 4 : low / 12; if (d.kind === 'hold' && !h.hold.on || d.kind === 'store' && !h.store.on) return { ok: false, reason: 'Not offered' }; amt = Math.round(d.kind === 'hold' ? monthly * h.hold.pct / 100 * m : h.store.fee * n * m); }
    else return { ok: false, reason: 'bad hold' };
    const p = await usePay(me, d.payRef, amt, 'hold:' + id); if (!p.ok) return p;
    const rec = { cert: 'IZ-' + sha(id + SECRET).slice(0, 8).toUpperCase(), id, kind: d.kind, listing: l.id, seeker: me.id, label: str(d.label, 120), amount: amt, t: now(), status: 'held', payRef: d.payRef };
    await store.put('holds', id, rec, me.id);
    if (d.kind === 'bed') { h.types[+d.ti].left--; h.free = Math.max(0, (h.free || 0) - 1); if (h.types.every(t => t.left < 1)) l.status = 'full'; await store.put('listings', l.id, l, l.owner); }
    await notify(l.owner, U_(me) + ' booked at ' + l.title + ': ' + rec.label + '.'); return { ok: true, d: rec };
  };

  W.reports = async (me, id, d, ex) => { if (ex) { if (isAdmin(me) && d.status) { ex.status = str(d.status, 20); await store.put('reports', id, ex); } return { ok: true, d: ex }; } if (d.by !== me.id) return { ok: false, reason: 'not allowed' }; const r = { id, by: me.id, target: str(d.target, 40), listing: d.listing || null, reason: str(d.reason, 300), t: now(), status: 'open' }; await store.put('reports', id, r); await notify('u_admin', 'New report: ' + r.reason); return { ok: true, d: r }; };
  W.services = async (me, id, d, ex) => { if (ex) { if (isAdmin(me)) { Object.assign(ex, { status: str(d.status, 40) }); await store.put('services', id, ex); } return { ok: true, d: ex }; } if (d.by !== me.id) return { ok: false, reason: 'not allowed' }; const s = { id, by: me.id, kind: str(d.kind, 40), listing: d.listing || null, partner: d.partner || null, t: now(), status: 'quote in 24h' }; await store.put('services', id, s); return { ok: true, d: s }; };
  W.tours = async (me, id, d, ex) => {
    if (!ex) { if (d.seeker !== me.id) return { ok: false, reason: 'not allowed' }; let a = null; if (d.agent) { a = await store.get('users', d.agent); if (!a || !a.agent || a.agent.status !== 'approved') return { ok: false, reason: 'agent not available' }; } const t = { id, seeker: me.id, agent: d.agent || null, listings: (d.listings || []).slice(0, 3), date: str(d.date, 10), slot: str(d.slot, 40), status: d.agent ? 'new' : 'solo' }; await store.put('tours', id, t, me.id); if (a) await notify(a.id, U_(me) + ' wants you to guide a viewing on ' + t.date + '.'); return { ok: true, d: t }; }
    const t = clone(ex);
    if (ex.agent === me.id && ['accepted', 'declined', 'done'].includes(d.status) && (ex.status === 'new' || ex.status === 'accepted' && d.status === 'done')) { t.status = d.status; await notify(t.seeker, d.status === 'done' ? 'How was your tour? Tap Plan to rate.' : U_(me) + (d.status === 'accepted' ? ' accepted your tour.' : ' could not take your tour. Please pick another agent.')); if (d.status === 'done') for (const r of await store.list('chats')) { const c = r.data; if (c.kind === 'agent' && c.a === t.seeker && c.b === t.agent && !c.closed) { c.closed = true; c.msgs.push({ from: 'sys', t: now(), x: 'Tour finished. This chat is now closed.' }); await store.put('chats', c.id, c, c.a); } } }
    if (ex.seeker === me.id && d.rated) t.rated = true;
    await store.put('tours', id, t, ex.seeker); return { ok: true, d: t };
  };
  W.notifs = async (me, id, d, ex) => { const n = ex ? clone(ex) : { id, list: [] }, have = new Set(n.list.map(x => x.t + x.x)); if (id === me.id) { const m = new Map((d.list || []).map(x => [x.t + x.x, x])); n.list.forEach(x => { const y = m.get(x.t + x.x); if (y && y.r) x.r = 1; }); } else { for (const x of (d.list || []).slice(0, 5)) { if (have.has(x.t + x.x) || !x.x) continue; if (R.leaks(x.x)) continue; n.list.unshift({ t: now(), x: str(x.x, 200) }); } } n.list = n.list.slice(0, 60); await store.put('notifs', id, n, id); return { ok: true, d: id === me.id ? n : undefined, ignored: id !== me.id }; };
  W.saved = async (me, id, d) => { if (id !== me.id) return { ok: true, ignored: true }; const s = { id, list: (d.list || []).slice(0, 200).map(x => str(x, 40)) }; await store.put('saved', id, s, id); return { ok: true, d: s }; };
  W.queue = async (me, id, d, ex) => { const q = ex ? clone(ex) : { id, list: [] }; if ((d.list || []).includes(me.id) && !q.list.includes(me.id)) q.list.push(me.id); await store.put('queue', id, q); return { ok: true, d: q }; };
  W.asks = async (me, id, d, ex) => { const a = ex ? clone(ex) : { id, map: {} }; Object.keys(d.map || {}).forEach(k => { const v = Math.floor(+d.map[k] || 0), cur = a.map[k] || 0; if (v > cur && v <= cur + 1) a.map[k] = v; else if (cur === 0 && v === 1) a.map[k] = 1; }); await store.put('asks', id, a); return { ok: true, d: a }; };
  W.agreements = async (me, id, d, ex) => {
    if (ex) { if (ex.owner !== me.id) return { ok: false, reason: 'not allowed' }; const sg = cleanSig(d.ownerSig); if (!sg) return { ok: false, reason: 'Add your signature' }; const a = clone(ex); a.ownerSig = Object.assign(sg, { t: now() }); await store.put('agreements', id, a, ex.seeker); return { ok: true, d: a }; }
    const l = await store.get('listings', String(d.listing || '')); if (!l || l.owner === me.id) return { ok: false, reason: 'not allowed' };
    const sg = cleanSig(d.sig); if (!sg) return { ok: false, reason: 'Add your signature' };
    const ou = await store.get('users', l.owner), strs = (x, n, m) => (Array.isArray(x) ? x : []).slice(0, n).map(v => str(v, m));
    const a = { id, kind: ['rent', 'stay', 'hostel', 'sale', 'land'].includes(d.kind) ? d.kind : l.type, listing: l.id, seeker: me.id, owner: l.owner, room: str(d.room, 40), title: str(d.title, 80), rows: (Array.isArray(d.rows) ? d.rows : []).slice(0, 40).map(r => [str(r && r[0], 80), str(r && r[1], 240)]), rules: strs(d.rules, 20, 200), sig: Object.assign(sg, { t: now() }), ownerSig: ou && ou.sig ? Object.assign({}, ou.sig, { t: now(), auto: true }) : undefined, ref: 'AG' + sha(id).slice(0, 6).toUpperCase(), t: now() };
    await store.put('agreements', id, a, me.id); await notify(l.owner, U_(me) + ' signed the agreement for ' + l.title + '.'); return { ok: true, d: a };
  };
  W.partners = async (me, id, d, ex) => { if (!isAdmin(me)) return { ok: true, d: ex, ignored: true }; const p = { id, name: str(d.name, 80), kind: str(d.kind, 20), city: str(d.city, 40), licence: str(d.licence, 40), jobs: +d.jobs || 0, active: !!d.active }; await store.put('partners', id, p); return { ok: true, d: p }; };

  async function push(me, body) {
    const order = ['users', 'listings', 'partners', 'chats', 'visits', 'tours', 'dealRooms', 'deals', 'holds', 'reports', 'services', 'notifs', 'saved', 'queue', 'asks', 'agreements'];
    const ch = (body.changes || []).slice(0, 200).sort((a, b) => order.indexOf(a.c) - order.indexOf(b.c)), results = [];
    for (const x of ch) {
      const h = W[x.c]; if (!h || !x.id || typeof x.d !== 'object' || !x.d) { results.push({ c: x.c, id: x.id, ok: false, reason: 'unknown record' }); continue; }
      try { const ex = await store.get(x.c, String(x.id)); const r = await h(me, String(x.id), x.d, ex); results.push(Object.assign({ c: x.c, id: x.id }, r)); } catch (e) { results.push({ c: x.c, id: x.id, ok: false, reason: 'server error: ' + e.message }); }
    }
    return { results };
  }

  /* ---------- media ---------- */
  const MAXB = { photo: 20 * 1048576, profile: 8 * 1048576, kyc: 150 * 1048576, video: (+E.MAX_VIDEO_MB || 200) * 1048576 }, CT = /^(image\/(jpeg|heic|heif|png|webp)|video\/(mp4|quicktime|webm))$/;
  async function sbSign(p, expires) { const r = await doFetch(store.base + '/storage/v1/object/sign/' + (E.MEDIA_BUCKET || 'izel-media') + '/' + p, { method: 'POST', headers: store.H(), body: JSON.stringify({ expiresIn: expires || 3600 }) }); const j = await r.json(); if (!r.ok) throw new Error(j.message || 'sign failed'); return store.base + '/storage/v1' + j.signedURL; }
  async function mediaNew(me, b) {
    const kind = ['photo', 'video', 'profile', 'kyc'].includes(b.kind) ? b.kind : null, ct = str(b.ct, 40), size = +b.size || 0; if (!kind || !CT.test(ct)) return err(400, 'That file type is not allowed');
    if (kind === 'video' && !/^video\//.test(ct) || kind !== 'video' && !/^(image\/|video\/)/.test(ct)) return err(400, 'Wrong file type');
    if (size > MAXB[kind]) return err(413, 'File is too big');
    const id = /^m_[a-z0-9]{6,24}$/.test(b.id || '') && !(await store.get('media', b.id)) ? b.id : 'm_' + crypto.randomBytes(8).toString('hex');
    const m = { id, owner: me.id, kind, ct, size, state: 'new', path: me.id + '/' + id, t: now() }; await store.put('media', id, m, me.id);
    let up;
    if (store.base) { const r = await doFetch(store.base + '/storage/v1/object/upload/sign/' + (E.MEDIA_BUCKET || 'izel-media') + '/' + m.path, { method: 'POST', headers: store.H(), body: '{}' }); const j = await r.json(); if (!r.ok) return err(502, 'Storage error: ' + (j.message || r.status)); up = { url: store.base + '/storage/v1' + j.url, method: 'PUT', headers: { 'Content-Type': ct, 'x-upsert': 'true' } }; }
    else up = { url: '/api/_up/' + id + '?s=' + sha(id + SECRET).slice(0, 24), method: 'PUT', headers: { 'Content-Type': ct } };
    return out(200, { ok: true, id, upload: up });
  }
  async function readHead(m) { if (store.base) { const u = await sbSign(m.path, 120), r = await doFetch(u, { headers: { Range: 'bytes=0-262143' } }); if (!r.ok && r.status !== 206) return null; return Buffer.from(await r.arrayBuffer()); } return store.readLocal ? store.readLocal(m.id, 262144) : null; }
  async function mediaDone(me, b) {
    const m = await store.get('media', str(b.id, 40)); if (!m || m.owner !== me.id) return err(404, 'Unknown file');
    const head = await readHead(m); if (!head || !head.length) return err(400, 'The upload did not arrive. Try again.');
    if (m.kind === 'photo') { const s = R.scanPhoto(head); if (!s.ok) { m.state = 'rejected'; m.why = s.why; await store.put('media', m.id, m, me.id); if (s.ai) { const u = await store.get('users', me.id); u.aiHits = (u.aiHits || 0) + 1; await store.put('users', me.id, u, me.id); const rep = { id: rid('r'), by: 'system', target: me.id, listing: null, reason: 'Uploaded an AI-made or edited image', t: now(), status: 'open' }; await store.put('reports', rep.id, rep); await notify('u_admin', U_(me) + ' uploaded an AI-made or edited image.'); } return out(200, { ok: false, rejected: true, why: s.why + '. Izel only accepts real, unedited camera photos.' + (s.ai ? ' This is recorded.' : '') }); } }
    m.state = 'ok'; await store.put('media', m.id, m, me.id); return out(200, { ok: true, id: m.id });
  }
  async function mediaGet(req, id, me) {
    const m = await store.get('media', id); if (!m) return err(404, 'Not found');
    if (m.kind === 'kyc' && !(me && (me.id === m.owner || isAdmin(me)))) return err(403, 'Private');
    if (m.state === 'rejected') return err(404, 'Not found');
    if (store.base) { const u = await sbSign(m.path, 3600); return { status: 302, headers: Object.assign({ Location: u, 'Cache-Control': 'private, max-age=1800' }, cors()), body: '' }; }
    return store.serveLocal ? store.serveLocal(m, req) : err(404, 'No storage');
  }

  /* ---------- payments ---------- */
  async function payInit(me, b) {
    let amount = Math.round((+b.amount || 0) * 100) / 100;
    if (b.room) { const rm = await store.get('dealRooms', String(b.room)); if (!rm || rm.seeker !== me.id || rm.stage !== 'agreed') return err(400, 'This deal is not ready for payment'); const lr = await store.get('listings', rm.listing); amount = rm.agreed || roomBase(lr, rm); }
    if (!(amount > 0) || amount > 5e7) return err(400, 'Bad amount');
    const ref = 'IZ' + Date.now().toString(36) + crypto.randomBytes(4).toString('hex'), p = { ref, user: me.id, amount, label: str(b.label, 80), status: 'init', t: now() };
    const key = E.PAYSTACK_SECRET_KEY;
    if (!key) { p.mode = 'test'; await store.put('pays', ref, p); return out(200, { ok: true, mode: 'test', ref, amount }); }
    const email = (me.id + '@izel.app').toLowerCase();
    const r = await doFetch((E.PAYSTACK_API || 'https://api.paystack.co') + '/transaction/initialize', { method: 'POST', headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' }, body: JSON.stringify({ email, amount: Math.round(amount * 100), currency: 'GHS', reference: ref, metadata: { user: me.id, label: p.label } }) });
    const j = await r.json().catch(() => ({})); if (!r.ok || !j.status) return err(502, 'Payment provider said: ' + (j.message || r.status));
    p.mode = 'paystack'; await store.put('pays', ref, p); return out(200, { ok: true, mode: 'paystack', ref, amount, access: j.data.access_code, pub: E.PAYSTACK_PUBLIC_KEY || '' });
  }
  async function payVerify(me, b) {
    const ref = str(b.ref, 60), p = await store.get('pays', ref); if (!p || p.user !== me.id) return err(404, 'Unknown payment');
    if (p.status === 'ok') return out(200, { ok: true, amount: p.amount });
    if (p.mode === 'test') { if (E.ALLOW_TEST_PAYMENTS === '0') return err(403, 'Test payments are off'); p.status = 'ok'; await store.put('pays', ref, p); return out(200, { ok: true, amount: p.amount, test: true }); }
    const r = await doFetch((E.PAYSTACK_API || 'https://api.paystack.co') + '/transaction/verify/' + encodeURIComponent(ref), { headers: { Authorization: 'Bearer ' + E.PAYSTACK_SECRET_KEY } }); const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.data || j.data.status !== 'success') return err(402, 'Payment not completed yet');
    if (Math.abs(j.data.amount / 100 - p.amount) > 0.5 || j.data.currency !== 'GHS') return err(402, 'Amount does not match');
    p.status = 'ok'; await store.put('pays', ref, p); return out(200, { ok: true, amount: p.amount });
  }
  async function payWebhook(req) {
    const raw = Buffer.isBuffer(req.body) ? req.body.toString() : String(req.body || ''), sig = (req.headers || {})['x-paystack-signature'];
    if (!E.PAYSTACK_SECRET_KEY || crypto.createHmac('sha512', E.PAYSTACK_SECRET_KEY).update(raw).digest('hex') !== sig) return err(401, 'bad signature');
    let ev; try { ev = JSON.parse(raw); } catch (e) { return err(400, 'bad json'); }
    if (ev.event === 'charge.success') { const p = await store.get('pays', ev.data.reference); if (p && p.status !== 'ok' && Math.abs(ev.data.amount / 100 - p.amount) <= 0.5) { p.status = 'ok'; await store.put('pays', p.ref, p); } }
    return out(200, { ok: true });
  }
  async function payoutRecipient(me, b) {
    if (b.kind === 'bank') {
      const num = String(b.number || '').replace(/\D/g, ''), bn = str(b.bank, 60);
      if (!bn || num.length < 8) return err(400, 'Pick your bank and enter the account number');
      const rec = { user: me.id, network: 'BANK', bankName: bn, last4: num.slice(-4), name: str(b.name, 60) };
      if (E.PAYSTACK_SECRET_KEY) {
        const H = { Authorization: 'Bearer ' + E.PAYSTACK_SECRET_KEY, 'Content-Type': 'application/json' }, A = E.PAYSTACK_API || 'https://api.paystack.co';
        const bl = await (await doFetch(A + '/bank?country=ghana&perPage=100', { headers: H })).json().catch(() => ({})), hit = ((bl.data) || []).filter(x => String(x.name).toLowerCase().indexOf(bn.toLowerCase().split(' ')[0]) > -1)[0];
        if (!hit) return err(400, 'We could not match that bank. Check the name.');
        const r = await doFetch(A + '/transferrecipient', { method: 'POST', headers: H, body: JSON.stringify({ type: 'ghipss', name: rec.name || me.name, account_number: num, bank_code: hit.code, currency: 'GHS' }) }); const j = await r.json().catch(() => ({}));
        if (!r.ok || !j.status) return err(502, 'Could not save payout details: ' + (j.message || r.status)); rec.code = j.data.recipient_code;
      }
      await store.put('payouts', me.id, rec); return out(200, { ok: true, last4: rec.last4, network: 'BANK', bank: bn });
    }
    const net = { MTN: 'MTN', VODAFONE: 'VOD', TELECEL: 'VOD', AIRTELTIGO: 'ATL' }[String(b.network || '').toUpperCase()], num = String(b.number || '').replace(/\D/g, '');
    if (!net || num.length < 9) return err(400, 'Pick a network and enter the MoMo number');
    const rec = { user: me.id, network: net, last4: num.slice(-4), name: str(b.name, 60), number: num };
    if (E.PAYSTACK_SECRET_KEY) { const r = await doFetch((E.PAYSTACK_API || 'https://api.paystack.co') + '/transferrecipient', { method: 'POST', headers: { Authorization: 'Bearer ' + E.PAYSTACK_SECRET_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify({ type: 'mobile_money', name: rec.name || me.name, account_number: num, bank_code: net, currency: 'GHS' }) }); const j = await r.json().catch(() => ({})); if (!r.ok || !j.status) return err(502, 'Could not save payout details: ' + (j.message || r.status)); rec.code = j.data.recipient_code; }
    delete rec.number; await store.put('payouts', me.id, rec); return out(200, { ok: true, last4: rec.last4, network: net });
  }
  async function runPayouts() {
    const due = (await store.list('deals')).map(r => Object.assign(r.data, { _c: 'deals' })).concat((await store.list('vearn')).map(r => Object.assign(r.data, { _c: 'vearn' }))).filter(d => d.payoutStatus === 'pending' && d.t < now() - 24 * 36e5), res = [];
    for (const d of due) {
      const po = await store.get('payouts', d.owner); if (!po || !po.code) { res.push({ id: d.id, skipped: 'owner has no payout details' }); continue; }
      if (!E.PAYSTACK_SECRET_KEY) { res.push({ id: d.id, skipped: 'Paystack is not connected' }); continue; }
      const r = await doFetch((E.PAYSTACK_API || 'https://api.paystack.co') + '/transfer', { method: 'POST', headers: { Authorization: 'Bearer ' + E.PAYSTACK_SECRET_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify({ source: 'balance', amount: Math.round(d.payout * 100), recipient: po.code, reason: 'Izel payout ' + d.id, reference: 'PO' + d.id.replace(/[^a-z0-9]/gi, '').slice(0, 30).padEnd(16, '0') }) }); const j = await r.json().catch(() => ({}));
      if (r.ok && j.status) { d.payoutStatus = 'sent'; d.payoutAt = now(); const c_ = d._c; delete d._c; await store.put(c_, d.id, d, d.seeker || d.owner); await notify(d.owner, 'GH₵' + d.payout + ' was sent to your payout account.'); res.push({ id: d.id, sent: true }); } else res.push({ id: d.id, error: j.message || r.status });
    }
    return res;
  }

  /* ---------- viewing code: 3 digits for the owner, 3 for the visitor ---------- */
  const halves = (id) => { const h = crypto.createHmac('sha256', SECRET).update('vc|' + id).digest(); const g = (o) => String(h.readUInt32BE(o) % 1000).padStart(3, '0'); return { owner: g(0), seeker: g(4) }; };
  async function settleFee(v, l, why) {
    if (v.settled || !v.fee) { v.settled = v.settled || why; return; }
    v.settled = why;
    if (why === 'visited' || why === 'seeker_noshow') { await store.put('vearn', 've_' + v.id, { id: 've_' + v.id, visit: v.id, owner: l.owner, seeker: v.seeker, amount: v.fee, payout: v.share, t: now(), payoutStatus: 'pending', why }, l.owner); if (why === 'seeker_noshow') await notify(l.owner, 'The visitor did not come. GH₵' + v.share + ' of the viewing fee is yours for holding the slot.'); }
    else if (why === 'owner_noshow') { v.refund = { amount: v.fee, status: 'pending', t: now() }; await notify(v.seeker, 'The owner did not confirm your viewing. Your GH₵' + v.fee + ' is being refunded.'); await tryRefund(v); }
  }
  async function tryRefund(v) {
    if (!v.refund || v.refund.status !== 'pending') return;
    if (E.PAYSTACK_SECRET_KEY && v.payRef) { try { const r = await doFetch((E.PAYSTACK_API || 'https://api.paystack.co') + '/refund', { method: 'POST', headers: { Authorization: 'Bearer ' + E.PAYSTACK_SECRET_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify({ transaction: v.payRef, amount: Math.round(v.refund.amount * 100) }) }); if (r.ok) v.refund.status = 'sent'; } catch (e) {} }
  }
  async function penalize(uid, reason) {
    const u = await store.get('users', uid); if (!u) return;
    const own = (await store.list('listings')).filter(r => r.data.owner === uid);
    const f = await flag(uid, f => { f.strikes = (f.strikes || 0) + 1; if (f.strikes >= 3) f.blocked = now() + 864e5; if (f.strikes >= 5) f.banned = true; });
    let n = 0; if (f.strikes >= 2) for (const r of own) if (r.data.status === 'live') { r.data.status = 'suspended'; await store.put('listings', r.id, r.data, uid); n++; }
    const rep = { id: rid('r'), by: 'system', target: uid, listing: null, reason, t: now(), status: n ? 'actioned' : 'open' };
    await store.put('reports', rep.id, rep); await notify(uid, 'Strike ' + f.strikes + ': ' + reason + (n ? ' Your listings are paused until Izel reviews your account.' : ''));
    await notify('u_admin', reason + ' (' + (u.name || uid) + ')' + (n ? '. ' + n + ' listing(s) paused.' : '.'));
  }
  async function settleOverdue() {
    const m = (await store.get('meta', 'settle')) || { t: 0 }; if (now() - m.t < 3e5) return; m.t = now(); await store.put('meta', 'settle', m);
    const cut = new Date(now() - 864e5).toISOString().slice(0, 10);
    for (const r of await store.list('visits')) {
      const v = r.data; if (!['confirmed', 'arrived'].includes(v.status) || !v.date || v.date >= cut || v.settled) continue;
      const l = await store.get('listings', v.listing); if (!l) continue;
      if (v.seekerOk && !v.ownerOk) { v.status = 'expired'; await settleFee(v, l, 'owner_noshow'); await penalize(l.owner, 'Did not confirm a booked viewing.'); }
      else { v.status = 'expired'; await settleFee(v, l, 'seeker_noshow'); await penalize(v.seeker, 'Did not show up for a booked viewing.'); }
      await store.put('visits', v.id, v, v.seeker);
    }
    for (const r of await store.list('visits')) { const v = r.data; if (v.refund && v.refund.status === 'pending') { await tryRefund(v); await store.put('visits', v.id, v, v.seeker); } }
  }
  async function visitSide(me, id) { const v = await store.get('visits', String(id || '')); if (!v) return {}; const l = await store.get('listings', v.listing); if (!l) return {}; const role = v.seeker === me.id ? 'seeker' : l.owner === me.id ? 'owner' : null; return { v, l, role }; }
  async function visitCode(me, id) {
    const { v, role } = await visitSide(me, id); if (!v || !role) return err(404, 'Viewing not found');
    if (!['confirmed', 'arrived'].includes(v.status)) return err(400, 'The viewing is not confirmed yet');
    return out(200, { ok: true, role, mine: halves(v.id)[role], youDone: !!v[role + 'Ok'], otherDone: !!v[(role === 'seeker' ? 'owner' : 'seeker') + 'Ok'] });
  }
  async function visitVerify(me, b) {
    const { v, l, role } = await visitSide(me, b.id); if (!v || !role) return err(404, 'Viewing not found');
    if (!['confirmed', 'arrived'].includes(v.status)) return err(400, 'This viewing is not open for check-in');
    const k = v.id + '|' + me.id, t = (await store.get('vtries', k)) || { n: 0, at: now() }; if (now() - t.at > 36e5) { t.n = 0; t.at = now(); }
    if (t.n >= 8) return err(429, 'Too many wrong tries. Try again in an hour.');
    const other = role === 'seeker' ? 'owner' : 'seeker', want = halves(v.id)[other], code = String(b.code || '').replace(/\D/g, '');
    if (code !== want) { t.n++; await store.put('vtries', k, t); return err(400, 'Those digits are not right. Check with the ' + other + '.'); }
    v[role + 'Ok'] = now();
    if (role === 'seeker' && v.status === 'confirmed') { v.status = 'arrived'; v.at = now(); await notify(l.owner, U_(me) + ' is at ' + l.title + '. Enter their 3 digits in the app to finish.'); }
    if (v.seekerOk && v.ownerOk) { v.status = 'visited'; await settleFee(v, l, 'visited'); await notify(v.seeker, 'Viewing confirmed by both of you. You can continue to payment.'); await notify(l.owner, 'Viewing confirmed by both of you.' + (v.share ? ' GH₵' + v.share + ' viewing share is on its way to you.' : '')); }
    await store.put('visits', v.id, v, v.seeker); return out(200, { ok: true, status: v.status, youDone: true, otherDone: !!v[other + 'Ok'] });
  }

  /* ---------- router ---------- */
  let showP = null;
  function ensureShowcase() {
    if (!showP) showP = (async () => {
      if (await store.get('flags', 'showcase_v1')) return; const t = now();
      for (const u of SHOW.users) if (!(await store.get('users', u.id))) await store.put('users', u.id, Object.assign({}, u, { kyc: { status: 'verified', seeded: true } }), u.id);
      let i = 0; for (const l of SHOW.listings) { await store.put('listings', l.id, Object.assign({}, l, { t: t - (i++) * 5 * 36e5 }), l.owner); }
      for (const x of SHOW.partners) await store.put('partners', x.id, x);
      await store.put('flags', 'showcase_v1', { id: 'showcase_v1', done: 1 });
    })().catch(() => { showP = null; });
    return showP;
  }
  const SEEKERS = [{ id: 's_esi', name: 'Esi Owusu', roles: ['seeker'], showcase: true }, { id: 's_kwame', name: 'Kwame Boateng', roles: ['seeker'], showcase: true }, { id: 's_abena', name: 'Abena Larbi', roles: ['seeker'], showcase: true }];
  const ASK = ['Hello, I am looking at three places around Madina and Legon this Saturday. Can you walk me through them? I would like to start at 10am.', 'Good day. I am moving to Accra for work and need a 2-bedroom near the airport. Could you show me a few options this week?', 'Hi, are you free for a viewing day on Sunday? I have two hostels saved around Ayeduase and want someone to check the rooms with me.'];
  async function agentStarters(me) {
    try { await ensureShowcase(); for (let i = 0; i < SEEKERS.length; i++) { const s = SEEKERS[i]; if (!(await store.get('users', s.id))) await store.put('users', s.id, Object.assign({ kyc: { status: 'verified', seeded: true } }, s), s.id);
        const id = [s.id, me.id, '', 'agent'].join('|'); if (await store.get('chats', id)) continue;
        await store.put('chats', id, { id, a: s.id, b: me.id, listing: null, kind: 'agent', seen: {}, msgs: [{ from: 'sys', t: now() - 3000, x: 'You are chatting with a verified Izel agent. Never pay an agent directly. Izel handles payment.' }, { from: s.id, t: now() - 1000 * (i + 1), x: ASK[i] }] }, s.id); } } catch (e) {}
  }
  const STARTERS = ['l4q3n6d1', 'l63jwkf6', 'l49h1qew', 'l1dqfz9l'];
  async function starterChats(u) {
    try { await ensureShowcase(); const first = (u.name || 'there').split(' ')[0];
      for (const lid of STARTERS) { const l = await store.get('listings', lid); if (!l) continue; const o = await store.get('users', l.owner); const id = [u.id, l.owner, lid, 'enq'].join('|');
        const facts = l.type === 'land' ? (l.plot || 'a plot') : l.type === 'hostel' ? 'a room in my hostel' : (l.beds + ' bed, ' + l.baths + ' bath');
        const per = l.per && l.per !== 'sale' ? ' per ' + l.per : '';
        const msgs = [{ from: 'sys', t: now() - 3000, x: 'Chat is private. Phone numbers are hidden on Izel. If anyone asks you to move the conversation outside, report them.' },
          { from: l.owner, t: now() - 1000, x: 'Hello ' + first + ', this is my property: ' + l.title + ' in ' + l.area + ', ' + l.city + '. ' + facts + ', GH₵' + Number(l.price).toLocaleString('en-US') + per + '. Are you interested? You can book a viewing right here in Izel.' }];
        await store.put('chats', id, { id, a: u.id, b: l.owner, listing: lid, kind: 'enq', msgs, seen: {} }, u.id); }
    } catch (e) {}
  }
  const BOTK = (t) => /price|cost|how much|negotia|cheap|reduce/.test(t) ? 'price' : /availab|still|taken/.test(t) ? 'avail' : /pet|dog|cat/.test(t) ? 'pet' : /car|park/.test(t) ? 'car' : /view|visit|see|come/.test(t) ? 'view' : /^(hi|hello|hey|good)/.test(t) ? 'hi' : 'other';
  async function handle(req) {
    await ensureShowcase();
    const m = req.method, p = String(req.path || '').replace(/\/+$/, '') || '/', q = req.query || {};
    if (m === 'OPTIONS') return { status: 204, headers: cors(), body: '' };
    let body = {}; if (req.body && !/^\/api\/(_up|pay\/webhook)/.test(p)) { try { body = JSON.parse(Buffer.isBuffer(req.body) ? req.body.toString() : req.body); } catch (e) { return err(400, 'Bad JSON'); } }
    try {
      if (p === '/api/health') return out(200, { ok: true, store: store.kind, sms: sms.ready() || DEV, otpDev: DEV, paystack: !!E.PAYSTACK_SECRET_KEY, admins: ADMINS.length });
      if (p === '/api/config') return out(200, { ok: true, otpLen: OTPN, ownerPct: R.OWNER_PCT, google: E.GOOGLE_CLIENT_ID || undefined, apple: E.APPLE_CLIENT_ID || undefined, paystack: !!E.PAYSTACK_SECRET_KEY, test: !E.PAYSTACK_SECRET_KEY, usdRate: +E.USD_RATE || undefined });
      if (p === '/api/auth/otp' && m === 'POST') return await sendOtp(body);
      if (p === '/api/auth/google' && m === 'POST') return await socialLogin('google', body);
      if (p === '/api/auth/apple' && m === 'POST') return await socialLogin('apple', body);
      if (p === '/api/auth/verify' && m === 'POST') return await verifyOtp(body);
      if (p === '/api/pay/webhook' && m === 'POST') return await payWebhook(req);
      if (p === '/api/cron/payouts') { if ((req.headers || {}).authorization !== 'Bearer ' + (E.CRON_SECRET || '\u0000')) return err(401, 'no'); return out(200, { ok: true, results: await runPayouts() }); }
      if (p.startsWith('/api/_up/') && m === 'PUT') { const id = p.slice(9); if (q.s !== sha(id + SECRET).slice(0, 24) || !store.saveLocal) return err(403, 'bad upload link'); const buf = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || ''); await store.saveLocal(id, buf); return out(200, { ok: true }); }
      if (p === '/api/demo/unlock' && m === 'POST') { const pin = String(E.DEMO_PIN || ''); if (!pin) return err(404, 'Not found'); const k = 'demo', t = (await store.get('vtries', k)) || { n: 0, at: now() }; if (now() - t.at > 6e5) { t.n = 0; t.at = now(); } if (t.n >= 10) return err(429, 'Try again later'); const got = String(body.pin || ''); const okp = got.length === pin.length && crypto.timingSafeEqual(Buffer.from(got), Buffer.from(pin)); if (!okp) { t.n++; await store.put('vtries', k, t); return err(400, 'No'); } return out(200, { ok: true }); }
      if (p === '/api/verify' && m === 'GET') { const ref = String(q.ref || '').toUpperCase(); const d = ref && ((await store.list('deals')).concat(await store.list('holds'))).map(r => r.data).find(x => x.cert === ref); const bad = !d; const l = d ? await store.get('listings', d.listing) : null; const j = bad ? { ok: false, reason: 'No Izel deal has this reference.' } : { ok: true, ref, property: l ? l.title : '', area: l ? l.area : '', amount: d.amount, date: d.t, status: d.status };
        if (q.v) { const e = (x) => String(x == null ? '' : x).replace(/[<>&"]/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c])); const html = '<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Izel check</title><body style="font-family:system-ui;background:#0d0d0b;color:#f3f0e6;display:grid;place-items:center;min-height:100vh;margin:0"><div style="max-width:380px;padding:28px;text-align:center"><div style="font-size:44px">' + (bad ? '✕' : '✓') + '</div><h1 style="font-size:24px;margin:8px 0">' + (bad ? 'Not an Izel deal' : 'Genuine Izel deal') + '</h1><p style="font-size:16px;color:#a7a293">' + (bad ? 'We have no record of this reference.' : e(j.ref) + '<br>' + e(j.property) + (j.area ? ', ' + e(j.area) : '') + '<br>GH₵' + e(j.amount) + ' paid through Izel on ' + new Date(j.date).toISOString().slice(0, 10)) + '</p><p style="font-size:14px;color:#777">Powered by Berchy</p></div>'; return { status: bad ? 404 : 200, headers: Object.assign({ 'Content-Type': 'text/html; charset=utf-8' }, cors()), body: html }; }
        return out(bad ? 404 : 200, j); }
      const me = await authed(req);
      if (p.startsWith('/api/media/') && m === 'GET' && p !== '/api/media/new' && p !== '/api/media/done') return await mediaGet(req, p.slice(11), me);
      if (p === '/api/pull' && m === 'GET') {
        if (!me) { // browsing without an account: live listings and partners only
          const rows = await store.since(+q.since || 0, ['listings', 'partners', 'asks']), data = { listings: [], partners: [], asks: [], users: [] }, seen = new Set(); let cursor = +q.since || 0;
          rows.forEach(r => { if (r.u > cursor) cursor = r.u; if (r.c === 'listings' && r.data.status !== 'live') return; data[r.c].push({ id: r.id, d: r.data }); if (r.c === 'listings') seen.add(r.data.owner); });
          for (const id of seen) { const u = await store.get('users', id); if (u) data.users.push({ id, d: pubUser(u) }); }
          return out(200, { cursor, data, me: {} });
        }
        return out(200, await pull(me, +q.since || 0));
      }
      if (!me) return err(401, 'Please sign in', { code: 'auth' });
      if (p === '/api/starter' && m === 'POST') { if (body.role === 'agent') await agentStarters(me); return out(200, { ok: true }); }
      if (p === '/api/me') return out(200, { ok: true, user: me });
      if (p === '/api/push' && m === 'POST') return out(200, await push(me, body));
      if (p === '/api/media/new' && m === 'POST') return await mediaNew(me, body);
      if (p === '/api/media/done' && m === 'POST') return await mediaDone(me, body);
      if (p === '/api/pay/init' && m === 'POST') return await payInit(me, body);
      if (p === '/api/pay/verify' && m === 'POST') return await payVerify(me, body);
      if (p === '/api/payout/recipient' && m === 'POST') return await payoutRecipient(me, body);
      if (p === '/api/visit/code' && m === 'GET') return await visitCode(me, q.id);
      if (p === '/api/visit/verify' && m === 'POST') return await visitVerify(me, body);
      if (p === '/api/view' && m === 'POST') { const id = str(body.id, 40), day = new Date().toISOString().slice(0, 10), k = id + '|' + me.id + '|' + day; if (await store.get('vw', k)) return out(200, { ok: true }); await store.put('vw', k, { t: now() }); const l = await store.get('listings', id); if (l && l.owner !== me.id) { l.views = (l.views || 0) + 1; await store.put('listings', id, l, l.owner); } return out(200, { ok: true }); }
      if (p === '/api/admin/payouts' && m === 'POST') { if (!isAdmin(me)) return err(403, 'Admins only'); return out(200, { ok: true, results: await runPayouts() }); }
      if (p === '/api/admin/import' && m === 'POST') { if (!isAdmin(me)) return err(403, 'Admins only'); let n = 0; for (const u of (body.users || [])) { if (u && u.id && !(await store.get('users', u.id))) { u.kyc = { status: 'verified', seeded: true }; await store.put('users', u.id, u, u.id); n++; } } for (const l of (body.listings || [])) { if (l && l.id) { await store.put('listings', l.id, l, l.owner); n++; } } for (const x of (body.partners || [])) { if (x && x.id) { await store.put('partners', x.id, x); n++; } } return out(200, { ok: true, imported: n }); }
      return err(404, 'Not found');
    } catch (e) { return err(500, 'Server error: ' + e.message); }
  }
  return { handle, _sign: sign, _store: store };
};

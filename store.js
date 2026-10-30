'use strict';
// Storage adapters. Same interface everywhere:
//   get(c,id) -> data|null     put(c,id,data,owner) -> stamp     since(stamp,colls?) -> [{c,id,data,u}]     list(c) -> [{c,id,data}]
const fs = require('fs'), path = require('path');
let seq = 0;
function stamp() { seq = (seq + 1) % 1000; return Date.now() * 1000 + seq; }

function memoryStore(file) {
  let rows = new Map();
  if (file) { try { rows = new Map(JSON.parse(fs.readFileSync(file, 'utf8'))); } catch (e) {} }
  let t = null;
  const flush = () => { if (!file) return; clearTimeout(t); t = setTimeout(() => { try { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, JSON.stringify([...rows])); } catch (e) {} }, 50); };
  return {
    kind: file ? 'file' : 'memory',
    async get(c, id) { const r = rows.get(c + '\u0000' + id); return r ? JSON.parse(JSON.stringify(r.data)) : null; },
    async put(c, id, data, owner) { const u = stamp(); rows.set(c + '\u0000' + id, { c, id, data: JSON.parse(JSON.stringify(data)), owner: owner || null, u }); flush(); return u; },
    async del(c, id) { rows.delete(c + '\u0000' + id); flush(); },
    async since(s, colls) { const out = []; rows.forEach(r => { if (r.u > s && (!colls || colls.includes(r.c))) out.push({ c: r.c, id: r.id, data: JSON.parse(JSON.stringify(r.data)), u: r.u }); }); return out.sort((a, b) => a.u - b.u); },
    async list(c) { const out = []; rows.forEach(r => { if (r.c === c) out.push({ c: r.c, id: r.id, data: JSON.parse(JSON.stringify(r.data)) }); }); return out; },
  };
}

function supabaseStore(env) {
  const base = String(env.SUPABASE_URL || '').trim().replace(/\/+$/, '').replace(/\/rest\/v1$/, ''), key = String(env.SUPABASE_SERVICE_KEY || '').trim();
  const H = (x) => Object.assign({ apikey: key, 'Content-Type': 'application/json' }, key.startsWith('sb_') ? {} : { Authorization: 'Bearer ' + key }, x || {});
  async function rest(method, p, body, prefer) {
    const r = await fetch(base + '/rest/v1/' + p, { method, headers: H(prefer ? { Prefer: prefer } : {}), body: body ? JSON.stringify(body) : undefined });
    const t = await r.text(); if (!r.ok) throw new Error('Supabase ' + r.status + ' ' + t.slice(0, 200));
    return t ? JSON.parse(t) : null;
  }
  const q = encodeURIComponent;
  return {
    kind: 'supabase', base, H,
    async get(c, id) { const r = await rest('GET', 'izel_records?c=eq.' + q(c) + '&id=eq.' + q(id) + '&select=data'); return r && r[0] ? r[0].data : null; },
    async put(c, id, data, owner) { const u = stamp(); await rest('POST', 'izel_records?on_conflict=c,id', { c, id, data, owner: owner || null, u }, 'resolution=merge-duplicates,return=minimal'); return u; },
    async del(c, id) { await rest('DELETE', 'izel_records?c=eq.' + q(c) + '&id=eq.' + q(id)); },
    async since(s, colls) { let out = [], from = s; for (let i = 0; i < 20; i++) { const rows = await rest('GET', 'izel_records?u=gt.' + from + (colls ? '&c=in.(' + colls.map(q).join(',') + ')' : '') + '&order=u.asc&limit=1000&select=c,id,data,u'); out = out.concat(rows); if (rows.length < 1000) break; from = rows[rows.length - 1].u; } return out; },
    async list(c) { return await rest('GET', 'izel_records?c=eq.' + q(c) + '&select=c,id,data&limit=5000'); },
  };
}
module.exports = { memoryStore, supabaseStore };

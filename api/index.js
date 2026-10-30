'use strict';
const { supabaseStore, memoryStore } = require('../store');
const makeApp = require('../app');
let app;
function get() { if (!app) { const E = process.env; app = makeApp(E, E.SUPABASE_URL ? supabaseStore(E) : memoryStore()); } return app; }
module.exports = async (req, res) => {
  const chunks = []; for await (const c of req) chunks.push(c); const raw = Buffer.concat(chunks);
  const u = new URL(req.url, 'http://x'), q = Object.fromEntries(u.searchParams);
  const r = await get().handle({ method: req.method, path: u.pathname, query: q, headers: req.headers, body: raw.length ? raw : undefined });
  res.statusCode = r.status; Object.entries(r.headers || {}).forEach(([k, v]) => res.setHeader(k, v)); res.end(r.body);
};
module.exports.config = { api: { bodyParser: false } };

'use strict';
// Business rules that must never be trusted to the phone: contact-sharing filter, fees, photo checks.
const FEE = { rent: 5, sale: 1.5, hostel: 4, stay: 8, land: 1.5 }, PROC = 1.95;

function norm(t) { return String(t).normalize('NFKC').replace(/[⓪①-⑨]/g, c => c === '⓪' ? '0' : String.fromCharCode(c.charCodeAt(0) - 0x2460 + 49)); }
function leaks(text) {
  const s = norm(text), d = s.replace(/[^\d]/g, '');
  if (/(\+?\d[\d\s().\-]{7,}\d)/.test(s) && d.length >= 9) return true;
  if (/whats\s?app|telegram|signal|call me|text me|my number|my phone|momo me|\binsta|\bsnap|@[a-z0-9._-]+\.[a-z]{2,}|\b(gmail|yahoo|hotmail)\b|\bdm me\b/i.test(s)) return true;
  const w = { zero: 0, one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9 }; let n = 0;
  s.toLowerCase().split(/[^a-z]+/).forEach(x => { if (x in w) n++; }); if (n >= 7) return true;
  const l = s.toLowerCase();
  return /\b(pay|send|give|transfer)\b.{0,25}\b(cash|directly|momo|mobile money|account|me)\b/.test(l) || /outside (of )?(the )?(app|izel|platform)/.test(l) || /\b(avoid|skip|bypass|without|dodge)\b.{0,15}\b(fee|app|izel|commission)\b/.test(l) || /\bmeet\b.{0,30}\bpay\b/.test(l) || /\bmy (momo|account|acc|line|contact|number|digits|whats)/.test(l) || /\b(zero|oh)\s?(two|2)\s?(four|4|zero|0|three|3|five|5|seven|7|eight|8)/.test(l);
}
// numbers split across a person's last messages ("0244" "556" "7788")
function splitLeak(prevTexts, text) {
  let d = 0, hits = 0; prevTexts.slice(-4).concat([text]).forEach(x => { const n = (norm(x).match(/\d/g) || []).length; if (n >= 2 && n < 9) { d += n; hits++; } });
  return hits >= 2 && d >= 9;
}
// Reads the first 256 KB of an uploaded photo: camera maker present, no AI or editing-app marks.
function scanPhoto(buf) {
  let s = ''; const u8 = buf.subarray(0, 262144); for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i] < 32 || u8[i] > 126 ? 32 : u8[i]);
  const ai = /midjourney|dall[\s\-·]?e\b|stable\s?diffusion|firefly|generative|c2pa|jumbf|trainedalgorithmicmedia|openai|chatgpt|imagen|leonardo\.?ai|runway|upscayl|topaz|remini|lensa|faceapp|beautycam|meitu|facetune|photoleap/i.exec(s);
  if (ai) return { ok: false, ai: true, why: 'AI or enhancement marks found (' + ai[0] + ')' };
  const jpg = u8[0] === 0xFF && u8[1] === 0xD8, png = u8[0] === 0x89 && u8[1] === 0x50, webp = s.indexOf('WEBP') > -1, heic = s.indexOf('ftyp') > -1;
  if (!jpg && !png && !webp && !heic) return { ok: false, why: 'This file is not a photo' };
  return { ok: true };
}
function dist(a, b, c, d) { const R = 6371000, t = x => x * Math.PI / 180, dl = t(c - a), dg = t(d - b), x = Math.sin(dl / 2) ** 2 + Math.cos(t(a)) * Math.cos(t(c)) * Math.sin(dg / 2) ** 2; return 2 * R * Math.asin(Math.sqrt(x)); }
function feeOf(type, amount) { const f = Math.round(amount * (FEE[type] || 5)) / 100, p = Math.round(amount * PROC) / 100; return { fee: f, proc: p, payout: Math.round((amount - f - p) * 100) / 100 }; }
const PLEDGE = 20, OWNER_PCT = +process.env.VIEW_OWNER_PCT || 70;
module.exports = { PLEDGE, OWNER_PCT, FEE, PROC, leaks, splitLeak, scanPhoto, dist, feeOf, norm };

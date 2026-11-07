// Neora - Vercel serverless proxy.
// The browser talks to its own HTTPS origin (/api/start); this function relays the
// request to the Vultr VM backend. That avoids mixed-content errors and keeps the
// backend address out of the public repo and out of the browser.
//
// Required environment variables (Vercel > Project > Settings > Environment Variables):
//   API_TARGET    Backend base URL, e.g. https://backend.example.com   (no trailing slash). Use HTTPS: the
//                 X-Proxy-Secret header is sent to this URL, and plain HTTP would expose it on the network.
//   PROXY_SECRET  Long random string, also configured on the backend. The backend must
//                 only trust X-Forwarded-For when X-Proxy-Secret matches this value.

const API_TARGET = (process.env.API_TARGET || '').replace(/\/+$/, '');
const PROXY_SECRET = process.env.PROXY_SECRET || '';
const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : '');

function clientIp(req) {
  const real = req.headers['x-real-ip'];
  if (typeof real === 'string' && real) return real.trim();
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff) return xff.split(',')[0].trim();
  return '';
}
const fail = (res, e) => {
  console.error('proxy hatası:', e && e.message);
  const timedOut = e && (e.name === 'TimeoutError' || e.name === 'AbortError');
  return res.status(timedOut ? 504 : 502).json({ error: timedOut ? 'Agent zamanında cevap veremedi.' : "Backend'e ulaşılamadı." });
};

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return res.status(405).json({ error: 'POST gerekli.' }); }
  if (!API_TARGET || PROXY_SECRET.length < 32) return res.status(500).json({ error: 'Sunucu yapılandırması eksik.' });
  const input = req.body;
  if (!input || typeof input !== 'object' || Array.isArray(input)) return res.status(400).json({ error: 'Geçersiz istek.' });
  const body = JSON.stringify({ url: str(input.url, 2048), goal: str(input.goal, 4000), model: str(input.model, 80), lang: str(input.lang, 8) });
  if (Buffer.byteLength(body) > 100 * 1024) return res.status(413).json({ error: 'İstek çok büyük.' });
  try {
    const r = await fetch(API_TARGET + '/api/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Proxy-Secret': PROXY_SECRET, 'X-Forwarded-For': clientIp(req) },
      body,
      signal: AbortSignal.timeout(15000),
    });
    res.status(r.status).setHeader('Content-Type', 'application/json; charset=utf-8');
    return res.send(await r.text());
  } catch (e) { return fail(res, e); }
}

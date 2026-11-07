// Neora - Vercel serverless proxy.
// The browser talks to its own HTTPS origin (/api/analyze); this function relays the
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

const MAX_BODY = 100 * 1024;        // same limit as serve.mjs
const MAX_GOAL = 4000;              // characters
const MAX_URL = 2048;               // characters
const MAX_MODEL = 80;               // characters
const UPSTREAM_TIMEOUT_MS = 55000;  // must stay below maxDuration (60 s) in vercel.json

const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : '');

function clientIp(req) {
  // Vercel overwrites these headers, so they cannot be spoofed by the caller.
  const real = req.headers['x-real-ip'];
  if (typeof real === 'string' && real) return real.trim();
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff) return xff.split(',')[0].trim();
  return '';
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'POST gerekli.' });
  }

  if (!API_TARGET || PROXY_SECRET.length < 32) {
    console.error('API_TARGET veya PROXY_SECRET tanımlı değil.');
    return res.status(500).json({ error: 'Sunucu yapılandırması eksik.' });
  }

  const input = req.body;
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return res.status(400).json({ error: 'Geçersiz istek.' });
  }

  // Forward only the fields the backend understands, with sane length limits.
  const body = JSON.stringify({
    url: str(input.url, MAX_URL),
    goal: str(input.goal, MAX_GOAL),
    model: str(input.model, MAX_MODEL),
    lang: str(input.lang, 8),
    deep: input.deep === true,
  });
  if (Buffer.byteLength(body) > MAX_BODY) {
    return res.status(413).json({ error: 'İstek çok büyük.' });
  }

  try {
    const r = await fetch(API_TARGET + '/api/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Proxy-Secret': PROXY_SECRET,
        'X-Forwarded-For': clientIp(req),
      },
      body,
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    });
    const text = await r.text();
    res.status(r.status).setHeader('Content-Type', 'application/json; charset=utf-8');
    return res.send(text);
  } catch (e) {
    console.error('proxy hatası:', e && e.message);
    const timedOut = e && (e.name === 'TimeoutError' || e.name === 'AbortError');
    return res.status(timedOut ? 504 : 502).json({
      error: timedOut ? 'Agent zamanında cevap veremedi.' : "Backend'e ulaşılamadı.",
    });
  }
}

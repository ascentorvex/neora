// Raw binary upload proxy. Vercel's request body parser is disabled so bytes are forwarded unchanged.
const API_TARGET = (process.env.API_TARGET || '').replace(/\/+$/, '');
const PROXY_SECRET = process.env.PROXY_SECRET || '';
const MAX_BYTES = 4 * 1024 * 1024;
export const config = { api: { bodyParser: false } };

function clientIp(req) {
  const real = req.headers['x-real-ip'];
  if (typeof real === 'string' && real) return real.trim();
  const xff = req.headers['x-forwarded-for'];
  return typeof xff === 'string' && xff ? xff.split(',')[0].trim() : '';
}
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return res.status(405).json({ error: 'POST gerekli.' }); }
  if (!API_TARGET || PROXY_SECRET.length < 32) return res.status(500).json({ error: 'Sunucu yapılandırması eksik.' });
  const chunks = []; let size = 0;
  try {
    for await (const chunk of req) {
      size += chunk.length;
      if (size > MAX_BYTES) return res.status(413).json({ error: 'Dosya boyutu en fazla 4 MB olabilir.' });
      chunks.push(chunk);
    }
    if (!size) return res.status(400).json({ error: 'Dosya boş.' });
    const upstream = await fetch(API_TARGET + '/api/upload', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-File-Name': String(req.headers['x-file-name'] || 'uploaded-file').slice(0, 360),
        'X-Proxy-Secret': PROXY_SECRET,
        'X-Forwarded-For': clientIp(req),
      },
      body: Buffer.concat(chunks),
      signal: AbortSignal.timeout(30000),
    });
    res.status(upstream.status).setHeader('Content-Type', 'application/json; charset=utf-8');
    return res.send(await upstream.text());
  } catch (e) {
    console.error('upload proxy error:', e && e.message);
    return res.status(502).json({ error: 'Dosya backend sunucusuna aktarılamadı.' });
  }
}

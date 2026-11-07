// Neora - zero-dependency static server + same-origin API proxy.
//   npm start                                   -> http://localhost:8080
//   PORT=80 npm start                           -> on the Vultr VM
//   API_TARGET=http://BACKEND_HOST:3000 PROXY_SECRET=... npm start   -> backend on another machine
import http from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('.', import.meta.url));
const PORT = Number(process.env.PORT) || 8080;
const HOST = process.env.HOST || '0.0.0.0';
const API_TARGET = (process.env.API_TARGET || 'http://127.0.0.1:3000').replace(/\/+$/, '');
const PROXY_SECRET = process.env.PROXY_SECRET || '';
if (PROXY_SECRET.length < 32) throw new Error('PROXY_SECRET zorunludur (en az 32 karakter). openssl rand -hex 32 ile üretin.');
const MAX_BODY = 100 * 1024;

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.txt': 'text/plain; charset=utf-8',
};
const PUBLIC = (p) => p === 'index.html' || p === 'robots.txt' || /^(css|js|config)\//.test(p);

const SECURITY = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'microphone=(self), camera=(), geolocation=(), payment=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
};

function send(res, status, body, headers = {}) {
  res.writeHead(status, { ...SECURITY, ...headers });
  res.end(body);
}
const sendJson = (res, status, obj) =>
  send(res, status, JSON.stringify(obj), { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });

async function proxy(req, res, path = '/api/analyze') {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > MAX_BODY) {
      res.setHeader('Connection', 'close');
      return sendJson(res, 413, { error: 'İstek çok büyük.' });
    }
    chunks.push(c);
  }
  try {
    const r = await fetch(API_TARGET + path, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': req.socket.remoteAddress || '',
        'X-Proxy-Secret': PROXY_SECRET,
      },
      body: Buffer.concat(chunks),
      signal: AbortSignal.timeout(130000),
    });
    send(res, r.status, await r.text(), { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  } catch (e) {
    console.error('proxy hatası:', e.message);
    sendJson(res, 502, { error: 'Backend\'e ulaşılamadı.' });
  }
}

async function serveStatic(req, res, pathname) {
  let rel;
  try { rel = decodeURIComponent(pathname); } catch { return send(res, 400, 'Bad request'); }
  if (rel.includes('\0')) return send(res, 400, 'Bad request');
  rel = normalize(rel.replace(/^\/+/, '') || 'index.html').split(sep).join('/');
  if (rel.startsWith('..') || !PUBLIC(rel)) return send(res, 404, 'Not found');
  try {
    const file = join(ROOT, rel);
    if (!(await stat(file)).isFile()) return send(res, 404, 'Not found');
    const data = await readFile(file);
    const ext = extname(file);
    const cache = ext === '.css' || ext === '.js' ? (rel.startsWith('config/') ? 'no-cache' : 'public, max-age=3600') : 'no-cache';
    send(res, 200, req.method === 'HEAD' ? '' : data, {
      'Content-Type': MIME[ext] || 'application/octet-stream', 'Content-Length': data.length, 'Cache-Control': cache,
    });
  } catch { send(res, 404, 'Not found'); }
}

const server = http.createServer((req, res) => {
  const { pathname } = new URL(req.url, 'http://localhost');
  if (pathname === '/api/analyze') {
    return req.method === 'POST' ? proxy(req, res) : sendJson(res, 405, { error: 'POST gerekli.' });
  }
  if (pathname === '/api/start') {
    return req.method === 'POST' ? proxy(req, res, '/api/start') : sendJson(res, 405, { error: 'POST gerekli.' });
  }
  if (pathname === '/api/job') {
    const id = new URL(req.url, 'http://localhost').searchParams.get('id') || '';
    if (!/^[a-f0-9]{32}$/.test(id)) return sendJson(res, 400, { error: 'Geçersiz istek.' });
    return fetch(API_TARGET + '/api/job/' + id, { headers: { 'X-Proxy-Secret': PROXY_SECRET }, signal: AbortSignal.timeout(15000) })
      .then(async (r) => send(res, r.status, await r.text(), { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }))
      .catch(() => sendJson(res, 502, { error: 'Backend\'e ulaşılamadı.' }));
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed', { Allow: 'GET, HEAD' });
  serveStatic(req, res, pathname);
});

server.listen(PORT, HOST, () => console.log(`Neora: http://localhost:${PORT}  (API -> ${API_TARGET})`));
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => server.close(() => process.exit(0)));

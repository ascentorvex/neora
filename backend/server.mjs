import { timingSafeEqual } from 'node:crypto';
import { limiter } from './ratelimit.mjs';
import express from 'express';
import { analyze } from './agent.mjs';
import { startJob, getJob } from './jobs.mjs';
import { cleanLang } from './lang.mjs';
import { saveUpload } from './uploads.mjs';

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const PROXY_SECRET = process.env.PROXY_SECRET || '';
if (Buffer.byteLength(PROXY_SECRET) < 32) {
  throw new Error('PROXY_SECRET zorunludur ve en az 32 byte olmalıdır. openssl rand -hex 32 ile üretin.');
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY || 'loopback');

function authenticatedProxy(req, res, next) {
  const supplied = req.get('X-Proxy-Secret') || '';
  const a = Buffer.from(supplied);
  const b = Buffer.from(PROXY_SECRET);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'Yetkisiz istek.' });
  }
  next();
}

app.use(express.json({ limit: '100kb', strict: true }));
app.get('/health', (req, res) => res.set('Cache-Control', 'no-store').json({ ok: true }));

// Raw file upload: the frontend proxy forwards application/octet-stream.
// Files are size-limited, assigned an unguessable ID and stored with private permissions.
app.post('/api/upload', authenticatedProxy, limiter,
  express.raw({ type: 'application/octet-stream', limit: '64mb' }),
  async (req, res) => {
    try {
      const encoded = String(req.get('X-File-Name') || 'uploaded-file').slice(0, 360);
      let name = 'uploaded-file';
      try { name = decodeURIComponent(encoded); } catch {}
      const saved = await saveUpload(name, req.body);
      res.set('Cache-Control', 'no-store').status(201).json(saved);
    } catch (e) {
      res.status(e.status || 400).json({ error: e.status ? e.message : 'Dosya yüklenemedi.' });
    }
  });


app.post('/api/analyze', authenticatedProxy, limiter, async (req, res) => {
  const url = typeof req.body?.url === 'string' ? req.body.url.trim().slice(0, 2048) : '';
  const goal = typeof req.body?.goal === 'string' ? req.body.goal.trim().slice(0, 4000) : '';
  const model = typeof req.body?.model === 'string' ? req.body.model.trim().slice(0, 80) : '';
  const lang = cleanLang(req.body?.lang);
  try {
    const r = await analyze(url, goal, model, { lang });
    res.set('Cache-Control', 'no-store').json(typeof r === 'string' ? { answer: r } : r);
  } catch (e) {
    console.error('analyze hatası:', e.message);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Sunucu hatası.' });
  }
});

const fields = (b) => ({
  url: typeof b?.url === 'string' ? b.url.trim().slice(0, 2048) : '',
  goal: typeof b?.goal === 'string' ? b.goal.trim().slice(0, 4000) : '',
  model: typeof b?.model === 'string' ? b.model.trim().slice(0, 80) : '',
  lang: cleanLang(b?.lang),
});

// Async mode: start a job, then poll /api/job/:id for live status and the final result.
app.post('/api/start', authenticatedProxy, limiter, (req, res) => {
  const { url, goal, model, lang } = fields(req.body);
  const r = startJob(req.ip, (onStatus) => analyze(url, goal, model, { onStatus, lang }));
  if (r.error) return res.status(r.code).json({ error: r.error });
  res.status(202).set('Cache-Control', 'no-store').json({ id: r.id });
});

app.get('/api/job/:id', authenticatedProxy, (req, res) => {
  if (!/^[a-f0-9]{32}$/.test(req.params.id)) return res.status(400).json({ error: 'Geçersiz istek.' });
  const j = getJob(req.params.id);
  if (!j) return res.status(404).json({ error: 'İş bulunamadı.' });
  res.set('Cache-Control', 'no-store').json(j);
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  res.status(err.status === 413 ? 413 : 400).json({ error: err.status === 413 ? 'İstek çok büyük.' : 'Geçersiz istek.' });
});

process.on('unhandledRejection', (e) => console.error('unhandledRejection:', e));
process.on('uncaughtException', (e) => { console.error('uncaughtException:', e); process.exit(1); });

app.listen(PORT, HOST, () => console.log(`Neora backend ${HOST}:${PORT} üzerinde aktif`));

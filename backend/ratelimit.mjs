const hits = new Map();
let active = 0;
const WINDOW = 60000, MAX = 10, MAX_ACTIVE = 3, MAX_KEYS = 10000;

setInterval(() => {
  const t = Date.now();
  for (const [k, v] of hits) if (t - v.start > WINDOW) hits.delete(k);
}, 60000).unref();

export function limiter(req, res, next) {
  const t = Date.now();
  const key = String(req.ip || 'unknown').slice(0, 64);
  let h = hits.get(key);
  if (!h || t - h.start > WINDOW) {
    if (!h && hits.size >= MAX_KEYS) {
      const oldest = hits.keys().next().value;
      if (oldest !== undefined) hits.delete(oldest);
    }
    h = { start: t, n: 0 };
    hits.set(key, h);
  }
  if (++h.n > MAX) return res.status(429).json({ error: 'Çok fazla istek. Bir dakika sonra tekrar dene.' });
  if (active >= MAX_ACTIVE) return res.status(503).json({ error: 'Sunucu şu an meşgul, birkaç saniye sonra tekrar dene.' });
  active++;
  let done = false;
  const release = () => { if (!done) { done = true; active--; } };
  res.on('finish', release);
  res.on('close', release);
  next();
}

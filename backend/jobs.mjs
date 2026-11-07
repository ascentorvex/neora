// In-memory job store: the browser starts a job, then polls its live status until the result is ready.
// Removes the proxy's 55 s limit and lets the UI show what the agent is doing right now.
// A running job is never expired; only finished results are dropped after TTL_MS.
import { randomBytes } from 'node:crypto';

const jobs = new Map();
const TTL_MS = 10 * 60 * 1000, MAX_JOBS = 200, PER_IP = 2;

function sweep() {
  const now = Date.now();
  for (const [id, j] of jobs) if (j.state !== 'running' && now - j.t > TTL_MS) jobs.delete(id); // running jobs live until they finish
}

export function startJob(ip, run) {
  sweep();
  const mine = [...jobs.values()].filter((j) => j.ip === ip && j.state === 'running').length;
  if (mine >= PER_IP) return { error: 'Too many running requests. Wait for the current one to finish.', code: 429 };
  if (jobs.size >= MAX_JOBS) return { error: 'Server busy, try again shortly.', code: 503 };
  const id = randomBytes(16).toString('hex');
  const job = { id, ip, state: 'running', status: { k: 'think', d: '' }, t: Date.now(), result: null, error: '', code: 0 };
  jobs.set(id, job);
  Promise.resolve()
    .then(() => run((s) => { if (s && typeof s.k === 'string') job.status = { k: s.k.slice(0, 12), d: String(s.d || '').slice(0, 90) }; }))
    .then((r) => { job.result = typeof r === 'string' ? { answer: r } : r; job.state = 'done'; })
    .catch((e) => { job.error = e && e.status ? e.message : 'Sunucu hatası.'; job.code = (e && e.status) || 500; job.state = 'error'; console.error('job hatası:', e && e.message); })
    .finally(() => { job.t = Date.now(); });
  return { id };
}

export function getJob(id) {
  sweep();
  const j = jobs.get(id);
  if (!j) return null;
  return { state: j.state, status: j.status, ...(j.state === 'done' ? { result: j.result } : {}), ...(j.state === 'error' ? { error: j.error, code: j.code } : {}) };
}

import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const IMAGE = process.env.FETCH_IMAGE || 'node:22-alpine';
// Backend root (not just fetcher/): fetcher.mjs imports ../security/url-guard.mjs
const DIR = (process.env.FETCHER_DIR || fileURLToPath(new URL('.', import.meta.url))).replace(/\/$/, '');
let running = 0;

function run(mode, arg) {
  return new Promise((resolve, reject) => {
    if (running >= 4) return reject(new Error('Çok fazla eşzamanlı istek, tekrar dene.'));
    running++;
    const name = 'neora-fetch-' + randomBytes(4).toString('hex');
    const args = [
      'run', '--rm', '--name', name,
      '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m',
      '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
      '--memory', '192m', '--memory-swap', '192m', '--cpus', '0.5', '--pids-limit', '64',
      '--user', '65534:65534',
      '-v', `${DIR}:/app:ro`, '-w', '/app',
      IMAGE, 'node', 'fetcher/fetcher.mjs', mode, arg,
    ];
    execFile('docker', args, { timeout: 30000, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      running--;
      if (err) {
        execFile('docker', ['rm', '-f', name], () => {});
        return reject(new Error(err.killed ? 'Zaman aşımı' : (stderr || err.message).slice(0, 200)));
      }
      try {
        const j = JSON.parse(stdout.trim().split('\n').pop());
        j.ok ? resolve(j.data) : reject(new Error(j.error));
      } catch { reject(new Error('Geçersiz fetcher çıktısı')); }
    });
  });
}

export const isoSearch = (q) => run('search', q);
export const isoRead = (u) => run('read', u);

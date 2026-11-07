import { execFile } from 'node:child_process';
import { randomBytes, createHash, createHmac } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const IMAGE = process.env.SANDBOX_IMAGE || 'python:3.12-alpine';
const TIMEOUT_MS = 10000;
const MAX_OUT = 12000;
const MAX_RUNNING = 2;
let running = 0;

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

const RUNNER = fileURLToPath(new URL('./sandbox/runner.py', import.meta.url));
const AUDIT_HMAC_KEY = process.env.AUDIT_HMAC_KEY || '';
if (AUDIT_HMAC_KEY && Buffer.byteLength(AUDIT_HMAC_KEY) < 32) {
  throw new Error('AUDIT_HMAC_KEY tanımlıysa en az 32 byte olmalıdır.');
}

export function evaluateCommand(command) {
  const cmd = String(command || '').trim();
  if (!cmd || cmd.length > 2000) return { allowed: false, reason: 'Komut boş veya uzunluk sınırını aşıyor.' };
  const match = cmd.match(/^python3\s+-c\s+(?:"([^"]*)"|'([^']*)')$/);
  if (!match) return { allowed: false, reason: 'Yalnızca kısıtlı Python3 -c komutları çalıştırılabilir.' };
  const source = match[1] ?? match[2];
  if (!source.trim()) return { allowed: false, reason: 'Python kodu boş.' };
  return { allowed: true, reason: 'restricted-python-ast', source };
}

function receipt({ id, command, output, startedAt, finishedAt, exitCode, decision, cleanup }) {
  const base = {
    version: 1,
    sandboxId: id,
    commandHash: sha256(command),
    outputHash: sha256(output),
    startedAt,
    finishedAt,
    durationMs: Math.max(0, Date.parse(finishedAt) - Date.parse(startedAt)),
    exitCode,
    policy: decision,
    containerCleanup: cleanup,
  };
  const receiptHash = sha256(JSON.stringify(base));
  const signature = AUDIT_HMAC_KEY ? createHmac('sha256', AUDIT_HMAC_KEY).update(receiptHash).digest('hex') : null;
  return { ...base, receiptHash, signature };
}

export function runInSandbox(command, onReceipt) {
  const emit = (p) => { console.log('AUDIT', JSON.stringify(p)); try { onReceipt && onReceipt(p); } catch {} };
  const cmd = String(command || '');
  const decision = evaluateCommand(cmd);
  const id = 'neora-sbx-' + randomBytes(8).toString('hex');
  const startedAt = new Date().toISOString();
  if (!decision.allowed) {
    const output = `POLICY DENY: ${decision.reason}`;
    const finishedAt = new Date().toISOString();
    const proof = receipt({ id, command: cmd, output, startedAt, finishedAt, exitCode: null, decision: 'deny', cleanup: 'not-created' });
    emit(proof);
    return Promise.resolve(output);
  }
  if (running >= MAX_RUNNING) return Promise.resolve('Sandbox meşgul; lütfen tekrar dene.');
  running++;
  const encoded = Buffer.from(decision.source, 'utf8').toString('base64');
  const args = [
    'run', '--rm', '--name', id,
    '--network', 'none', '--ipc', 'private',
    '--memory', '128m', '--memory-swap', '128m', '--memory-reservation', '64m',
    '--cpus', '0.5', '--pids-limit', '48',
    '--ulimit', 'nofile=64:64', '--ulimit', 'nproc=48:48',
    '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=8m',
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    '--user', '65534:65534',
    '-v', `${RUNNER}:/runner.py:ro`,
    IMAGE, 'python3', '-I', '-S', '/runner.py', encoded,
  ];
  return new Promise((resolve) => {
    execFile('docker', args, { timeout: TIMEOUT_MS, maxBuffer: 512 * 1024, windowsHide: true }, (err, stdout, stderr) => {
      let released = false;
      let output = `${stdout || ''}${stderr ? '\n' + stderr : ''}`.trim().slice(0, MAX_OUT);
      let exitCode = err ? (Number.isInteger(err.code) ? err.code : null) : 0;
      const finish = (cleanup) => {
        if (released) return;
        released = true;
        running--;
        if (err?.killed) output = `${output}\n[Timeout: ${TIMEOUT_MS / 1000} s]`.trim();
        if (err && !output) output = `Sandbox hatası: ${String(err.message || 'bilinmeyen hata').slice(0, 200)}`;
        output ||= '(no output)';
        const finishedAt = new Date().toISOString();
        const proof = receipt({ id, command: cmd, output, startedAt, finishedAt, exitCode, decision: 'allow', cleanup });
        emit(proof);
        resolve(output);
      };
      const verifyAbsent = () => {
        execFile('docker', ['inspect', id], { timeout: 5000, windowsHide: true }, (inspectErr, _out, inspectErrText) => {
          if (inspectErr) {
            const detail = `${inspectErrText || ''} ${inspectErr.message || ''}`.toLowerCase();
            return finish(detail.includes('no such object') || detail.includes('no such container') ? 'confirmed-absent' : 'cleanup-unconfirmed');
          }
          execFile('docker', ['rm', '-f', id], { timeout: 5000, windowsHide: true }, (rmErr) => {
            if (rmErr) return finish('cleanup-unconfirmed');
            execFile('docker', ['inspect', id], { timeout: 5000, windowsHide: true }, (afterErr, _afterOut, afterErrText) => {
              const detail = `${afterErrText || ''} ${afterErr?.message || ''}`.toLowerCase();
              finish(afterErr && (detail.includes('no such object') || detail.includes('no such container')) ? 'confirmed-absent' : 'cleanup-unconfirmed');
            });
          });
        });
      };
      if (err?.killed) {
        execFile('docker', ['rm', '-f', id], { timeout: 5000, windowsHide: true }, () => verifyAbsent());
      } else {
        // Verify --rm cleanup; if the container remains, remove and verify it again.
        verifyAbsent();
      }
    });
  });
}


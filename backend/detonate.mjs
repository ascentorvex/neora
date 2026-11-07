// Two-stage inspection of an untrusted npm package / GitHub repo.
//  1) FETCH container (network, install scripts OFF) downloads the code into a throwaway dir.
//  2) DETONATION container (NO network, read-only, caps dropped) runs install scripts + imports it with
//     a behavior hook and honeypot secrets. Both containers and the temp dir are destroyed afterwards.
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, chmod, rm, readdir, stat, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseWineOutput } from './wine-evidence.mjs';
import { validateTarget, classify, computeVerdict, buildReport, summaryForModel, evidenceHash, LABELS, clean, wineLabel } from './verdict.mjs';

const IMAGE = process.env.SANDBOX_NODE_IMAGE || 'node:22-alpine';
const DET_IMAGE = process.env.SANDBOX_DET_IMAGE || 'neora-det:1'; // node + python3 + sh (probe/Dockerfile)
const RUNTIME = /^[a-z0-9_-]{2,20}$/.test(process.env.SANDBOX_RUNTIME || '') ? ['--runtime', process.env.SANDBOX_RUNTIME] : []; // e.g. runsc (gVisor)
const BACKEND = fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, '');
// Time limits are OFF by default (0 = unlimited). To bring one back, set the env var in .env (milliseconds):
//   NEORA_FETCH_MS      download step          NEORA_DETONATE_MS   whole detonation container
//   NEORA_BUDGET_MS     total script run time inside the container   NEORA_RUN_MS   per-script limit
const ms0 = (v) => { const n = Number(v); return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0; };
const FETCH_MS = ms0(process.env.NEORA_FETCH_MS), DETONATE_MS = ms0(process.env.NEORA_DETONATE_MS);
const BUDGET_MS = ms0(process.env.NEORA_BUDGET_MS), RUN_MS = ms0(process.env.NEORA_RUN_MS);
// Optional Windows application runtime. The image is built and validated separately.
const WINE_IMAGE_RAW = process.env.NEORA_WINE_IMAGE || 'neora-wine:1';
const WINE_IMAGE = /^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,200}$/.test(WINE_IMAGE_RAW) ? WINE_IMAGE_RAW : 'neora-wine:1';
// Wine runs get a fixed OBSERVATION WINDOW: most programs never exit by themselves, so reaching the end of the window is
// normal (reported as a low note), not a failure. NEORA_WINE_MS is only the outer host watchdog for the whole container.
const WINE_RUN_S = Math.min(600, Math.max(5, Math.floor(Number(process.env.NEORA_WINE_RUN_S)) || 30));
const WINE_MS = ms0(process.env.NEORA_WINE_MS) || (WINE_RUN_S + 90) * 1000;
const WINE_EXT = /\.(?:exe|scr|com|pif)$/i;

const MAX_BYTES = 150 * 1024 * 1024;
let busy = false;

const docker = (args, ms, name) => new Promise((resolve) => {
  const p = execFile('docker', args, { timeout: ms, maxBuffer: 3 * 1024 * 1024, killSignal: 'SIGKILL' }, (err, stdout, stderr) => {
    const killed = !!(err && (err.killed || err.signal));
    const done = () => resolve({ code: err ? (typeof err.code === 'number' ? err.code : -1) : 0, killed, stdout: String(stdout || ''), stderr: String(stderr || '') });
    killed && name ? execFile('docker', ['rm', '-f', name], () => done()) : done();
  });
  p.on('error', () => {});
});
const gone = async (name) => {
  const r = await docker(['ps', '-a', '-q', '--filter', `name=^/${name}$`], 8000);
  if (r.stdout.trim()) { await docker(['rm', '-f', name], 8000); return !(await docker(['ps', '-a', '-q', '--filter', `name=^/${name}$`], 8000)).stdout.trim(); }
  return true;
};
async function dirSize(d, acc = { n: 0 }) {
  for (const e of await readdir(d, { withFileTypes: true }).catch(() => [])) {
    const p = join(d, e.name);
    if (e.isDirectory()) { await dirSize(p, acc); } else if (e.isFile()) acc.n += (await stat(p).catch(() => ({ size: 0 }))).size;
    if (acc.n > MAX_BYTES) break;
  }
  return acc.n;
}
const HARDEN = ['--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '65534:65534'];

// Run only supported top-level Windows applications. DLLs, drivers, MSI installers,
// and archive members remain static-only. The sample is mounted read-only.
// The in-container script (wine/neora-wine-run) copies a fresh prefix, runs the sample under Wine for WINE_RUN_S seconds
// (strace + registry/file diff) and prints evidence sections that wine-evidence.mjs turns into events.
async function runWineFile(sampleDir, samplePath, containerName) {
  const sampleName = basename(samplePath);
  const what = `wine:run:${sampleName}`;
  const image = await docker(['image', 'inspect', WINE_IMAGE], 8000);
  if (image.code !== 0) {
    return { what, code: null, missing: true, started: false, timedOut: false, hostKilled: false, ms: 0, events: [],
      output: 'Wine image is not available locally; refusing to pull an image automatically.' };
  }
  const nonce = randomBytes(8).toString('hex');
  const args = [
    'run', '--rm', '--name', containerName,
    '--network', 'none', '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--user', '65534:65534',
    '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=2g,mode=1777',
    '--memory', '3g', '--memory-swap', '3g', '--cpus', '1', '--pids-limit', '512',
    '--ulimit', 'nofile=1024',   // per-file size limit is applied inside neora-wine-run AFTER the prefix copy
    '-v', `${sampleDir}:/work:ro`,
    '-e', `NEORA_SAMPLE=${sampleName}`, '-e', `NEORA_NONCE=${nonce}`, '-e', `NEORA_WINE_RUN_S=${WINE_RUN_S}`,
    '-w', '/tmp', WINE_IMAGE, 'neora-wine-run',
  ];
  const startedAt = Date.now();
  const r = await docker(args, WINE_MS, containerName);
  const daemonFailure = /Error response from daemon|OCI runtime create failed|failed to create shim task|invalid mount config/i.test(r.stderr);
  const parsed = parseWineOutput(r.stdout, nonce, what, sampleName);
  const started = !daemonFailure && !!parsed.meta;
  if (!started) console.error('WINE-FAIL', what, 'daemon:', daemonFailure, 'script:', parsed.failure, '|', clean(`${r.stdout}\n${r.stderr}`, 500));
  return {
    what,
    code: parsed.meta?.exit ?? null,
    missing: false,
    started,
    timedOut: !!parsed.meta && parsed.meta.ended === 'window', // observation window ended while still running (informational)
    hostKilled: r.killed,                                          // host watchdog had to kill the container (real failure)
    ms: Date.now() - startedAt,
    events: parsed.events,
    output: '',
  };
}


export async function inspectTarget(kind, target, { lang = 'en' } = {}) {
  lang = lang === 'tr' ? 'tr' : 'en';
  const v = validateTarget(kind, target);
  if (!v.ok) return { summary: `Inspection refused: ${v.reason}` };
  if (busy) return { summary: 'The inspection sandbox is busy with another request. Ask the user to retry in about a minute.' };
  busy = true;
  const t0 = Date.now(), id = randomBytes(4).toString('hex');
  const nf = `neora-fetch-${id}`, nd = `neora-det-${id}`;
  let tmp = null, incompleteReason = '', staticNote = '', raw = null;
  try {
    tmp = await mkdtemp(join(tmpdir(), 'neora-inspect-'));
    const out = join(tmp, 'out');
    await mkdir(out); await chmod(out, 0o777);

    // ---- 1) fetch (network allowed, scripts disabled) ----
    const base = ['run', '--rm', '--name', nf, ...HARDEN, '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=400m,mode=1777',
      '--pids-limit', '256', '--memory', '768m', '--memory-swap', '768m', '--cpus', '1',
      '-e', 'HOME=/tmp', '-e', 'npm_config_cache=/tmp/.npm', '-e', 'npm_config_update_notifier=false',
      '-v', `${out}:/out:rw`, '-v', `${BACKEND}/probe:/probe:ro`, '-w', '/tmp'];
    const NPM = 'npm install --ignore-scripts --no-audit --no-fund --omit=optional --registry=https://registry.npmjs.org/';
    let fetchArgs;
    if (v.kind === 'npm') {
      fetchArgs = [...base, '-e', `SPEC=${v.spec}`, IMAGE, 'sh', '-c', `mkdir -p /out/proj && cd /out/proj && npm init -y >/dev/null 2>&1 && ${NPM} -- "$SPEC"`];
    } else if (v.kind === 'pip') {
      fetchArgs = [...base, '-e', `PKG=${v.name}`, '-e', `PKG_VER=${v.version}`, IMAGE, 'sh', '-c', 'mkdir -p /out/proj && node /probe/fetch-pypi.cjs && f=$(cat /tmp/p.name) && case "$f" in *.whl|*.zip) unzip -q /tmp/p.dat -d /out/proj ;; *) tar -xzf /tmp/p.dat --strip-components=1 -C /out/proj ;; esac'];
    } else if (v.kind === 'github') {
      fetchArgs = [...base, '-e', `GH_TARBALL=${v.url}`, IMAGE, 'sh', '-c', `mkdir -p /out/proj && node /probe/fetch-gh.cjs && tar -xzf /tmp/r.tgz --strip-components=1 -C /out/proj && cd /out/proj && { [ ! -f package.json ] || ${NPM}; true; }`];
    }
    const proj = join(out, 'proj');
    const targetRel = v.kind === 'npm' ? `node_modules/${v.name}` : '.';
    let f = { killed: false, stderr: '' };
    if (v.kind === 'command') await mkdir(proj);
    else f = await docker(fetchArgs, FETCH_MS, nf);
    const okFetch = !f.killed && await access(join(proj, targetRel)).then(() => true, () => false);
    if (!okFetch) {
      incompleteReason = f.killed ? 'Download step timed out.' : `Could not fetch the target (${clean(f.stderr.split('\n').filter(Boolean).pop() || 'not found', 120)}).`;
    } else if ((await dirSize(proj)) > MAX_BYTES) {
      incompleteReason = 'Target is too large to inspect safely (over 150 MB).';
    } else {
      // ---- 2) detonate (no network, read-only) ----
      const det = ['run', '--rm', '--name', nd, '--network', 'none', ...RUNTIME, ...HARDEN,
        '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=64m,mode=1777',
        '--pids-limit', '128', '--memory', '256m', '--memory-swap', '256m', '--cpus', '0.5',
        '--ulimit', 'nofile=256', '--ulimit', 'fsize=20000000',
        '-v', `${proj}:/work:ro`, '-v', `${BACKEND}/probe:/probe:ro`,
        '-e', `NEORA_TARGET=${targetRel}`, '-e', `NEORA_KIND=${v.kind}`, '-e', `NEORA_BUDGET_MS=${BUDGET_MS}`, '-e', `NEORA_RUN_MS=${RUN_MS}`, ...(v.kind === 'command' ? ['-e', `NEORA_CMD=${v.cmd}`] : []), '-w', '/work',
        DET_IMAGE, 'node', '/probe/run.cjs'];
      const r = await docker(det, DETONATE_MS, nd);
      try { raw = JSON.parse(r.stdout.trim().split('\n').pop()); } catch {}
      if (!raw) incompleteReason = r.killed ? 'Detonation step timed out.' : /No such image|Unable to find image/i.test(r.stderr) ? 'Detonation image missing: run deploy/deploy.sh to build it.' : 'Detonation produced no readable evidence.';
      else if (!raw.static?.runnable) {
        // Nothing can be executed here (Windows .exe/.dll, Java, C, PowerShell ...). Content was still READ and scored;
        // the user is told explicitly that nothing ran. Only a target with nothing readable stays "incomplete".
        const sc = raw.static?.scan || {};
        if (!((sc.text || 0) + (sc.binary || 0) + (sc.members || 0))) incompleteReason = 'Nothing readable or runnable was found in the target.';
        else staticNote = 'Nothing could be executed in this Linux sandbox (no Node, Python or shell entry points; Windows executables, Java and other languages are not run here). The contents were read and scored statically instead: source and scripts, strings inside binaries, archive members. This is NOT a runtime safety verdict.';
      }
      else if (raw.budgetExceeded) incompleteReason = 'Time budget ran out; some scripts were skipped.';
    }
  } catch (e) {
    incompleteReason = 'Inspection error: ' + clean(e.message, 120);
  } finally {
    if (tmp) await rm(tmp, { recursive: true, force: true }).catch(() => {});
    busy = false;
  }
  const destroyed = (await gone(nf)) && (await gone(nd));
  const st = raw?.static || {};
  const events = raw?.dynamic?.events || [];
  const runs = raw?.dynamic?.runs || [];
  const findings = classify({ static: st, events, runs, kind: v.kind, name: v.name });
  const nothingRan = !!raw && !st.runnable;
  const unread = (st.archivesSkipped || []).length;
  const notRun = Object.values(st.notRun || {}).reduce((a, b) => a + b, 0) + unread;
  const verdict = computeVerdict(findings, !!incompleteReason || !raw, { nothingRan, notRun: notRun > 0 });
  const ms = Date.now() - t0;
  const receipt = {
    'fetch container': `${nf} ${destroyed ? 'destroyed' : 'CLEANUP FAILED'}`,
    'detonation container': `${nd} ${destroyed ? 'destroyed' : 'CLEANUP FAILED'}`,
    'temp files': 'wiped',
    'detonation network': 'none',
    'evidence sha256': evidenceHash(findings, st).slice(0, 24),
    duration: `${Math.round(ms / 1000)} s`,
    at: new Date().toISOString(),
  };
  console.log('INSPECT', v.label, verdict.level, verdict.score, ms + 'ms');
  const slug = String(v.label).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'target';
  const md = buildReport({ label: v.label, kind: v.kind, lang, verdict, findings, st, runs, events, receipt }) + (incompleteReason ? `\n\n> ${incompleteReason}\n` : '') + (staticNote ? `\n\n> ${staticNote}\n` : '');
  return {
    summary: summaryForModel({ label: v.label, lang, verdict, findings, incompleteReason: incompleteReason || staticNote }),
    report: { name: `neora-inspection-${slug}.md`, content: md },
    vlog: { target: clean(v.label, 80), kind: v.kind, level: verdict.level, label: LABELS[lang][verdict.level], score: verdict.score, n: verdict.n, mode: verdict.mode, ok: destroyed, ms },
  };
}


// Inspect one uploaded file. The existing probe performs static analysis and only
// executes supported script/package entry points inside a fresh, offline container.
// Windows PE files (.exe/.dll) are deliberately NOT executed in this Linux image.
export async function inspectUploadedFile(upload, { lang = 'en' } = {}) {
  lang = lang === 'tr' ? 'tr' : 'en';
  if (busy) return { summary: lang === 'tr'
    ? 'İnceleme sandbox alanı başka bir istek tarafından kullanılıyor. Lütfen yaklaşık bir dakika sonra tekrar deneyin.'
    : 'The inspection sandbox is busy with another request. Ask the user to retry in about a minute.' };
  busy = true;
  const t0 = Date.now();
  const id = randomBytes(6).toString('hex');
  const nd = `neora-file-${id}`;
  const nw = `neora-wine-${id}`;
  let tmp = null, raw = null, wineRun = null, incompleteReason = '';
  const label = clean(upload?.name || 'uploaded-file', 100);
  const isWineTarget = WINE_EXT.test(label);
  try {
    tmp = await mkdtemp(join(tmpdir(), 'neora-file-'));
    const sample = join(tmp, label.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 100) || 'sample.bin');
    const { copyFile } = await import('node:fs/promises');
    await copyFile(upload.path, sample);
    await chmod(sample, 0o644);
    await chmod(tmp, 0o755);
    const args = ['run', '--rm', '--name', nd, '--network', 'none', ...RUNTIME, ...HARDEN,
      '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=64m,mode=1777',
      '--pids-limit', '96', '--memory', '256m', '--memory-swap', '256m', '--cpus', '0.5',
      '--ulimit', 'nofile=256', '--ulimit', 'fsize=20000000',
      '-v', `${tmp}:/work:ro`, '-v', `${BACKEND}/probe:/probe:ro`,
      '-e', 'NEORA_TARGET=.', '-e', 'NEORA_KIND=file',
      '-e', `NEORA_BUDGET_MS=${BUDGET_MS || 45000}`, '-e', `NEORA_RUN_MS=${RUN_MS || 10000}`,
      '-w', '/work', DET_IMAGE, 'node', '/probe/run.cjs'];
    const r = await docker(args, DETONATE_MS || 60000, nd);
    try { raw = JSON.parse(r.stdout.trim().split('\n').pop()); } catch {}

    if (!raw) {
      incompleteReason = r.killed ? 'Dosya analizi zaman aşımına uğradı.' :
        /No such image|Unable to find image/i.test(r.stderr) ? 'Sandbox imajı bulunamadı; probe Docker imajını oluşturup tekrar deneyin.' :
        'Sandbox okunabilir analiz kanıtı üretemedi.';
    } else if (!raw.static?.runnable && !isWineTarget &&
      !((raw.static?.scan?.text || 0) + (raw.static?.scan?.binary || 0) + (raw.static?.scan?.members || 0))) {
      incompleteReason = 'Dosyada okunabilir statik içerik bulunamadı.';
    }

    // Static analysis remains first. Only top-level EXE/SCR/COM/PIF files are
    // additionally launched in a separate, offline, constrained Wine container.
    if (isWineTarget) {
      wineRun = await runWineFile(tmp, sample, nw);
      if (wineRun.missing) {
        incompleteReason = incompleteReason || (lang === 'tr'
          ? `Wine imajı bulunamadı (${WINE_IMAGE}). İmajı sunucuda önceden yükleyin.`
          : `Wine image not found (${WINE_IMAGE}). Load the image on the server first.`);
      } else if (wineRun.hostKilled) {
        incompleteReason = incompleteReason || (lang === 'tr'
          ? 'Wine çalıştırması beklenmedik şekilde takıldı ve sunucu tarafından durduruldu.'
          : 'Wine execution hung and was terminated by the host watchdog.');
      } else if (!wineRun.started) {
        incompleteReason = incompleteReason || (lang === 'tr'
          ? 'Wine konteyneri başlatılamadı; statik analiz sonucu korunuyor.'
          : 'Wine container could not be started; static analysis is retained.');
      }

      if (wineRun.started) {
        if (raw?.static?.notRun) {
          const ext = label.toLowerCase().split('.').pop();
          if (raw.static.notRun[ext] > 0) raw.static.notRun[ext]--;
          if (!raw.static.notRun[ext]) delete raw.static.notRun[ext];
        }
        raw = raw || { static: {}, dynamic: { runs: [], events: [] } };
        raw.dynamic = raw.dynamic || { runs: [], events: [] };
        raw.dynamic.events = raw.dynamic.events || [];
        raw.dynamic.runs = raw.dynamic.runs || [];
        raw.dynamic.events.push(...wineRun.events);
        raw.dynamic.runs.push({ ...wineRun, events: undefined, output: undefined });
      } else if (raw && !raw.static?.runnable) {
        incompleteReason = incompleteReason || (lang === 'tr'
          ? 'Windows dosyası Wine ile çalıştırılamadı; bu rapor statik analizle sınırlıdır.'
          : 'The Windows file was not run in Wine; this report is limited to static analysis.');
      }
    }
  } catch (e) {
    incompleteReason = (lang === 'tr' ? 'Dosya analizi hatası: ' : 'File inspection error: ') + clean(e.message, 120);
  } finally {
    if (tmp) await rm(tmp, { recursive: true, force: true }).catch(() => {});
    busy = false;
  }

  const detonationDestroyed = await gone(nd);
  const wineDestroyed = await gone(nw);
  const destroyed = detonationDestroyed && wineDestroyed;
  const st = raw?.static || {};
  const events = raw?.dynamic?.events || [];
  const runs = raw?.dynamic?.runs || [];
  const findings = classify({ static: st, events, runs, kind: 'file', name: label });
  const wineStarted = !!wineRun?.started;
  const nothingRan = !!raw && !st.runnable && !wineStarted;
  const unread = (st.archivesSkipped || []).length;
  const notRun = Object.values(st.notRun || {}).reduce((a, b) => a + b, 0) + unread;
  // Wine output/exit status is not full Windows API instrumentation, so a Wine
  // execution is always reported as partial coverage, never as a clean verdict.
  const verdict = computeVerdict(findings, !!incompleteReason || !raw, {
    nothingRan,
    notRun: notRun > 0 || wineStarted,
  });
  const ms = Date.now() - t0;
  const receipt = {
    'uploaded file': label,
    'detonation container': `${nd} ${detonationDestroyed ? 'destroyed' : 'CLEANUP FAILED'}`,
    ...(wineRun ? {
      'Wine container': `${nw} ${wineDestroyed ? 'destroyed' : 'CLEANUP FAILED'}`,
      'Wine result': wineRun.missing ? 'image missing' : wineRun.timedOut ? 'timed out' :
        !wineRun.started ? 'container did not start' : `exit ${wineRun.code}`,
    } : {}),
    'temporary copy': 'wiped',
    'detonation network': 'none',
    'Wine network': wineRun ? 'none' : 'not used',
    'evidence sha256': evidenceHash(findings, st).slice(0, 24),
    duration: `${Math.round(ms / 1000)} s`,
    at: new Date().toISOString(),
  };
  const md = buildReport({ label, kind: 'file', lang, verdict, findings, st, runs, events, receipt }) +
    (incompleteReason ? `\n\n> ${incompleteReason}\n` : '') +
    (wineStarted ? (lang === 'tr'
      ? '\n\n> Wine ile süreç başlatıldı; bu, Windows VM seviyesinde API/registry/dosya sistemi izleme değildir. Bu nedenle sonuç kısmi kapsam olarak raporlanır.\n'
      : '\n\n> A process was launched with Wine; this is not Windows-VM-level API/registry/filesystem instrumentation. Coverage is therefore reported as partial.\n') : '');
  return {
    summary: summaryForModel({ label, lang, verdict, findings, incompleteReason, wineRan: wineStarted }),
    report: { name: `neora-file-inspection-${id}.md`, content: md, inspection: true },
    vlog: { target: label, kind: 'file', level: verdict.level, label: (wineStarted && !findings.some((f) => f.id === 'not_executed' || f.id === 'containers_unopened')) ? wineLabel(LABELS[lang][verdict.level], lang) : LABELS[lang][verdict.level], score: verdict.score, n: verdict.n, mode: verdict.mode, ok: destroyed, ms },
  };
}


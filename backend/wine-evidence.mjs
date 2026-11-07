// Turns the text printed by wine/neora-wine-run into evidence events for classify() in verdict.mjs.
// Everything here is DATA parsing: the sample controls some of these strings, so nothing is executed or trusted.
import { clean } from './verdict.mjs';

const LOOPBACK = /^(?:127\.|0\.0\.0\.0$|::1?$|::ffff:127\.)/;
const WINE_INTERNAL = /\\+(?:services|winedevice|plugplay|explorer|rpcss|svchost|conhost|wineboot|winemenubuilder|mscorsvw|tabtip)\.exe/i;
const NOISE_KEY = /^System\\CurrentControlSet\\(?:Control\\(?:ComputerName|DeviceClasses)|Services\\Tcpip)|^Volatile Environment|\\CurrentVersion\\Fonts$/i;
const PERSIST_KEY = /\\(?:Run|RunOnce|RunServices|RunServicesOnce)$|\\Winlogon$|Image File Execution Options|\\Windows\\(?:Load|Run)$/i;

export function splitSections(stdout, nonce) {
  const marker = `@@NEORA:${nonce} `;
  const sections = {}; let cur = null;
  for (const line of String(stdout || '').split('\n')) {
    if (line.startsWith(marker)) {
      const head = line.slice(marker.length).trim();
      cur = head.split(' ')[0];
      sections[cur] = { head, lines: [] };
    } else if (cur && cur !== 'END') sections[cur].lines.push(line);
  }
  return sections;
}

function parseMeta(head) {
  const m = {};
  for (const kv of head.split(' ').slice(1)) { const i = kv.indexOf('='); if (i > 0) m[kv.slice(0, i)] = kv.slice(i + 1); }
  const exit = m.exit === '' || m.exit === undefined ? null : Number(m.exit);
  return { wine: m.wine || 'unknown', exit: Number.isFinite(exit) ? exit : null, ended: m.ended === 'exited' ? 'exited' : 'window', runS: Number(m.run_s) || 0, trace: m.trace === '1', arch: m.arch || 'unknown' };
}

// grep -n prefixes each trace line with its line number ("123:<pid>  syscall(...)"); the order tells infra from sample.
const lineNo = (l) => { const m = l.match(/^(\d+):/); return m ? Number(m[1]) : 0; };

function sampleStart(lines, sampleName) {
  const has = (m) => m && m[2].includes(`sample\\\\${sampleName}`);
  const re = /execve\("([^"]*)",\s*\[(.*?)\],\s/;
  let loader32 = false, infra = 0;
  for (const l of lines) {
    const m = l.match(re);
    if (!m) continue;
    // 64-bit sample: first wine64 exec that names it (Wine's own startup is all before this line)
    if (/(?:^|\/)wine64(?:-preloader)?$/.test(m[1]) && has(m)) return lineNo(l);
    if (/(?:^|\/)wine(?:-preloader)?$/.test(m[1]) && has(m) && !/\/bin\/wine$/.test(m[1])) loader32 = true;
    if (WINE_INTERNAL.test(m[2])) infra = Math.max(infra, lineNo(l));
  }
  // 32-bit sample: it runs inside the 32-bit loader, which starts BEFORE wineboot, so there is no later exec to anchor on.
  // Everything up to the last Wine-internal process (wineboot/services/winedevice/svchost) is infrastructure.
  return loader32 ? infra : 0;
}

function netEvents(lines, ph, startLine = 0) {
  const seen = new Set(), out = [];
  for (const l of lines) {
    if (lineNo(l) < startLine) continue; // Wine's own startup (wineboot) probes DNS before the sample starts

    const call = (l.match(/\b(connect|sendto|bind)\(/) || [])[1];
    if (!call || call === 'bind') continue;
    const ip = (l.match(/inet_addr\("([^"]+)"\)/) || l.match(/inet_pton\(AF_INET6,\s*"([^"]+)"/) || [])[1];
    const port = (l.match(/sin6?_port=htons\((\d+)\)/) || [])[1];
    if (!ip || LOOPBACK.test(ip)) continue;
    const key = `${ip}:${port}`;
    if (seen.has(key) || out.length >= 20) continue;
    seen.add(key);
    out.push({ t: port === '53' ? 'dns.lookup' : 'net.connect', ph, d: `${ip}:${port ?? '?'}` });
  }
  return out;
}

function execEvents(lines, ph, sampleName) {
  const out = [], seen = new Set();
  for (const l of lines) {
    const m = l.match(/execve\("([^"]*)",\s*\[(.*?)\],\s/);
    if (!m) continue;
    const argv = [...m[2].matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((x) => x[1]);
    const exe = m[1];
    if (/(?:wineserver(?:64)?|Xvfb|strace)$/.test(exe)) continue;
    const isLoader = /(?:^|\/)wine(?:64)?(?:-preloader)?$/.test(exe);
    const cmd = (isLoader ? argv.slice(1) : [exe, ...argv.slice(1)]).join(' ');
    if (!cmd || WINE_INTERNAL.test(cmd)) continue;
    if (isLoader && !/\.exe|\.bat|\.cmd|\.com|\.scr|cmd|powershell/i.test(cmd)) continue;
    if (cmd.includes(`\\\\sample\\\\${sampleName}`) || cmd.includes(`\\sample\\${sampleName}`)) continue; // the launch itself
    if (seen.has(cmd) || out.length >= 25) continue;
    seen.add(cmd);
    out.push({ t: 'proc.spawn', ph, d: cmd });
  }
  return out;
}

function regEvents(lines, ph) {
  const out = []; let key = '';
  for (const l of lines) {
    const h = l.match(/^\[(.+)\]\s+\d+/);
    if (h) { key = h[1].replace(/\\\\/g, '\\'); continue; }
    if (!key || !l.startsWith('"') && !l.startsWith('@')) continue;
    if (/^Software\\Wine\\/i.test(key) || NOISE_KEY.test(key)) continue;
    const persist = PERSIST_KEY.test(key);
    if (out.length < 25) out.push({ t: persist ? 'fs.persist' : 'reg.write', ph, d: `registry ${key}: ${l.slice(0, 140)}` });
  }
  return out;
}

function fileEvents(lines, ph) {
  const out = [];
  for (const l of lines) {
    const p = l.replace(/^>\s*/, '').replace(/^\.\//, '');
    if (!p || out.length >= 25) continue;
    const persist = /Start Menu\/Programs\/Startup\//i.test(p);
    out.push({ t: persist ? 'fs.persist' : 'fs.write', ph, d: `C:/${p}` });
  }
  return out;
}

export function parseWineOutput(stdout, nonce, what, sampleName = '') {
  const s = splitSections(stdout, nonce);
  if (!s.META) return { meta: null, events: [], complete: false, failure: s.FAIL ? clean(s.FAIL.lines.join(' '), 160) : '' };
  const meta = parseMeta(s.META.head), L = (n) => (s[n]?.lines || []).filter(Boolean);
  const start = sampleStart(L('EXEC'), sampleName);
  const events = [...netEvents(L('NET'), what, start), ...execEvents(L('EXEC'), what, sampleName), ...regEvents(L('REG'), what), ...fileEvents(L('FILES'), what)];
  const tail = clean([...L('STDOUT'), ...L('STDERR')].join(' '), 300);
  if (tail) events.push({ t: 'wine.output', ph: what, d: tail });
  return { meta, events, complete: !!s.END, failure: '' };
}

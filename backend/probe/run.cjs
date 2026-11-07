'use strict';
// Runs INSIDE the one-time detonation container (no network, read-only, all caps dropped).
//  1) static scan of source files and of strings inside binaries
//  2) executes many entry points (npm lifecycle scripts/bin/import, python setup.py/imports/scripts, shell scripts,
//     or a pasted command) with behavior hooks and honeypot secrets
//  3) prints one JSON document with the evidence.
const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const SCRATCH = process.env.NEORA_SCRATCH || '/tmp';
const WORK = process.env.NEORA_WORK || '/work';
const TARGET = process.env.NEORA_TARGET || '.';
const KIND = process.env.NEORA_KIND || '';
const CMD = process.env.NEORA_CMD || '';
// 0 / unset = no limit (the host decides). NEORA_BUDGET_MS = total run time, NEORA_RUN_MS = per script.
const BUDGET = Number(process.env.NEORA_BUDGET_MS) > 0 ? Number(process.env.NEORA_BUDGET_MS) : Infinity;
const RUN_MS = Number(process.env.NEORA_RUN_MS) > 0 ? Number(process.env.NEORA_RUN_MS) : 0;
const START = Date.now();
const HOME = path.join(SCRATCH, 'home');
const EV = path.join(SCRATCH, 'ev', 'events.jsonl');
const BIN = path.join(SCRATCH, 'bin');
const HOOK = path.join(__dirname, 'hook.cjs');
const PYDIR = path.join(__dirname, 'py');
const rules = require('./rules.cjs');
const tdir = path.resolve(WORK, TARGET);

// ---------- honeypots + shims ----------
function mk(p, c, mode) { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, c, { mode: mode || 0o600 }); }
const HONEY = {
  '.ssh/id_rsa': '-----BEGIN OPENSSH PRIVATE KEY-----\nNEORA-CANARY-DO-NOT-USE\n-----END OPENSSH PRIVATE KEY-----\n',
  '.aws/credentials': '[default]\naws_access_key_id=AKIANEORACANARY00000\naws_secret_access_key=NEORACANARYSECRET\n',
  '.npmrc': '//registry.npmjs.org/:_authToken=npm_NEORACANARYTOKEN\n',
  '.git-credentials': 'https://neora:NEORACANARY@github.com\n',
  '.env': 'OPENAI_API_KEY=sk-NEORACANARY\n',
  '.kube/config': 'apiVersion: v1\nusers: [{name: neora-canary}]\n',
  '.docker/config.json': '{"auths":{"registry.example":{"auth":"TkVPUkFDQU5BUlk="}}}\n',
  '.config/solana/id.json': '[0,0,0,0,"NEORA-CANARY"]\n',
  '.ethereum/keystore/UTC--neora-canary': '{"address":"0000000000000000000000000000000000000000"}\n',
  '.config/google-chrome/Default/Login Data': 'NEORA-CANARY\n',
  '.bash_history': 'ssh deploy@example.com\n',
};
for (const [p, c] of Object.entries(HONEY)) mk(path.join(HOME, p), c);
fs.mkdirSync(path.dirname(EV), { recursive: true });
fs.writeFileSync(EV, '');
const SHIM = [
  '#!/bin/sh',
  'a=$(printf \'%s \' "$@" | tr -d \'"\\\\\\n\' | cut -c1-160)',
  'printf \'{"t":"proc.shim","d":"%s %s","ph":"%s"}\\n\' "$(basename "$0")" "$a" "$NEORA_PHASE" >> "$NEORA_EVENTS"',
  'exit 0', '',
].join('\n');
for (const n of ['curl', 'wget', 'nc', 'ncat', 'ssh', 'scp', 'sftp', 'telnet', 'git', 'certutil', 'powershell', 'sudo', 'apt', 'apt-get', 'apk', 'pip', 'pip3', 'npm', 'npx', 'yarn', 'docker', 'kubectl', 'crontab', 'systemctl', 'chmod', 'base64']) mk(path.join(BIN, n), SHIM, 0o755);

function envFor(phase, extra) {
  return Object.assign({
    PATH: BIN + ':/usr/local/bin:/usr/bin:/bin', HOME, USER: 'neora', CI: 'true', NODE_ENV: 'production',
    AWS_SECRET_ACCESS_KEY: 'NEORACANARYSECRET', AWS_ACCESS_KEY_ID: 'AKIANEORACANARY00000',
    GITHUB_TOKEN: 'ghp_NEORACANARYTOKEN', NPM_TOKEN: 'npm_NEORACANARYTOKEN', OPENAI_API_KEY: 'sk-NEORACANARY',
    NEORA_EVENTS: EV, NEORA_PHASE: phase, NODE_OPTIONS: '--require ' + HOOK,
    PYTHONPATH: [PYDIR, tdir, path.join(tdir, 'src')].join(':'), PYTHONDONTWRITEBYTECODE: '1', PYTHONUNBUFFERED: '1',
  }, extra || {});
}

// ---------- 1) static scan ----------
// Everything here is READ, never executed: source/script text, strings inside binaries (ASCII + UTF-16LE) and the
// members of archives (read in memory by probe/archive.py). What this Linux container cannot run (Windows .exe/.dll,
// Java, Android, macOS, PowerShell, PHP, C ...) is recorded in st.notRun so the verdict can tell the user that the
// content was read and scored statically but NOT executed.
const st = {
  files: 0, scannedBytes: 0, truncated: false, lifecycle: [], rules: {}, natives: [], nativeScanned: 0, winExec: 0,
  langs: [], runnable: false,
  scan: { text: 0, binary: 0, archive: 0, members: 0 },   // how much was read statically
  notRun: {},        // ext -> count: present but not executable here
  flags: [],         // structural findings: double extension, disguised binary, packed PE, encrypted archive ...
  pe: [],            // light PE header facts
  archivesSkipped: [], // containers we could not open (7z, rar, iso, nested ...)
};
// Text-like files that are read and pattern-matched (source, scripts, configs, installers, web, Office/Android XML ...).
const EXT = new RegExp('\\.(?:' + [
  'js', 'cjs', 'mjs', 'jsx', 'ts', 'tsx', 'mts', 'cts', 'json', 'jsonc', 'coffee', 'vue', 'svelte',
  'sh', 'bash', 'zsh', 'ksh', 'fish', 'command', 'ps1', 'psm1', 'psd1', 'bat', 'cmd', 'vbs', 'vbe', 'jse', 'wsf', 'wsh', 'sct', 'hta', 'reg', 'inf', 'url',
  'py', 'pyw', 'pyi', 'ipynb', 'rb', 'rake', 'gemspec', 'php', 'phtml', 'php5', 'asp', 'aspx', 'ashx', 'asmx', 'jsp', 'jspx', 'cfm',
  'pl', 'pm', 'lua', 'go', 'rs', 'c', 'cc', 'cpp', 'cxx', 'h', 'hh', 'hpp', 'hxx', 'cs', 'csx', 'vb', 'bas', 'vba', 'java', 'kt', 'kts', 'scala', 'groovy', 'gradle',
  'swift', 'm', 'mm', 'dart', 'r', 'jl', 'nim', 'zig', 'ex', 'exs', 'erl', 'hs', 'clj', 'sql', 'asm', 's', 'ahk', 'au3', 'applescript',
  'yml', 'yaml', 'toml', 'cfg', 'ini', 'conf', 'properties', 'plist', 'xml', 'xsl', 'xslt', 'desktop', 'service', 'timer', 'html', 'htm', 'xhtml', 'mk', 'cmake', 'tf',
].join('|') + ')$|(?:^|\\/)(?:Makefile|Dockerfile|Jenkinsfile|Vagrantfile|Rakefile|Gemfile|Procfile|\\.bashrc|\\.bash_profile|\\.zshrc|\\.profile)$', 'i');
// Binary / compiled / document formats: we cannot run them, but we read the strings inside (ASCII + UTF-16LE).
const NATIVE = /\.(?:node|exe|dll|scr|sys|ocx|cpl|drv|ax|efi|com|pif|msi|msp|mst|so|dylib|bundle|a|o|lib|bin|elf|out|ko|class|dex|wasm|pyc|pyo|lnk|pdf|rtf|doc|dot|xls|xlt|ppt|pps)$/i;
// Archives we can open read-only (zip family + tar family + single compressed streams).
const ARCHIVE = /\.(?:zip|jar|war|ear|apk|aab|xapk|whl|nupkg|vsix|xpi|crx|egg|ipa|docx|docm|xlsx|xlsm|pptx|pptm|odt|ods|odp|epub|tar|tgz|gz|bz2|xz|tbz2|txz)$/i;
// Containers we cannot open here: only listed.
const OPAQUE = /\.(?:7z|rar|iso|img|cab|dmg|pkg|deb|rpm|appimage|vhd|vhdx|msix|appx)$/i;
// Extensions that should never be executables: PE/ELF/Mach-O magic behind them is a disguise.
const HARMLESS = /\.(?:txt|log|csv|jpe?g|png|gif|bmp|ico|webp|mp3|mp4|avi|mov|wav|dat|db|tmp|css|map|md|svg|woff2?|ttf|eot)$/i;
// Present but not runnable in this Linux/Node/Python/sh container.
const NOT_RUN = /\.(?:exe|dll|scr|sys|ocx|cpl|drv|ax|efi|com|pif|msi|msp|mst|so|dylib|bundle|bin|elf|out|ko|class|dex|wasm|lnk|jar|apk|aab|xapk|ipa|ps1|psm1|bat|cmd|vbs|vbe|jse|wsf|wsh|hta|go|rs|c|cc|cpp|cxx|cs|vb|bas|vba|java|kt|scala|groovy|swift|asm|ahk|au3|applescript|docm|xlsm|pptm|7z|rar|iso|cab|dmg|pkg|deb|rpm|appimage)$/i;
const WINEXT = /\.(?:exe|dll|scr|sys|msi|ocx|cpl|drv|ax|com|pif|msp|mst)$/i;
const DOUBLE_EXT = /\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp[34]|zip|rar)\s*\.(?:exe|scr|bat|cmd|com|pif|js|jse|vbs|vbe|wsf|hta|lnk|msi|ps1)$/i;
const MAX_FILES = 6000, MAX_BYTES = 16 * 1024 * 1024, MAX_NATIVE = 4 * 1024 * 1024, MAX_NATIVE_FILES = 40, MAX_NATIVE_BYTES = 48 * 1024 * 1024, MAX_ARCHIVES = 20;
const ARCHIVE_PY = path.join(__dirname, 'archive.py');
let magicReads = 0, nativeBytes = 0, archivesRead = 0;
function clean(s) { return String(s).replace(/[^\x20-\x7e]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 100); }
function flag(id, f, d) { if (st.flags.length < 40 && !st.flags.some((x) => x.id === id && x.f === f)) st.flags.push({ id, f: clean(f), d: clean(d || '') }); }
function noteNotRun(name) { const m = String(name).match(/\.([A-Za-z0-9]{1,8})$/); const k = m ? m[1].toLowerCase() : 'bin'; st.notRun[k] = (st.notRun[k] || 0) + 1; }
function walk(dir, depth) {
  if (depth > 10) return;
  let ents;
  try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of ents) {
    if (st.files >= MAX_FILES) { st.truncated = true; return; }
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, depth + 1);
    else if (e.isFile()) { st.files++; scanFile(p, e.name); }
  }
}
function applyRules(text, rel, isBinary) {
  for (const r of rules) {
    if (isBinary && r.textOnly) continue;
    const m = text.match(r.re);
    if (!m) continue;
    const slot = st.rules[r.id] || (st.rules[r.id] = { count: 0, samples: [] });
    slot.count++;
    if (slot.samples.length < 3) { const i = m.index || 0; slot.samples.push({ f: clean(rel), s: clean(text.slice(Math.max(0, i - 20), i + 70)) }); }
  }
}
// Printable ASCII runs and UTF-16LE runs (Windows binaries keep most strings in UTF-16), >= 6 chars, capped.
function extractStrings(buf, cap) {
  cap = cap || 3 * 1024 * 1024;
  const out = []; let total = 0;
  const push = (s) => { if (total < cap) { out.push(s); total += s.length + 1; } };
  let i = 0, start = -1;
  for (; i <= buf.length; i++) {
    const c = i < buf.length ? buf[i] : 0;
    if ((c >= 0x20 && c <= 0x7e) || c === 0x09) { if (start < 0) start = i; }
    else { if (start >= 0 && i - start >= 6) push(buf.toString('latin1', start, i)); start = -1; if (total >= cap) break; }
  }
  for (let par = 0; par < 2; par++) {
    let s = '';
    for (let j = par; j + 1 < buf.length; j += 2) {
      const c = buf[j];
      if (buf[j + 1] === 0 && ((c >= 0x20 && c <= 0x7e) || c === 0x09)) s += String.fromCharCode(c);
      else { if (s.length >= 6) push(s); s = ''; }
      if (total >= cap) break;
    }
    if (s.length >= 6) push(s);
  }
  return out.join('\n');
}
function entropy(b) {
  if (!b.length) return 0;
  const cnt = new Array(256).fill(0);
  for (let i = 0; i < b.length; i++) cnt[b[i]]++;
  let h = 0;
  for (const c of cnt) if (c) { const p = c / b.length; h -= p * Math.log2(p); }
  return h;
}
// Light PE header reader: DLL?, section names (packers), high-entropy sections, .NET assembly?
function peInfo(b) {
  try {
    if (b.length < 0x100 || b[0] !== 0x4d || b[1] !== 0x5a) return null;
    const o = b.readUInt32LE(0x3c);
    if (o < 0x40 || o + 24 > b.length || b.toString('latin1', o, o + 4) !== 'PE\0\0') return null;
    const ns = b.readUInt16LE(o + 6), opt = b.readUInt16LE(o + 20), ch = b.readUInt16LE(o + 22);
    const magic = b.readUInt16LE(o + 24), dd = o + 24 + (magic === 0x20b ? 112 : 96);
    const info = { dll: !!(ch & 0x2000), sections: [], packer: '', highEntropy: false, dotnet: false };
    if (dd + 15 * 8 <= b.length && b.readUInt32LE(dd + 14 * 8) !== 0) info.dotnet = true;
    const secs = o + 24 + opt;
    for (let i = 0; i < Math.min(ns, 40); i++) {
      const s = secs + i * 40;
      if (s + 40 > b.length) break;
      const nm = b.toString('latin1', s, s + 8).replace(/\0.*$/, '');
      info.sections.push(nm);
      if (!info.packer && /^(?:UPX\d|\.?aspack|\.?adata|\.?petite|\.?themida|\.?vmp\d|MPRESS\d|\.?enigma\d|\.?nsp\d|\.?yP$|\.?ndata)/i.test(nm)) info.packer = nm;
      const size = b.readUInt32LE(s + 16), ptr = b.readUInt32LE(s + 20);
      if (size >= 8192 && ptr > 0 && ptr < b.length && !/^\.(?:rsrc|reloc)$/.test(nm) && entropy(b.subarray(ptr, Math.min(b.length, ptr + Math.min(size, 262144)))) > 7.3) info.highEntropy = true;
    }
    return info;
  } catch { return null; }
}
function magicKind(b) {
  if (b.length < 4) return '';
  if (b[0] === 0x4d && b[1] === 0x5a) return 'pe';
  if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return 'elf';
  const m = b.readUInt32BE(0);
  if (m === 0xcffaedfe || m === 0xfeedface || m === 0xcefaedfe || m === 0xcafebabe) return 'macho';
  return '';
}
function headBytes(p, n) { try { const fd = fs.openSync(p, 'r'), b = Buffer.alloc(n), r = fs.readSync(fd, b, 0, n, 0); fs.closeSync(fd); return b.subarray(0, r); } catch { return Buffer.alloc(0); } }
function isBinaryMagic(p) {
  if (magicReads++ > 600) return false;
  return !!magicKind(headBytes(p, 4));
}
// Read a binary/document buffer: strings (ASCII + UTF-16) through the same rules as source code.
function scanBinaryBuffer(buf, rel, name) {
  const kind = magicKind(buf);
  if (kind === 'pe') {
    const pe = peInfo(buf);
    if (pe) {
      if (st.pe.length < 12) st.pe.push({ f: clean(rel), dll: pe.dll, dotnet: pe.dotnet, packer: pe.packer, highEntropy: pe.highEntropy, sections: pe.sections.slice(0, 8).map(clean).join(',') });
      if (pe.packer || pe.highEntropy) flag('packed_binary', rel, pe.packer ? 'packer section ' + pe.packer : 'high-entropy section (packed/encrypted)');
    }
  }
  if (/\.(?:vbe|jse)$/i.test(name)) flag('script_encoded', rel, 'Windows Script Encoder (.vbe/.jse)');
  applyRules(extractStrings(buf), rel, true);
  st.scan.binary++; st.nativeScanned++;
}
function readNative(p, size) {
  try {
    const fd = fs.openSync(p, 'r');
    const head = Buffer.alloc(Math.min(size, MAX_NATIVE)), n = fs.readSync(fd, head, 0, head.length, 0);
    let buf = head.subarray(0, n);
    if (size > MAX_NATIVE + 1) { // overlay / appended payloads live at the end
      const tail = Buffer.alloc(Math.min(size - MAX_NATIVE, 1024 * 1024)), m = fs.readSync(fd, tail, 0, tail.length, size - tail.length);
      buf = Buffer.concat([buf, tail.subarray(0, m)]);
    }
    fs.closeSync(fd);
    return buf;
  } catch { return null; }
}
function checkNameTricks(rel, name) {
  if (/[‮‭⁦-⁩]/.test(name)) flag('rlo_name', rel, 'Unicode direction override in file name');
  if (DOUBLE_EXT.test(name)) flag('double_ext', rel, name);
}
function scanArchive(p, rel) {
  if (archivesRead >= MAX_ARCHIVES) { st.archivesSkipped.push(clean(rel)); return; }
  archivesRead++;
  const r = cp.spawnSync('python3', ['-I', ARCHIVE_PY, p], { env: { PATH: '/usr/local/bin:/usr/bin:/bin' }, timeout: 25000, maxBuffer: 96 * 1024 * 1024, encoding: 'utf8', killSignal: 'SIGKILL', stdio: ['ignore', 'pipe', 'pipe'] });
  let a = null;
  try { a = JSON.parse(r.stdout); } catch {}
  if (!a || a.error) { st.archivesSkipped.push(clean(rel) + (a && a.error ? ' (' + a.error + ')' : '')); return; }
  st.scan.archive++;
  if (a.encrypted) flag('encrypted_archive', rel, 'password-protected members: contents hidden from the scan');
  if (a.skipped > 0) st.truncated = true;
  for (const m of a.members) {
    const mrel = rel + '!/' + m.n, mname = path.basename(m.n);
    st.scan.members++;
    checkNameTricks(mrel, mname);
    if (/(?:^|\/)vbaProject\.bin$/i.test(m.n)) flag('office_macro_file', mrel, 'VBA macro project inside document');
    if (/\.(?:class|dex)$/i.test(mname)) { /* counted below */ }
    if (m.b64 === null || m.b64 === undefined) continue;
    const buf = Buffer.from(m.b64, 'base64');
    if (ARCHIVE.test(mname) && !/\.(?:json|js)$/i.test(mname)) { st.archivesSkipped.push(clean(mrel) + ' (nested)'); noteNotRun(mname); continue; }
    if (WINEXT.test(mname)) st.winExec++;
    if (NOT_RUN.test(mname)) noteNotRun(mname);
    if (magicKind(buf) || NATIVE.test(mname)) {
      if (st.natives.length < 8) st.natives.push(clean(mrel));
      if (st.nativeScanned < MAX_NATIVE_FILES) scanBinaryBuffer(buf, mrel, mname);
    } else if (EXT.test(mname) && !/\.d\.ts$/.test(mname) && buf.length <= 800 * 1024 && st.scannedBytes + buf.length <= MAX_BYTES) {
      st.scannedBytes += buf.length; st.scan.text++;
      applyRules(buf.toString('utf8'), mrel, false);
    }
  }
}
function scanFile(p, name) {
  const rel = path.relative(WORK, p);
  checkNameTricks(rel, name);
  if (name === 'package.json') {
    try {
      const j = JSON.parse(fs.readFileSync(p, 'utf8'));
      const dir = path.dirname(p);
      const isTarget = path.resolve(dir) === tdir;
      for (const h of ['preinstall', 'install', 'postinstall'].concat(isTarget ? ['prepare'] : [])) {
        if (j.scripts && typeof j.scripts[h] === 'string') st.lifecycle.push({ pkg: clean(j.name || path.basename(dir)), hook: h, cmd: clean(j.scripts[h]), full: String(j.scripts[h]).slice(0, 2000), dir, isTarget });
      }
    } catch {}
  }
  if (OPAQUE.test(name)) { st.archivesSkipped.push(clean(rel)); noteNotRun(name); return; }
  if (ARCHIVE.test(name) && !/\.(?:json|js)$/i.test(name)) { if (NOT_RUN.test(name)) noteNotRun(name); scanArchive(p, rel); return; }
  const disguised = HARMLESS.test(name) && isBinaryMagic(p);
  const native = NATIVE.test(name) || disguised || (!/\./.test(name) && isBinaryMagic(p));
  if (native) {
    if (disguised) flag('disguised_binary', rel, 'executable code behind a harmless extension');
    if (st.natives.length < 8) st.natives.push(clean(rel));
    if (WINEXT.test(name)) st.winExec++;
    if (NOT_RUN.test(name) || disguised || !/\./.test(name)) noteNotRun(disguised || !/\./.test(name) ? 'bin' : name);
    try {
      const size = fs.statSync(p).size;
      if (size <= 128 * 1024 * 1024 && st.nativeScanned < MAX_NATIVE_FILES && nativeBytes + Math.min(size, MAX_NATIVE) <= MAX_NATIVE_BYTES) {
        const buf = readNative(p, size);
        if (buf) { nativeBytes += buf.length; scanBinaryBuffer(buf, rel, name); }
      } else st.truncated = true;
    } catch {}
    return;
  }
  if (!EXT.test(name) && !EXT.test('/' + name) || /\.d\.ts$/.test(name)) return;
  if (NOT_RUN.test(name)) noteNotRun(name);
  let size = 0;
  try { size = fs.statSync(p).size; } catch { return; }
  if (size > 800 * 1024 || st.scannedBytes + size > MAX_BYTES) { if (st.scannedBytes + size > MAX_BYTES) st.truncated = true; return; }
  let text;
  try { text = fs.readFileSync(p, 'utf8'); } catch { return; }
  st.scannedBytes += size; st.scan.text++;
  applyRules(text, rel, false);
}
if (KIND !== 'command') walk(WORK, 0);
else { applyRules(CMD, 'command', false); st.scan.text++; }

// ---------- 2) plan: execute many entry points ----------
const plan = [];
const add = (label, cmd, args, cwd, o) => { if (plan.length < 26) plan.push(Object.assign({ label, cmd, args, cwd }, o || {})); };
const has = (p) => { try { return fs.existsSync(p); } catch { return false; } };
const files = (d, re) => { try { return fs.readdirSync(d, { withFileTypes: true }).filter((e) => e.isFile() && re.test(e.name)).map((e) => e.name).sort(); } catch { return []; } };
const dirs = (d) => { try { return fs.readdirSync(d, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort(); } catch { return []; } };
const SKIP = /(?:^|[._-])(?:test|tests|spec|config|conf|webpack|rollup|babel|jest|eslint|gulpfile|gruntfile|karma|vite|tailwind|postcss|conftest|noxfile|tasks|setup)(?:[._-]|\.)/i;
const rel = (p) => path.relative(tdir, p) || '.';

if (KIND === 'command') {
  add('cmd', 'sh', ['-x', '-c', CMD], WORK, { trace: true });
  st.langs.push('shell');
} else {
  const ordered = st.lifecycle.slice().sort((a, b) => (b.isTarget ? 1 : 0) - (a.isTarget ? 1 : 0)).slice(0, 10);
  for (const l of ordered) add('install:' + l.pkg + ':' + l.hook, 'sh', ['-c', l.full], has(l.dir) ? l.dir : WORK);
  const pj = path.join(tdir, 'package.json');
  if (has(pj)) {
    st.langs.push('node');
    add('import:' + clean(path.basename(tdir)), process.execPath, ['-e', 'try{require(process.env.NEORA_PKGDIR)}catch(e){}'], tdir, { extra: { NEORA_PKGDIR: tdir } });
    let main = ''; try { main = require.resolve(tdir); } catch {}
    const ran = new Set([main]);
    try {
      const j = JSON.parse(fs.readFileSync(pj, 'utf8'));
      const bins = typeof j.bin === 'string' ? [j.bin] : Object.values(j.bin || {});
      for (const b of bins.slice(0, 4)) { const f = path.resolve(tdir, String(b)); if (has(f) && !ran.has(f)) { ran.add(f); add('node:bin:' + clean(rel(f)), process.execPath, [f, '--help'], tdir); } }
    } catch {}
    for (const d of ['.', 'scripts', 'bin', 'tools']) for (const f of files(path.join(tdir, d), /\.(?:js|cjs|mjs)$/).filter((x) => !SKIP.test(x))) {
      const full = path.resolve(tdir, d, f); if (ran.has(full)) continue; ran.add(full);
      if (ran.size < 9) add('node:run:' + clean(rel(full)), process.execPath, [full], tdir);
    }
  }
  const pyFiles = (d) => files(path.join(tdir, d), /\.py$/).filter((x) => !SKIP.test(x));
  const pkgs = [...dirs(tdir).filter((d) => has(path.join(tdir, d, '__init__.py'))), ...dirs(path.join(tdir, 'src')).filter((d) => has(path.join(tdir, 'src', d, '__init__.py')))].slice(0, 3);
  if (has(path.join(tdir, 'setup.py')) || pkgs.length || pyFiles('.').length || pyFiles('scripts').length) st.langs.push('python');
  if (has(path.join(tdir, 'setup.py'))) add('py:setup:setup.py', 'python3', ['setup.py', '--name'], tdir);
  for (const p of pkgs) add('py:import:' + clean(p), 'python3', ['-c', 'import importlib,sys;importlib.import_module(sys.argv[1])', p], tdir);
  let nPy = 0;
  for (const d of ['.', 'scripts', 'bin']) for (const f of pyFiles(d)) if (nPy++ < 6) add('py:run:' + clean(path.join(d, f)), 'python3', [path.join(tdir, d, f)], tdir);
  let nSh = 0;
  for (const d of ['.', 'scripts', 'bin']) for (const f of files(path.join(tdir, d), /\.(?:sh|bash)$/)) if (nSh++ < 6) add('sh:run:' + clean(path.join(d, f)), 'sh', ['-x', path.join(tdir, d, f)], tdir, { trace: true });
  if (nSh) st.langs.push('shell');

  // Additional interpreted runtimes are installed in the dedicated detonation image.
  // Only obvious entry-point scripts are invoked; arbitrary binaries are never exec'd here.
  const runtimeScripts = [
    { lang: 'ruby', ext: /\.rb$/i, bin: 'ruby', args: (f) => [f] },
    { lang: 'php', ext: /\.(?:php|phtml)$/i, bin: 'php', args: (f) => [f] },
    { lang: 'perl', ext: /\.pl$/i, bin: 'perl', args: (f) => [f] },
    { lang: 'lua', ext: /\.lua$/i, bin: 'lua', args: (f) => [f] },
  ];
  for (const rt of runtimeScripts) {
    let count = 0;
    for (const d of ['.', 'scripts', 'bin']) {
      for (const f of files(path.join(tdir, d), rt.ext).filter((x) => !SKIP.test(x))) {
        if (count++ >= 6) continue;
        const full = path.join(d, f);
        add(rt.lang + ':run:' + clean(full), rt.bin, rt.args(full), tdir);
      }
    }
    if (count) st.langs.push(rt.lang);
  }
}
st.runnable = plan.length > 0;
st.lifecycle = st.lifecycle.map(({ pkg, hook, cmd, isTarget }) => ({ pkg, hook, cmd, isTarget }));

// ---------- 3) dynamic run ----------
const DYN0 = Date.now();
const left = () => BUDGET - (Date.now() - DYN0);
const runs = [];
const seenTrace = new Set();
for (const it of plan) {
  if (left() < 300) { runs.push({ what: it.label, skipped: true }); continue; }
  const t = Date.now();
  const r = cp.spawnSync(it.cmd, it.args, { cwd: has(it.cwd) ? it.cwd : WORK, env: envFor(it.label, it.extra), timeout: RUN_MS ? Math.min(RUN_MS, left()) : (Number.isFinite(left()) ? Math.max(1, left()) : undefined), maxBuffer: 1 << 20, encoding: 'utf8', killSignal: 'SIGKILL', stdio: ['ignore', 'pipe', 'pipe'] });
  const timedOut = !!(r.error && r.error.code === 'ETIMEDOUT');
  runs.push({ what: it.label, code: r.status, signal: r.signal || null, timedOut, ms: Date.now() - t, missing: !!(r.error && r.error.code === 'ENOENT') });
  if (it.trace && r.stderr) {
    let n = 0;
    for (const line of r.stderr.split('\n')) {
      const m = line.match(/^\++ (.+)$/);
      if (m && n++ < 40) { const d = clean(m[1]); const k = it.label + d; if (!seenTrace.has(k)) { seenTrace.add(k); fs.appendFileSync(EV, JSON.stringify({ t: 'sh.trace', d, ph: it.label }) + '\n'); } }
    }
  }
}

let events = [];
try { events = fs.readFileSync(EV, 'utf8').split('\n').filter(Boolean).slice(0, 500).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean); } catch {}
process.stdout.write(JSON.stringify({ static: st, dynamic: { runs, events }, elapsedMs: Date.now() - START, budgetExceeded: runs.some((r) => r.skipped) }));

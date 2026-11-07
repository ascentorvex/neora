'use strict';
// Runs INSIDE the detonation container. Finds executables / scripts of other types inside the inspected
// target (.exe, ELF binaries, .bat/.cmd, .vbs, .sh, .py ...), scans binaries for suspicious API/strings and
// executes them with honeypot secrets and NO network. If strace is available in the image every run is traced
// (connect, execve, file opens/writes) and turned into events the verdict logic understands.
const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const NOEXEC = /\.(?:dll|so|node|dylib|sys|ocx|a|o|lib)(?:\.\d+)*$/i; // libraries: scanned, never run directly
const BYEXT = { exe: 'pe', com: 'pe', scr: 'pe', bat: 'bat', cmd: 'bat', vbs: 'vbs', sh: 'sh', bash: 'sh', py: 'py', ps1: 'ps1' };
const MAX_EXEC_BYTES = 150 * 1024 * 1024;

function head(p, n) {
  let fd;
  try { fd = fs.openSync(p, 'r'); const b = Buffer.alloc(n); const r = fs.readSync(fd, b, 0, n, 0); return b.subarray(0, r); } catch { return Buffer.alloc(0); } finally { try { fd && fs.closeSync(fd); } catch {} }
}

// -> 'pe' | 'elf' | 'macho' | 'bat' | 'vbs' | 'sh' | 'py' | 'ps1' | null (not an executable we handle)
function kindOf(p, name) {
  if (NOEXEC.test(name)) return null;
  const ext = ((name.match(/\.([A-Za-z0-9]+)$/) || [])[1] || '').toLowerCase();
  const h = head(p, 160);
  if (BYEXT[ext]) return BYEXT[ext];
  if (h[0] === 0x4d && h[1] === 0x5a) return 'pe';
  if (h[0] === 0x7f && h[1] === 0x45 && h[2] === 0x4c && h[3] === 0x46) return 'elf';
  if ((h[0] === 0xcf || h[0] === 0xce) && h[1] === 0xfa && h[2] === 0xed && h[3] === 0xfe) return 'macho';
  if (h[0] === 0x23 && h[1] === 0x21) {
    const line = h.toString('latin1').split('\n')[0];
    if (/python/.test(line)) return 'py';
    if (/\b(?:ba|z|da|a)?sh\b/.test(line)) return 'sh';
  }
  return null;
}

// ---- static scan of binaries (strings are checked as latin1 and UTF-16LE) ----
const has = (buf, s) => buf.includes(Buffer.from(s, 'latin1')) || buf.includes(Buffer.from(s, 'utf16le'));
const BIN_RULES = [
  { id: 'pe_injection', min: 3, any: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtUnmapViewOfSection', 'QueueUserAPC', 'SetThreadContext'] },
  { id: 'pe_keylog', min: 2, any: ['GetAsyncKeyState', 'SetWindowsHookEx', 'GetKeyboardState', 'GetClipboardData'] },
  { id: 'pe_downloader', min: 1, any: ['URLDownloadToFile', 'InternetOpenUrl', 'WinHttpOpen', 'HttpSendRequest', 'InternetReadFile'] },
  { id: 'pe_persist', min: 1, any: ['CurrentVersion\\Run', 'CurrentVersion\\RunOnce', 'schtasks', 'Start Menu\\Programs\\Startup'] },
  { id: 'pe_antianalysis', min: 2, any: ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'VBoxGuest', 'vmtoolsd', 'SbieDll', 'wine_get_version'] },
  { id: 'bin_packed', min: 1, any: ['UPX0', 'UPX!', '.aspack', '.themida', 'MPRESS1'] },
  { id: 'miner', min: 1, any: ['stratum+tcp', 'xmrig', 'cryptonight', 'minerd'] },
  { id: 'cred_paths', min: 1, any: ['.ssh/id_rsa', '.aws/credentials', '.git-credentials', 'wallet.dat', 'Login Data', '/etc/shadow'] },
];
const IPURL = /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/;
function scanBinary(p, rel, rules, cap = 40 * 1024 * 1024) {
  let buf;
  try { if (fs.statSync(p).size > cap) return; buf = fs.readFileSync(p); } catch { return; }
  const add = (id, sample) => {
    const slot = rules[id] || (rules[id] = { count: 0, samples: [] });
    slot.count++;
    if (slot.samples.length < 3) slot.samples.push({ f: rel, s: sample });
  };
  for (const r of BIN_RULES) {
    const hit = r.any.filter((s) => has(buf, s));
    if (hit.length >= r.min) add(r.id, hit.slice(0, 4).join(', '));
  }
  const m = buf.toString('latin1').match(IPURL);
  if (m) add('raw_ip_url', m[0]);
}

// ---- strace output -> events ----
const SENS = /(\.ssh|\.aws|\.npmrc|\.git-credentials|(^|\/)\.env(\.|$)|id_rsa|id_ed25519|\.kube|\.docker|\.gnupg|\/etc\/shadow|\.netrc|wallet|Login Data|\.bash_history)/i;
const PERSIST = /(\.bashrc|\.zshrc|\.profile|\.bash_profile|crontab|\/cron\.|authorized_keys|\.config\/autostart|\/systemd\/|\/etc\/rc\.|LaunchAgents|\/Startup\/)/i;
const BADPROC = /\b(?:curl|wget|powershell|pwsh|certutil|nc|ncat|scp|ssh|sftp|telnet|crontab|systemctl|nohup|setsid)\b|base64\s+-d|chmod\s+\+x|\/dev\/tcp\/|bash\s+-i|mkfifo/;
function parseTrace(text, ph, home) {
  const ev = [], seen = new Set();
  const push = (t, d) => {
    d = String(d).replace(/[^\x20-\x7e]/g, '?').slice(0, 200);
    const k = t + '|' + d;
    if (seen.has(k) || ev.length >= 120) return;
    seen.add(k); ev.push({ t, d, ph });
  };
  for (const line of text.split('\n')) {
    let m;
    if ((m = line.match(/\bconnect\(\d+, \{sa_family=AF_INET6?, sin6?_port=htons\((\d+)\)[^}]*?(?:inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6, "([^"]+)"\))/))) {
      const ip = m[2] || m[3] || '';
      if (/^(?:127\.|0\.0\.0\.0$|::1$|::$)/.test(ip)) continue;
      push('x.connect', `${ip}:${m[1]}${m[1] === '53' ? ' (DNS lookup)' : ''}`);
    } else if ((m = line.match(/\bexecve\("([^"]+)", \[([^\]]*)\]/))) {
      const d = `${path.basename(m[1])} ${m[2].replace(/"/g, '').replace(/,\s*/g, ' ')}`.slice(0, 160);
      if (BADPROC.test(d)) push('x.spawn', d);
    } else if ((m = line.match(/\bopen(?:at)?\((?:AT_FDCWD, )?"([^"]+)", ([A-Z_|]+)/))) {
      const f = m[1], write = /O_WRONLY|O_RDWR|O_CREAT|O_APPEND|O_TRUNC/.test(m[2]);
      if (write && PERSIST.test(f)) push('fs.persist', f);
      else if (!write && home && f.startsWith(home) && SENS.test(f)) push('fs.sensitive', '[home] ' + f.replace(home, '~'));
      else if (!write && f.startsWith('/etc/shadow')) push('fs.sensitive', f);
    } else if ((m = line.match(/\b(?:rename|renameat|symlink|chmod|fchmodat|unlink|unlinkat)\(.*?"([^"]+)"/))) {
      if (PERSIST.test(m[1])) push('fs.persist', m[1]);
    }
  }
  return ev;
}

const exists = (...c) => c.some((p) => { try { return fs.existsSync(p); } catch { return false; } });
function tools() {
  const bins = ['/usr/bin', '/usr/local/bin', '/bin', '/usr/lib/wine'];
  const w = (b) => exists(...bins.map((d) => path.join(d, b)));
  return { strace: w('strace'), wine: w('wine') || w('wine64'), xvfb: w('xvfb-run'), python: w('python3') };
}

// Builds argv for one file, or { skip: reason }.
function plan(kind, abs, name, T, scratch, idx) {
  const wine = (args) => (T.xvfb ? ['xvfb-run', '-a', 'wine', ...args] : ['wine', ...args]);
  switch (kind) {
    case 'pe': return T.wine ? { argv: wine([abs]), via: 'wine' } : { skip: 'Windows program: needs wine (not in this sandbox image)' };
    case 'bat': return T.wine ? { argv: wine(['cmd', '/c', abs]), via: 'wine' } : { skip: 'batch file: needs wine (not in this sandbox image)' };
    case 'vbs': return T.wine ? { argv: wine(['cscript', '//nologo', abs]), via: 'wine' } : { skip: 'VBScript: needs wine (not in this sandbox image)' };
    case 'sh': return { argv: ['sh', abs], via: 'sh' };
    case 'py': return T.python ? { argv: ['python3', abs], via: 'python3' } : { skip: 'Python script: no python3 in this sandbox image' };
    case 'elf': {
      const dst = path.join(scratch, 'x', idx + '-' + name.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 40));
      try { fs.mkdirSync(path.dirname(dst), { recursive: true }); fs.copyFileSync(abs, dst); fs.chmodSync(dst, 0o755); } catch { return { skip: 'could not stage the binary' }; }
      return { argv: [dst], via: 'native' };
    }
    case 'ps1': return { skip: 'PowerShell: no runtime in the sandbox (static scan only)' };
    case 'macho': return { skip: 'macOS binary: cannot run on Linux (static scan only)' };
    default: return { skip: 'unsupported type' };
  }
}

module.exports = { kindOf, scanBinary, parseTrace, tools, plan, MAX_EXEC_BYTES };

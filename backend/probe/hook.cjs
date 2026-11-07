'use strict';
// Preloaded (node --require) into every node process of the detonation run. It only OBSERVES:
// it logs sensitive file access, process spawns, network attempts and secret reads, never blocks.
const fs = require('fs');
const EV = process.env.NEORA_EVENTS;
const PHASE = process.env.NEORA_PHASE || '';
if (!EV || global.__neoraHook) return;
global.__neoraHook = true;

const append = fs.appendFileSync.bind(fs);
const seen = new Set();
let count = 0;
let quiet = 0;
function log(t, d) {
  try {
    const dd = String(d).replace(/[^\x20-\x7e]/g, '?').slice(0, 200);
    const k = t + '|' + dd;
    if (seen.has(k) || count >= 300) return;
    seen.add(k); count++;
    append(EV, JSON.stringify({ t, d: dd, ph: PHASE }) + '\n');
  } catch {}
}

const HOME = process.env.HOME || '';
const SENS = /(\.ssh|\.aws|\.npmrc|\.git-credentials|(^|\/)\.env(\.|$)|id_rsa|id_ed25519|\.kube|\.docker|\.gnupg|\/etc\/(passwd|shadow)|\.netrc|wallet|Login Data|\.bash_history|\.config\/gcloud)/i;
const PERSIST = /(\.bashrc|\.zshrc|\.profile|\.bash_profile|crontab|\/cron\.|authorized_keys|\/etc\/|\.config\/autostart|\/systemd\/|\.git\/hooks|LaunchAgents|\/Startup\/)/i;
const WRITES = new Set(['writeFileSync', 'writeFile', 'appendFileSync', 'appendFile', 'createWriteStream', 'copyFileSync', 'copyFile', 'renameSync', 'rename', 'symlinkSync', 'symlink', 'chmodSync', 'chmod', 'unlinkSync', 'unlink', 'mkdirSync', 'mkdir']);
const READS = ['readFileSync', 'readFile', 'openSync', 'open', 'createReadStream', 'readdirSync', 'readdir', 'existsSync', 'statSync', 'lstatSync', 'accessSync', 'readlinkSync', 'stat', 'lstat', 'access', 'readlink'];

function p2s(p) {
  try {
    if (typeof p === 'string') return p;
    if (Buffer.isBuffer(p)) return p.toString();
    if (p && typeof p.pathname === 'string') return p.pathname;
  } catch {}
  return '';
}
function inspect(op, a, b) {
  for (const raw of [a, b]) {
    const s = p2s(raw);
    if (!s) continue;
    const home = HOME && s.startsWith(HOME) ? '[home] ' : '';
    if (WRITES.has(op) && PERSIST.test(s)) log('fs.persist', op + ' ' + s);
    else if (SENS.test(s)) log('fs.sensitive', home + op + ' ' + s);
    else if (/^readdir/.test(op) && s.replace(/\/$/, '') === HOME) log('fs.homescan', s);
  }
}
function wrapFs(obj, names, two) {
  for (const n of names) {
    const o = obj[n];
    if (typeof o !== 'function') continue;
    try {
      const w = function (a, b) {
        try { inspect(n, a, two.test(n) ? b : undefined); } catch {}
        return o.apply(this, arguments);
      };
      Object.assign(w, o);
      obj[n] = w;
    } catch {}
  }
}
const TWO = /copy|rename|symlink/;
wrapFs(fs, [...READS, ...WRITES], TWO);
try { wrapFs(fs.promises, ['readFile', 'open', 'readdir', 'writeFile', 'appendFile', 'copyFile', 'rename', 'symlink', 'chmod', 'unlink', 'mkdir', 'stat', 'lstat', 'access', 'readlink'], TWO); } catch {}

try {
  const cp = require('child_process');
  for (const n of ['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork']) {
    const o = cp[n];
    if (typeof o !== 'function') continue;
    const w = function (c, a) {
      try { log('proc.spawn', n + ' ' + String(c) + ' ' + (Array.isArray(a) ? a.join(' ') : '')); } catch {}
      quiet++;
      try { return o.apply(this, arguments); } finally { quiet--; }
    };
    Object.assign(w, o);
    cp[n] = w;
  }
} catch {}

function tgt(a) {
  let o = a[0];
  if (Array.isArray(o)) o = o[0];
  if (o && typeof o === 'object') return (o.host || o.path || '?') + ':' + (o.port || '');
  return String(a[1] || '?') + ':' + String(o);
}
try {
  const net = require('net');
  const oc = net.Socket.prototype.connect;
  net.Socket.prototype.connect = function (...a) { try { log('net.connect', tgt(a)); } catch {} return oc.apply(this, a); };
} catch {}
try {
  const dns = require('dns');
  for (const n of ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveTxt']) {
    const o = dns[n];
    if (typeof o !== 'function') continue;
    dns[n] = function (h) { try { log('dns.lookup', h); } catch {} return o.apply(this, arguments); };
  }
} catch {}
function urlOf(u) {
  if (typeof u === 'string') return u;
  if (u && u.href) return u.href;
  if (u && typeof u === 'object') return (u.protocol || '') + '//' + (u.hostname || u.host || '') + (u.path || '');
  return String(u);
}
for (const m of ['http', 'https']) {
  try {
    const mod = require(m);
    for (const n of ['request', 'get']) {
      const o = mod[n];
      mod[n] = function (u) { try { log('http.request', urlOf(u)); } catch {} return o.apply(this, arguments); };
    }
  } catch {}
}
try {
  if (typeof globalThis.fetch === 'function') {
    const of = globalThis.fetch;
    globalThis.fetch = function (u) { try { log('http.fetch', typeof u === 'string' ? u : (u && u.url) || String(u)); } catch {} return of.apply(this, arguments); };
  }
} catch {}
try { const dg = require('dgram'); const oc = dg.createSocket; dg.createSocket = function () { log('net.udp', 'createSocket'); return oc.apply(this, arguments); }; } catch {}
try { const os = require('os'); for (const n of ['networkInterfaces', 'userInfo', 'hostname']) { const o = os[n]; os[n] = function () { log('recon.os', n); return o.apply(this, arguments); }; } } catch {}

const SENS_ENV = /(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|AWS_|GITHUB|GH_|NPM_|CREDENTIAL|PRIVATE|SESSION|COOKIE)/i;
try {
  process.env = new Proxy(process.env, {
    get(t, k) { if (!quiet && typeof k === 'string' && SENS_ENV.test(k) && Object.prototype.hasOwnProperty.call(t, k)) log('env.read', k); return t[k]; },
    ownKeys(t) { if (!quiet) log('env.enumerate', 'all'); return Reflect.ownKeys(t); },
  });
} catch {}

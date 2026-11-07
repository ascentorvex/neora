import test from 'node:test';
import assert from 'node:assert/strict';
import { parseWineOutput } from '../wine-evidence.mjs';
const N = 'smoke', M = `@@NEORA:${N} `;
const X = (pid, path, argv) => `${pid}    execve("${path}", [${argv.map((a) => `"${a}"`).join(', ')}], 0x7d /* 15 vars */) = 0`;
// Shapes copied from a REAL 32-bit run on the server: the sample starts in the 32-bit loader BEFORE wineboot.
const real32 = [
  M + 'META wine=wine-8.0 exit=0 ended=exited run_s=20 trace=1 arch=x86',
  M + 'NET',
  '20:44    connect(5, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("108.61.10.10")}, 16) = -1 ENETUNREACH',
  '21:44    connect(5, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("108.61.115.10")}, 16) = -1 ENETUNREACH',
  '90:88    connect(9, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.9")}, 16) = -1 ENETUNREACH',
  M + 'EXEC',
  '1:40    ' + X('', '/usr/bin/wine', ['wine', 'C:\\\\sample\\\\a.exe']).trim(),
  '2:40    ' + X('', '/usr/lib/wine/wine', ['/usr/lib/wine/wine', 'C:\\\\sample\\\\a.exe']).trim(),
  '6:40    ' + X('', '/usr/lib/wine/wine', ['/usr/lib/wine/wine', 'C:\\\\sample\\\\a.exe']).trim(),
  '15:44    ' + X('', '/usr/lib/wine/wine64', ['/usr/lib/wine/wine64', 'C:\\\\windows\\\\system32\\\\wineboot.exe', '--init']).trim(),
  '32:48    ' + X('', '/usr/lib/wine/wine64', ['/usr/lib/wine/wine64', 'C:\\\\windows\\\\system32\\\\services.exe']).trim(),
  '55:80    ' + X('', '/usr/lib/wine/wine64', ['/usr/lib/wine/wine64', 'C:\\\\windows\\\\system32\\\\svchost.exe', '-k', 'LocalServiceNetworkRestricted']).trim(),
  M + 'END',
].join('\n');

test('32-bit sample: wineboot DNS probes are not blamed on it, its own connect is kept, the launch is not a spawn', () => {
  const r = parseWineOutput(real32, N, 'wine:run:a.exe', 'a.exe');
  assert.equal(r.meta.arch, 'x86');
  assert.deepEqual(r.events.filter((e) => e.t === 'dns.lookup'), []);
  assert.deepEqual(r.events.filter((e) => e.t === 'net.connect').map((e) => e.d), ['203.0.113.9:443']);
  assert.deepEqual(r.events.filter((e) => e.t === 'proc.spawn'), []);
});

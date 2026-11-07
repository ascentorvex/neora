import test from 'node:test';
import assert from 'node:assert/strict';
import { classify, computeVerdict, summaryForModel, buildReport } from '../verdict.mjs';

const st = { runnable: false, winExec: true, natives: ['7z.exe'], files: 1, scan: { binary: 1 }, notRun: {} };
const wineRun = { what: 'wine:run:7z.exe', started: true, timedOut: true };
const go = (runs, wineRan) => {
  const findings = classify({ static: st, events: [], runs, kind: 'file', name: '7z.exe' });
  const verdict = computeVerdict(findings, false, { nothingRan: false, notRun: wineRan });
  return { findings, verdict, runs };
};

test('Wine ran: finding, label, notice and report all say it WAS run in Wine, never "cannot be run"', () => {
  const { findings, verdict, runs } = go([wineRun], true);
  const w = findings.find((f) => f.id === 'win_exec');
  assert.match(w.t.en, /run offline in Wine/); assert.doesNotMatch(w.t.en, /cannot be run/);
  assert.match(w.t.tr, /Wine ile/);
  const sum = summaryForModel({ label: '7z.exe', lang: 'en', verdict, findings, incompleteReason: '', wineRan: true });
  assert.match(sum, /WAS run offline in Wine/); assert.match(sum, /not a Windows VM/);
  assert.doesNotMatch(sum, /some files could not be executed/); assert.doesNotMatch(sum, /only read, not executed/);
  const md = buildReport({ label: '7z.exe', kind: 'file', lang: 'en', verdict, findings, st, runs, events: [], receipt: {} });
  assert.match(md, /RUN WITH WINE \(PARTIAL\)/); assert.doesNotMatch(md, /only read, not executed/);
  const tr = summaryForModel({ label: '7z.exe', lang: 'tr', verdict, findings, incompleteReason: '', wineRan: true });
  assert.match(tr, /WINE İLE ÇALIŞTIRILDI: ZARARLI DAVRANIŞ GÖRÜLMEDİ/);
});

test('Wine did NOT run: old static-only wording is unchanged', () => {
  const { findings, verdict } = go([], false);
  assert.match(findings.find((f) => f.id === 'win_exec').t.en, /cannot be run in this Linux sandbox/);
  const sum = summaryForModel({ label: '7z.exe', lang: 'en', verdict, findings, incompleteReason: '' });
  assert.doesNotMatch(sum, /WAS run offline in Wine/);
});

test('Wine ran but another file was NOT executed: the honest "not executed" part is kept', () => {
  const st2 = { ...st, notRun: { dll: 2 } };
  const findings = classify({ static: st2, events: [], runs: [wineRun], kind: 'file', name: 'x.zip' });
  const verdict = computeVerdict(findings, false, { nothingRan: false, notRun: true });
  const sum = summaryForModel({ label: 'x.zip', lang: 'en', verdict, findings, incompleteReason: '', wineRan: true });
  assert.match(sum, /could not be executed here/);
});

test('label: Wine + clean -> new purple wording; Wine + malicious behavior -> still UNSAFE (never softened)', () => {
  const clean = go([wineRun], true);
  const s1 = summaryForModel({ label: 'a.exe', lang: 'en', verdict: clean.verdict, findings: clean.findings, incompleteReason: '', wineRan: true });
  assert.match(s1, /RUN WITH WINE: NO MALICIOUS BEHAVIOR SEEN \(PARTIAL COVERAGE, not a Windows VM\)/);
  const events = [{ t: 'fs.persist', ph: 'wine:run:a.exe', d: 'registry Software\\Microsoft\\Windows\\CurrentVersion\\Run: "x"="C:\\a.exe"' }];
  const findings = classify({ static: st, events, runs: [wineRun], kind: 'file', name: 'a.exe' });
  const verdict = computeVerdict(findings, false, { nothingRan: false, notRun: true });
  assert.notEqual(verdict.level, 'partial');
  const s2 = summaryForModel({ label: 'a.exe', lang: 'en', verdict, findings, incompleteReason: '', wineRan: true });
  assert.doesNotMatch(s2, /RUN WITH WINE: NO MALICIOUS/);
  assert.match(s2, /SUSPICIOUS|UNSAFE/);
});

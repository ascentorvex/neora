import test from 'node:test';
import assert from 'node:assert/strict';
import { makeReport } from '../report.mjs';

test('strips HTML and builds a safe file name', () => {
  const r = makeReport('Rakip Analizi: Çok Şey!', '<script>alert(1)</script>Merhaba **dünya**, bu yeterince uzun bir rapor metnidir.');
  assert.equal(r.name, 'neora-rakip-analizi-cok-sey.md');
  assert.ok(!r.content.includes('<script'));
  assert.ok(r.content.startsWith('# Rakip Analizi'));
});

test('rejects empty or tiny reports and caps size', () => {
  assert.equal(makeReport('x', 'kısa'), null);
  assert.ok(makeReport('x', 'a'.repeat(100000)).content.length <= 40100);
});

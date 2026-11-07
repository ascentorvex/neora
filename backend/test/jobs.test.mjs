import test from 'node:test';
import assert from 'node:assert/strict';
import { startJob, getJob } from '../jobs.mjs';

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

test('job reports live status, then the result', async () => {
  const r = startJob('1.1.1.1', async (st) => { st({ k: 'search', d: 'scooters' }); await wait(60); st({ k: 'answer' }); return { answer: 'ok' }; });
  assert.match(r.id, /^[a-f0-9]{32}$/);
  await wait(20);
  assert.deepEqual(getJob(r.id).status, { k: 'search', d: 'scooters' });
  assert.equal(getJob(r.id).state, 'running');
  await wait(100);
  const j = getJob(r.id);
  assert.equal(j.state, 'done');
  assert.equal(j.result.answer, 'ok');
});

test('errors are stored without leaking internals; unknown ids are null; per-IP cap applies', async () => {
  const bad = startJob('2.2.2.2', async () => { throw new Error('secret internals'); });
  await wait(20);
  const j = getJob(bad.id);
  assert.equal(j.state, 'error');
  assert.ok(!j.error.includes('secret'));
  assert.equal(getJob('0'.repeat(32)), null);
  const slow = () => new Promise((r) => setTimeout(r, 200));
  startJob('3.3.3.3', slow); startJob('3.3.3.3', slow);
  assert.equal(startJob('3.3.3.3', slow).code, 429);
  assert.ok(startJob('4.4.4.4', slow).id);
});

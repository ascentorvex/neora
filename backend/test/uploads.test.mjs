import test from 'node:test';
import assert from 'node:assert/strict';
import { access } from 'node:fs/promises';
import { saveUpload, takeUpload, deleteUpload } from '../uploads.mjs';

test('uploads are assigned random one-time ids and deleted after claim', async () => {
  const bytes = Buffer.from('safe test fixture');
  const saved = await saveUpload('../sample.txt', bytes);
  assert.match(saved.id, /^[a-f0-9]{32}$/);
  assert.equal(saved.name, '.._sample.txt');
  assert.equal(saved.size, bytes.length);
  const item = await takeUpload(saved.id);
  assert.ok(item);
  await access(item.path);
  assert.equal(await takeUpload(saved.id), null);
  await deleteUpload(item);
  await assert.rejects(access(item.path));
});

test('rejects empty and oversized uploads', async () => {
  await assert.rejects(saveUpload('empty.bin', Buffer.alloc(0)), /boş/i);
  await assert.rejects(saveUpload('large.bin', Buffer.alloc(64 * 1024 * 1024 + 1)), /64 MB/i);
});

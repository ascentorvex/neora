import { randomBytes, createHash } from 'node:crypto';
import { mkdir, writeFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const DIR = join(tmpdir(), 'neora-uploads');
const MAX_BYTES = 64 * 1024 * 1024;
const TTL_MS = 30 * 60 * 1000;
const records = new Map();

function safeName(value) {
  const s = String(value || 'uploaded-file').replace(/[\u0000-\u001f\u007f/\\]/g, '_').slice(0, 120);
  return s || 'uploaded-file';
}
async function sweep() {
  const now = Date.now();
  for (const [id, item] of records) {
    if (now - item.createdAt > TTL_MS) {
      records.delete(id);
      await rm(item.path, { force: true }).catch(() => {});
    }
  }
}
export async function saveUpload(name, buffer) {
  await sweep();
  if (!Buffer.isBuffer(buffer) || !buffer.length) throw Object.assign(new Error('Dosya boş.'), { status: 400 });
  if (buffer.length > MAX_BYTES) throw Object.assign(new Error('Dosya boyutu en fazla 64 MB olabilir.'), { status: 413 });
  await mkdir(DIR, { recursive: true, mode: 0o700 });
  const id = randomBytes(16).toString('hex');
  const path = join(DIR, id + '.bin');
  await writeFile(path, buffer, { mode: 0o600, flag: 'wx' });
  records.set(id, { path, name: safeName(name), size: buffer.length, createdAt: Date.now() });
  return { id, name: safeName(name), size: buffer.length, sha256: createHash('sha256').update(buffer).digest('hex') };
}
export async function takeUpload(id) {
  await sweep();
  if (!/^[a-f0-9]{32}$/.test(String(id || ''))) return null;
  const item = records.get(id);
  if (!item) return null;
  records.delete(id);
  try {
    const info = await stat(item.path);
    if (!info.isFile() || info.size !== item.size) return null;
    return { ...item, id };
  } catch { return null; }
}
export async function deleteUpload(item) {
  if (item?.path) await rm(item.path, { force: true }).catch(() => {});
}

import test from 'node:test';
import assert from 'node:assert/strict';
import { isBlockedIp, resolvePublicAddresses, validatePublicHttpUrl } from '../security/url-guard.mjs';

test('blocks private, loopback, link-local and reserved IPv4', () => {
  for (const ip of ['127.0.0.1', '10.0.0.2', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '224.0.0.1', '203.0.113.4']) {
    assert.equal(isBlockedIp(ip), true, ip);
  }
});

test('allows a public IPv4 and globally routable IPv6 address', () => {
  assert.equal(isBlockedIp('1.1.1.1'), false);
  assert.equal(isBlockedIp('2606:4700:4700::1111'), false);
});

test('blocks loopback and special-use IPv6', () => {
  for (const ip of ['::1', '::', 'fc00::1', 'fe80::1', '::ffff:127.0.0.1', '2001:db8::1', 'ff02::1']) {
    assert.equal(isBlockedIp(ip), true, ip);
  }
});

test('accepts public hostname only when all DNS answers are public', async () => {
  const lookup = async () => [{ address: '1.1.1.1' }, { address: '2606:4700:4700::1111' }];
  assert.equal(await validatePublicHttpUrl('https://example.com/path', lookup), 'https://example.com/path');
  await assert.rejects(validatePublicHttpUrl('https://example.com', async () => [
    { address: '1.1.1.1' }, { address: '127.0.0.1' },
  ]));
});

test('rejects unsafe schemes, embedded credentials and local hostnames', async () => {
  await assert.rejects(validatePublicHttpUrl('file:///etc/passwd'));
  await assert.rejects(validatePublicHttpUrl('https://user:pass@example.com'));
  await assert.rejects(validatePublicHttpUrl('http://localhost'));
  await assert.rejects(validatePublicHttpUrl('http://127.0.0.1'));
});


test('blocks additional IPv4 special-use ranges', () => {
  for (const ip of ['0.1.2.3', '192.0.0.8', '198.18.0.1', '198.51.100.1', '203.0.113.1', '240.0.0.1']) {
    assert.equal(isBlockedIp(ip), true, ip);
  }
});

test('blocks IPv6 special-purpose and documentation ranges', () => {
  for (const ip of ['2001:0:1::1', '2001:db8::1', '2002::1', '3fff::1', '2001:4860::1']) {
    if (ip === '2001:4860::1') assert.equal(isBlockedIp(ip), false, ip);
    else assert.equal(isBlockedIp(ip), true, ip);
  }
});

test('normalizes IPv4-mapped IPv6 addresses before classification', () => {
  assert.equal(isBlockedIp('::ffff:10.0.0.1'), true);
  assert.equal(isBlockedIp('::ffff:1.1.1.1'), false);
});


test('rejects non-standard ports to reduce SSRF attack surface', async () => {
  await assert.rejects(validatePublicHttpUrl('http://example.com:8080', async () => [{ address: '1.1.1.1' }]));
  await assert.rejects(validatePublicHttpUrl('https://example.com:8443', async () => [{ address: '1.1.1.1' }]));
});


test('returns the exact validated DNS address set for connection pinning', async () => {
  const records = await resolvePublicAddresses('example.com', async () => [
    { address: '1.1.1.1', family: 4 },
    { address: '2606:4700:4700::1111', family: 6 },
  ]);
  assert.deepEqual(records, [
    { address: '1.1.1.1', family: 4 },
    { address: '2606:4700:4700::1111', family: 6 },
  ]);
  await assert.rejects(resolvePublicAddresses('mixed.example', async () => [
    { address: '1.1.1.1', family: 4 },
    { address: '10.0.0.1', family: 4 },
  ]));
});

import dns from 'node:dns/promises';
import net from 'node:net';

function ipv4Number(ip) {
  return ip.split('.').reduce((n, part) => (n * 256n) + BigInt(Number(part)), 0n);
}
function ipv6Number(ip) {
  let s = ip.toLowerCase();
  if (s.includes('.')) {
    const i = s.lastIndexOf(':');
    const v4 = s.slice(i + 1);
    if (!net.isIPv4(v4)) return null;
    const [a, b, c, d] = v4.split('.').map(Number);
    s = `${s.slice(0, i)}:${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = 8 - left.length - right.length;
  if ((halves.length === 1 && fill !== 0) || (halves.length === 2 && fill < 1)) return null;
  const words = [...left, ...Array(fill).fill('0'), ...right];
  if (words.length !== 8 || words.some(x => !/^[0-9a-f]{1,4}$/.test(x))) return null;
  return words.reduce((n, x) => (n << 16n) | BigInt(parseInt(x, 16)), 0n);
}
function inCidr(value, base, bits, width) {
  const shift = BigInt(width - bits);
  return (value >> shift) === (base >> shift);
}
function ipv4Blocked(ip) {
  const n = ipv4Number(ip);
  const blocked = [
    ['0.0.0.0',8], ['10.0.0.0',8], ['100.64.0.0',10], ['127.0.0.0',8],
    ['169.254.0.0',16], ['172.16.0.0',12], ['192.0.0.0',24],
    ['192.0.2.0',24], ['192.88.99.0',24], ['192.168.0.0',16],
    ['198.18.0.0',15], ['198.51.100.0',24], ['203.0.113.0',24],
    ['224.0.0.0',4], ['240.0.0.0',4],
  ];
  return blocked.some(([base, bits]) => inCidr(n, ipv4Number(base), bits, 32));
}
function ipv6Blocked(ip) {
  const n = ipv6Number(ip);
  if (n === null) return true;
  // Only global-unicast space (2000::/3) is eligible. Explicitly reject
  // IETF protocol assignments, documentation, 6to4 and other special-use space.
  if (!inCidr(n, ipv6Number('2000::'), 3, 128)) return true;
  const blocked = [
    ['2001::',23], ['2001:db8::',32], ['2002::',16], ['3fff::',20],
  ];
  return blocked.some(([base, bits]) => inCidr(n, ipv6Number(base), bits, 128));
}

export function isBlockedIp(ip) {
  if (net.isIPv4(ip)) return ipv4Blocked(ip);
  if (!net.isIPv6(ip)) return true;
  const normalized = ip.toLowerCase();
  if (normalized.startsWith('::ffff:')) {
    const tail = normalized.slice(7);
    return net.isIPv4(tail) ? ipv4Blocked(tail) : true;
  }
  return ipv6Blocked(normalized);
}

export async function resolvePublicAddresses(host, lookup = dns.lookup) {
  if (net.isIP(host)) {
    if (isBlockedIp(host)) throw new Error('Bu adrese izin verilmiyor.');
    return [{ address: host, family: net.isIP(host) }];
  }
  const records = await lookup(host, { all: true, verbatim: true });
  const addresses = [...new Map(records.map(x => [x.address, {
    address: x.address, family: net.isIP(x.address),
  }])).values()];
  if (!addresses.length || addresses.some(x => !x.family || isBlockedIp(x.address))) {
    throw new Error('Bu adrese izin verilmiyor.');
  }
  return addresses;
}

export async function validatePublicHttpUrl(raw, lookup = dns.lookup) {
  let u;
  try { u = new URL(raw); } catch { throw new Error('Geçersiz URL.'); }
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password || (u.port && !['80', '443'].includes(u.port))) {
    throw new Error('Yalnızca kimlik bilgisi içermeyen http/https adreslerine izin verilir.');
  }
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) {
    throw new Error('Bu adrese izin verilmiyor.');
  }
  await resolvePublicAddresses(host, lookup);
  return u.href;
}

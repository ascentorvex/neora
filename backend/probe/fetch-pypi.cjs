'use strict';
// Runs in the NETWORK-enabled fetch container: downloads one PyPI release file (no pip, no setup.py execution).
const https = require('https');
const fs = require('fs');
const name = process.env.PKG || '';
const ver = process.env.PKG_VER || '';
const MAX = 30 * 1024 * 1024;
if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$/.test(name) || (ver && !/^[A-Za-z0-9._!+-]{1,30}$/.test(ver))) { console.error('bad spec'); process.exit(2); }
function get(url, hops, cb, binary) {
  const host = new URL(url).hostname;
  if (host !== 'pypi.org' && host !== 'files.pythonhosted.org') { console.error('host refused'); process.exit(3); }
  https.get(url, { headers: { 'user-agent': 'neora-inspect' } }, (r) => {
    if (r.statusCode >= 300 && r.statusCode < 400 && r.headers.location && hops < 3) { r.resume(); return get(new URL(r.headers.location, url).href, hops + 1, cb, binary); }
    if (r.statusCode !== 200) { console.error('http ' + r.statusCode); process.exit(4); }
    const chunks = []; let n = 0;
    r.on('data', (c) => { n += c.length; if (n > MAX) { console.error('too large'); process.exit(5); } chunks.push(c); });
    r.on('end', () => cb(Buffer.concat(chunks)));
  }).on('error', (e) => { console.error(String(e.code || e.message)); process.exit(6); });
}
get(`https://pypi.org/pypi/${encodeURIComponent(name)}/${ver ? encodeURIComponent(ver) + '/' : ''}json`, 0, (buf) => {
  let j; try { j = JSON.parse(buf.toString()); } catch { console.error('bad json'); process.exit(7); }
  const files = j.urls || [];
  const f = files.find((x) => x.packagetype === 'sdist') || files.find((x) => x.packagetype === 'bdist_wheel') || files[0];
  if (!f || !/^[\w.+!-]+\.(?:tar\.gz|zip|whl)$/.test(f.filename || '')) { console.error('no usable file'); process.exit(8); }
  get(f.url, 0, (data) => { fs.writeFileSync('/tmp/p.dat', data); fs.writeFileSync('/tmp/p.name', f.filename); process.exit(0); }, true);
}, false);

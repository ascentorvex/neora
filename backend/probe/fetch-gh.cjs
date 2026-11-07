'use strict';
// Runs in the NETWORK-enabled fetch container: downloads one GitHub repo tarball (no git, no hooks).
const https = require('https');
const fs = require('fs');
const u = process.env.GH_TARBALL;
const MAX = 40 * 1024 * 1024;
if (!/^https:\/\/codeload\.github\.com\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+\/tar\.gz\/HEAD$/.test(u || '')) { console.error('bad url'); process.exit(2); }
function get(url, hops) {
  https.get(url, { headers: { 'user-agent': 'neora-inspect' } }, (r) => {
    if (r.statusCode >= 300 && r.statusCode < 400 && r.headers.location && hops < 3) {
      const l = new URL(r.headers.location, url);
      if (l.protocol !== 'https:' || !/(^|\.)github\.com$|(^|\.)githubusercontent\.com$/.test(l.hostname)) { console.error('redirect refused'); process.exit(3); }
      r.resume(); return get(l.href, hops + 1);
    }
    if (r.statusCode !== 200) { console.error('http ' + r.statusCode); process.exit(4); }
    let n = 0;
    const out = fs.createWriteStream('/tmp/r.tgz');
    r.on('data', (c) => { n += c.length; if (n > MAX) { console.error('too large'); process.exit(5); } });
    r.pipe(out);
    out.on('finish', () => process.exit(0));
  }).on('error', (e) => { console.error(String(e.code || e.message)); process.exit(6); });
}
get(u, 0);

import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { resolvePublicAddresses } from '../security/url-guard.mjs';
import { searchBing } from './search.mjs';

const MAX_BYTES = 1500000;
const MAX_REDIRECTS = 4;
const UA = 'NeoraFetcher/1.0 (+safe-public-web-reader)';

function stripHtml(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ').trim();
}

// Connect to one of the exact IPs checked immediately before the request.
// The original hostname remains in Host and TLS SNI/certificate validation.
function pinnedRequest(url, addresses) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const transport = u.protocol === 'https:' ? https : http;
    const selected = addresses[0];
    const options = {
      protocol: u.protocol,
      hostname: u.hostname.replace(/^\[|\]$/g, ''),
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      method: 'GET',
      path: `${u.pathname}${u.search}`,
      headers: { 'User-Agent': UA, Accept: 'text/html,text/plain,application/json,application/xml,text/xml;q=0.9,*/*;q=0.1' },
      timeout: 15000,
      lookup: (_hostname, opts, callback) => {
        if (opts?.all) callback(null, [{ address: selected.address, family: selected.family }]);
        else callback(null, selected.address, selected.family);
      },
    };
    if (u.protocol === 'https:' && !net.isIP(options.hostname)) options.servername = options.hostname;
    const req = transport.request(options, resolve);
    req.on('timeout', () => req.destroy(new Error('İstek zaman aşımına uğradı.')));
    req.on('error', reject);
    req.end();
  });
}

async function readPage(url) {
  let current = url;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const u = new URL(current);
    const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password || (u.port && !['80', '443'].includes(u.port))) {
      throw new Error('Yalnızca kimlik bilgisi içermeyen standart http/https adreslerine izin verilir.');
    }
    if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) {
      throw new Error('Bu adrese izin verilmiyor.');
    }
    const addresses = await resolvePublicAddresses(host);
    const response = await pinnedRequest(current, addresses);

    if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
      response.resume();
      if (hop === MAX_REDIRECTS) throw new Error('Çok fazla yönlendirme.');
      current = new URL(response.headers.location, current).href;
      continue;
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      response.resume();
      return `[HATA: Uzak sunucu HTTP ${response.statusCode} döndürdü.]`;
    }
    const type = response.headers['content-type'] || '';
    if (!/text\/|json|xml/i.test(type)) {
      response.resume();
      return `[HATA: Desteklenmeyen içerik türü: ${type.slice(0, 40) || 'bilinmiyor'}]`;
    }
    const declaredLength = Number(response.headers['content-length'] || 0);
    if (declaredLength > MAX_BYTES) {
      response.destroy();
      return '[HATA: Sayfa boyutu sınırı aşıyor.]';
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of response) {
      size += chunk.length;
      if (size > MAX_BYTES) {
        response.destroy();
        return '[HATA: Sayfa boyutu sınırı aşıyor.]';
      }
      chunks.push(chunk);
    }
    const body = Buffer.concat(chunks).toString('utf8');
    return (/html/i.test(type) ? stripHtml(body) : body).slice(0, 8000);
  }
  throw new Error('Çok fazla yönlendirme.');
}

const [mode, arg] = process.argv.slice(2);
try {
  let data;
  if (mode === 'search') data = await searchBing(String(arg || '').slice(0, 500));
  else if (mode === 'read') data = await readPage(String(arg || ''));
  else throw new Error('Bilinmeyen mod.');
  console.log(JSON.stringify({ ok: true, data }));
} catch (e) {
  console.log(JSON.stringify({ ok: false, error: String(e.message || 'Fetch hatası').slice(0, 300) }));
}

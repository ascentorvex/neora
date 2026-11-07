const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

const clean = (s) => String(s || '')
  .replace(/<[^>]+>/g, ' ')
  .replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#x27;|&#39;/g, "'")
  .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#0183;|&nbsp;|&#32;/g, ' ')
  .replace(/\s+/g, ' ').trim();

function bingUrl(href) {
  href = href.replace(/&amp;/g, '&');
  try {
    const u = new URL(href);
    if (u.hostname.endsWith('bing.com')) {
      if (!u.pathname.startsWith('/ck/')) return '';
      const t = u.searchParams.get('u') || '';
      if (!t.startsWith('a1')) return '';
      return Buffer.from(t.slice(2).replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    }
  } catch { return ''; }
  return href;
}

export async function searchBing(q) {
  const r = await fetch('https://www.bing.com/search?q=' + encodeURIComponent(q) + '&setlang=en&cc=us', {
    headers: { 'User-Agent': UA, 'Accept-Language': 'en-US,en;q=0.9' },
    signal: AbortSignal.timeout(12000),
  });
  const html = await r.text();
  const out = [];
  for (const b of html.split('<li class="b_algo"').slice(1)) {
    const a = b.match(/<h2[^>]*>\s*<a[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/);
    if (!a) continue;
    const url = bingUrl(a[1]);
    if (!/^https?:\/\//.test(url)) continue;
    const rest = b.slice(b.indexOf(a[0]) + a[0].length);
    const s = rest.match(/<p[^>]*>([\s\S]*?)<\/p>/);
    out.push({ title: clean(a[2]), url, snippet: clean(s ? s[1] : '') });
    if (out.length >= 5) break;
  }
  return out;
}

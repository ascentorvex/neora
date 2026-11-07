// Turns model-written Markdown into a safe downloadable report (data only, never executed).
const MAX_CHARS = 40000;
const TR = { 'ç': 'c', 'ğ': 'g', 'ı': 'i', 'ö': 'o', 'ş': 's', 'ü': 'u' };

export function makeReport(title, markdown) {
  const body = String(markdown || '')
    .replace(/<[^>]*>/g, '')            // no HTML/script in the file
    .replace(/\u0000/g, '')
    .trim()
    .slice(0, MAX_CHARS);
  if (body.length < 40) return null;
  const t = String(title || 'report').trim().slice(0, 80) || 'report';
  const slug = t.toLowerCase().replace(/[çğıöşü]/g, (c) => TR[c])
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'report';
  return { name: `neora-${slug}.md`, content: body.startsWith('#') ? body : `# ${t}\n\n${body}` };
}

import { runInSandbox } from './tools.mjs';
import { isoSearch } from './isolated.mjs';
import { makeReport } from './report.mjs';
import { inspectTarget, inspectUploadedFile } from './detonate.mjs';
import { takeUpload, deleteUpload } from './uploads.mjs';
import { langLock, langName } from './lang.mjs';

const INFERENCE_URL = 'https://api.vultrinference.com/v1/chat/completions';
const MODEL = process.env.MODEL || 'glm-5.3-flash';
const MAX_STEPS = 6;
const MAX_TOKENS = 2000; // was 800: long answers were cut off mid-sentence
const MAX_CONTINUE = 2;
// 0 = no deadline (job mode has no proxy limit). Set NEORA_DEADLINE_MS only if you use the classic single-request mode.
const DEADLINE_MS = Number(process.env.NEORA_DEADLINE_MS) > 0 ? Number(process.env.NEORA_DEADLINE_MS) : 0;
const ALLOWED = new Set(['glm-5.3-flash', 'glm-5.3', 'glm-5.2', 'deepseek-v4.1-flash-1017']);

const fail = (status, message) => Object.assign(new Error(message), { status });

async function searchWeb(q) {
  try {
    const res = await isoSearch(q);
    if (!res.length) return 'Arama sonucu alınamadı.';
    return res.map((x, i) => `${i + 1}. ${x.title}\n${x.url}\n${x.snippet}`).join('\n\n');
  } catch (e) {
    return 'Arama hatası: ' + e.message;
  }
}

const fn = (name, description, props, required) => ({
  type: 'function',
  function: { name, description, parameters: { type: 'object', properties: props, required } },
});

const TOOLS = [
  fn('web_search', 'Search the internet. Returns top results with title, url and snippet. Use when the user asks to find or research something without giving a link.',
    { query: { type: 'string', description: 'Search query' } }, ['query']),
  fn('read_page', 'Open a web page URL (e.g. from search results) and return its text content.',
    { url: { type: 'string', description: 'Full https URL' } }, ['url']),
  fn('run_command', 'Run restricted Python code with python3 -c in a throwaway Linux sandbox with no internet or host filesystem access. Only a safe AST subset and approved built-ins are available.',
    { command: { type: 'string', description: 'Shell command to run' } }, ['command']),
  fn('write_report', 'Save the final deliverable as a downloadable Markdown report file. Call it once, after research and calculations are done. Keep the report under about 600 words.',
    { title: { type: 'string', description: 'Report title' }, markdown: { type: 'string', description: 'Full report in Markdown: summary, key findings with numbers, comparison table or list, and a Sources section with URLs' } }, ['title', 'markdown']),
  fn('inspect_uploaded_file', 'Analyze a file that the user uploaded to this conversation. Use when the user asks whether an attached/uploaded file is safe, suspicious, malware, or asks to inspect it. The file is already stored server-side; do not ask for its contents. The sandbox is one-time, offline and destroyed after analysis. Static analysis always runs first. Top-level .exe/.scr/.com/.pif files are additionally run for a short window in a separate offline Wine container; .dll/.msi and files inside archives stay static-only. Report exactly what the tool result says: if it says a Wine run happened, say so and summarize its findings; if it says the file was not run, say it was static-only. A Wine run is never equivalent to a Windows VM, so always call that coverage partial.',
    { upload_ids: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 5, description: 'All 32-character upload IDs from [uploaded_file: ID] markers in the user message' }, lang: { type: 'string', enum: ['tr', 'en'] } }, ['upload_ids', 'lang']),
  fn('inspect_package', 'Safety-test untrusted code in a one-time sandbox (no network, read-only, destroyed afterwards): an npm package, a PyPI package, a public GitHub repo, or a pasted shell command/one-liner. Downloads happen with scripts disabled; then many entry points (install scripts, imports, CLI entries, Python setup/imports/scripts, shell scripts) are executed and watched. A code-computed verdict is returned. Use whenever the user asks if a package, repo, script or install command is safe.',
    { kind: { type: 'string', enum: ['npm', 'pip', 'github', 'command'] }, target: { type: 'string', description: 'npm name[@version] | PyPI name[==version] | https://github.com/owner/repo | the exact shell command text for kind command' }, lang: { type: 'string', enum: ['tr', 'en'], description: 'tr if the user writes Turkish, otherwise en' } }, ['kind', 'target']),
];

const EXTRA = '\nTools: web_search (search the internet), read_page (read a web page), run_command (isolated, offline sandbox that runs only a restricted Python subset). When the user asks you to find something online, call web_search first, then read_page on the 1-2 most relevant results, and cite the source URLs in your answer. Do not use tools for greetings or general chat. If a search or page read fails, say so plainly; never invent results. INSPECTIONS: when the user asks whether an attached file is safe, call inspect_uploaded_file using all 32-character [uploaded_file: ID] markers in the message. For Windows EXE files, state whether they were run in Wine ONLY as the inspect_uploaded_file result states it (a Wine run, or static-only). Never claim a Wine run that the result does not mention, and never call a file clean or safe just because a short Wine run showed nothing: it is partial coverage, not a Windows VM. To check whether an npm/PyPI package, GitHub repo, script or shell command (e.g. curl ... | bash) is safe, call inspect_package once with kind npm, pip, github or command (never run installs yourself). Its verdict is computed by code: repeat it exactly, never soften or upgrade it, and note that a clean result is not a guarantee. The report file is attached automatically; do not call write_report after it. REPORTS: when the user asks for research, a comparison, an analysis or a report, work efficiently (at most 3 searches/page reads), do calculations with run_command, then call write_report once with the complete report in the user\'s language, and finish with a short summary pointing to the downloadable file. Write the final answer in the language of the user\'s last message.';

async function post(body) {
  const key = process.env.VULTR_KEY;
  if (!key) throw fail(500, 'Sunucuda VULTR_KEY tanımlı değil (.env).');
  let lastErr = 'Model cevap vermedi.';
  for (let i = 0; i < 2; i++) {
    try {
      const r = await fetch(INFERENCE_URL, {
        method: 'POST',
        headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(60000),
      });
      const raw = await r.text();
      if (!r.ok) {
        lastErr = `Model sağlayıcısı HTTP ${r.status} hatası döndürdü.`;
        if (r.status < 500) throw fail(502, lastErr);
        continue;
      }
      return JSON.parse(raw);
    } catch (e) {
      if (e.status) throw e;
      lastErr = `Model isteği başarısız: ${e.message}`;
    }
  }
  throw fail(502, lastErr);
}

async function chatOnce(system, userContent, extra = {}) {
  const messages = [
    { role: 'system', content: system + EXTRA + langLock(extra.lang) },
    { role: 'user', content: userContent },
  ];
  const log = [];
  let report = null;
  const t0 = Date.now();
  // live status for the UI: {k: think|search|read|run|report|inspect|answer, d: short detail}
  const st = (k, d = '') => { try { extra.onStatus && extra.onStatus({ k, d: String(d).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 90) }); } catch {} };
  const host = (u) => { try { return new URL(u).hostname; } catch { return String(u).slice(0, 60); } };
  for (let step = 0; step <= MAX_STEPS; step++) {
    const useTools = step < MAX_STEPS && (!DEADLINE_MS || Date.now() - t0 < DEADLINE_MS);
    if (!useTools) messages.push({ role: 'user', content: `Do not use any more tools. Write the final answer now from what you have gathered, in ${langName(extra.lang) || 'the language of the user\'s own words'}.` });
    st('think');
    const data = await post({
      model: extra.model || MODEL,
      max_tokens: MAX_TOKENS,
      reasoning_effort: 'minimal',
      messages,
      ...(useTools ? { tools: TOOLS } : {}),
    });
    const msg = data.choices?.[0]?.message;
    if (!msg) throw fail(502, 'Model boş cevap döndürdü.');

    if (useTools && msg.tool_calls?.length) {
      messages.push({ role: 'assistant', content: msg.content || '', tool_calls: msg.tool_calls });
      for (const c of msg.tool_calls) {
        let args = {};
        try { args = JSON.parse(c.function?.arguments || '{}'); } catch {}
        console.log('TOOL', c.function?.name, JSON.stringify(args).slice(0, 200));
        let out;
        if (c.function?.name === 'web_search') {
          const q = String(args.query || '').trim();
          st('search', q);
          log.push(`- 🔎 ${q.slice(0, 100)}`);
          out = q ? await searchWeb(q) : 'Sorgu boş.';
log.push('- ↳ ' + String(out).split(String.fromCharCode(10)).join(' ⏎ ').slice(0, 4000));
        } else if (c.function?.name === 'read_page') {
          const u = String(args.url || '').trim();
          st('read', host(u));
          log.push(`- 📄 ${u.slice(0, 120)}`);
          out = u && extra.readPage ? await extra.readPage(u) : 'URL boş.';
log.push('- ↳ ' + String(out).split(String.fromCharCode(10)).join(' ⏎ ').slice(0, 4000));
        } else if (c.function?.name === 'inspect_uploaded_file') {
          if (report?.inspection) out = 'An inspection already ran in this request; do not start another.';
          else {
            const ids = Array.isArray(args.upload_ids) ? args.upload_ids.slice(0, 5) : [];
            if (!ids.length) out = 'No uploaded file IDs were supplied. Ask the user to upload the file again.';
            else {
              const reports = [], summaries = [];
              for (const uploadId of ids) {
                const upload = await takeUpload(String(uploadId || ''));
                if (!upload) { summaries.push('One uploaded file is missing or expired; ask the user to upload it again.'); continue; }
                try {
                  st('inspect', upload.name);
                  const r = await inspectUploadedFile(upload, { lang: extra.lang === 'tr' ? 'tr' : 'en' });
                  summaries.push(r.summary);
                  if (r.report) reports.push(`## ${upload.name}\n\n${r.report.content}`);
                  if (r.vlog) log.push('- 🧪 ' + JSON.stringify(r.vlog));
                } finally { await deleteUpload(upload); }
              }
              out = summaries.join('\n\n');
              if (reports.length) report = {
                name: 'neora-uploaded-file-inspections.md',
                content: reports.join('\n\n---\n\n'),
                inspection: true,
              };
            }
          }
        } else if (c.function?.name === 'inspect_package') {
          if (report?.inspection) out = 'An inspection already ran in this request; do not start another.';
          else if (DEADLINE_MS && Date.now() - t0 > DEADLINE_MS * 0.4) out = 'Not enough time left for a sandbox inspection in this request. Tell the user to retry with a shorter, single request.';
          else {
            st('inspect', args.kind === 'command' ? 'command' : args.target);
            const r = await inspectTarget(args.kind, args.target, { lang: langName(extra.lang) ? (extra.lang === 'tr' ? 'tr' : 'en') : args.lang });
            out = r.summary;
            if (r.report) report = { ...r.report, inspection: true };
            if (r.vlog) log.push('- 🧪 ' + JSON.stringify(r.vlog));
          }
        } else if (c.function?.name === 'write_report') {
          st('report');
          const r = report?.inspection ? null : makeReport(args.title, args.markdown);
          if (report?.inspection) out = 'The inspection report is already attached; do not write another report.';
          else if (r) { report = r; out = `Report saved as ${r.name} (${r.content.length} chars). Now reply with a short summary and tell the user the file is ready to download.`; }
          else if (!report?.inspection) out = 'Report rejected: markdown missing, too short or malformed. Retry with a shorter, complete report.';
        } else {
          const cmd = String(args.command || '');
          st('run', cmd.replace(/\s+/g, ' '));
          log.push(`- $ ${cmd.replace(/\s+/g, ' ').slice(0, 120)}`);
          out = cmd ? await runInSandbox(cmd, (p) => log.push('- 🛡 ' + JSON.stringify({ p: p.policy, ms: p.durationMs, c: p.containerCleanup, h: String(p.receiptHash).slice(0, 12), s: !!p.signature, x: p.exitCode }))) : 'Komut boş.';
log.push('- ↳ ' + String(out).split(String.fromCharCode(10)).join(' ⏎ ').slice(0, 20000));
        }
        messages.push({ role: 'tool', tool_call_id: c.id, content: String(out).slice(0, 4000) });
      }
      continue;
    }

    let answer = (msg.content || '').trim();
    let reason = data.choices?.[0]?.finish_reason;
    if (!answer) { console.error('BOS CEVAP step', step, JSON.stringify(data).slice(0, 1500)); throw fail(502, 'Model boş cevap döndürdü.'); }
    // Output hit the token limit: ask the model to continue instead of returning a cut-off answer.
    if (reason === 'length') st('answer');
    for (let n = 0; reason === 'length' && n < MAX_CONTINUE; n++) {
      const more = await post({
        model: extra.model || MODEL,
        max_tokens: MAX_TOKENS,
        reasoning_effort: 'minimal',
        messages: [...messages, { role: 'assistant', content: answer }, { role: 'user', content: `Continue exactly where you stopped, in ${langName(extra.lang) || 'the same language'}. Do not repeat anything and do not add a preamble.` }],
      });
      answer += more.choices?.[0]?.message?.content || '';
      reason = more.choices?.[0]?.finish_reason;
    }
    answer = answer.trim();
    return { answer: log.length ? `${answer}\n\n## Tools used\n${log.join('\n')}` : answer, report };
  }
  throw fail(502, 'Model sonuç üretemedi.');
}

export async function chatWithTools(system, userContent, extra = {}) {
  const m = ALLOWED.has(extra.model) ? extra.model : MODEL;
  try {
    return { ...(await chatOnce(system, userContent, { ...extra, model: m })), model: m };
  } catch (e) {
    if (m === MODEL) throw e;
    console.warn('Model basarisiz, varsayilana donuluyor:', m, e.message);
    return { ...(await chatOnce(system, userContent, { ...extra, model: MODEL })), model: MODEL, fallback: m };
  }
}

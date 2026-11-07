/*
 * Neora - connection settings for the AI backend.
 *
 * This is the ONLY file you need to edit to point the site at a different backend
 * or to change the model list. It is loaded by index.html before js/agent.js.
 *
 * IMPORTANT: this file is public. Anyone who opens the site can read it.
 * Never put API keys, tokens or passwords here. Keep secrets on the backend server.
 */
window.NEORA_CONFIG = Object.freeze({

  // Backend endpoint. The site sends POST { url, goal, model, deep } and expects { answer } or { error }.
  //
  // Option A (works as-is over http): the Vultr backend directly.
  // Option B (recommended, required if the site uses https): same-origin path
  //          '/api/analyze' + the nginx proxy block in deploy/nginx.conf (see README.md).
  apiUrl: '/api/analyze',
  // Optional: direct upload to your own backend (bypasses Vercel's 4.5 MB body limit). Needs a CORS block in nginx and the
  // same host in the connect-src of the Content-Security-Policy (vercel.json). Example: 'https://YOUR_BACKEND_HOST/api/upload'
  // Leave empty to upload through the same-origin '/api/upload' proxy.
  uploadUrl: '',
  // Browser-side size limit. The default same-origin proxies cap uploads lower (4 MiB on Vercel, 5 MiB on the bundled nginx),
  // so raise this only together with the proxy limit or when "uploadUrl" points to a direct backend endpoint.
  maxUploadMb: 64,

  // Live-status mode (recommended): start a job, then poll it. Shows what the agent is doing and has no
  // proxy time limit. Remove both lines to use the classic single request instead.
  startUrl: '/api/start',
  jobUrl: '/api/job',

  // How long to wait for the agent before giving up (milliseconds). 0 = no limit.
  requestTimeoutMs: 300000,

  // Models shown in the picker. The FIRST one is the default.
  // "id" is sent to the backend as "model".
  models: [
    { id: 'deepseek-v4.1-flash-1017', name: 'DeepSeek V4.1 Flash', tag: 'Recommended', d: 'Best for agents: fast, with a very large context window' },
    { id: 'glm-5.3-flash',            name: 'GLM 5.3 Flash',       tag: 'Low latency', d: 'Fast, low-latency chat responses' },
    { id: 'glm-5.3',                  name: 'GLM 5.3',                                  d: 'Standard GLM model' },
    { id: 'glm-5.2',                  name: 'GLM 5.2',                                  d: 'Previous GLM release' }
  ],

  // Shown disabled in the picker ("coming soon").
  speechModel: { id: 'granite-speech-5.0-2b', name: 'Granite Speech 5.0 2B', d: 'Speech model for voice input' }
});

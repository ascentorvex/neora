# Neora backend

The backend must run on a dedicated VM/host with Docker Engine available. It binds to `127.0.0.1:3000` by default and requires `PROXY_SECRET` on every `/api/analyze` request. Keep port 3000 private and expose the app only through the frontend proxy.

## Setup

```bash
npm ci
cp .env.example .env
openssl rand -hex 32
# Set VULTR_KEY, PROXY_SECRET, AUDIT_HMAC_KEY and FETCHER_DIR in .env
node --env-file=.env server.mjs
```

`PROXY_SECRET` must be the same random value configured in the frontend proxy. Never commit `.env`.

The fetcher container needs outbound internet access. It validates all DNS answers and pins the HTTP(S) connection to a validated IP for each request and redirect; keep host-level egress filtering enabled to block private, loopback, link-local and cloud metadata ranges as defense in depth. The sandbox runner mounts `sandbox/runner.py` read-only and executes a restricted Python AST subset; imports, attributes, file/process APIs and arbitrary shell commands are denied. Each run emits a SHA-256 audit receipt. Set `AUDIT_HMAC_KEY` to a separate random value of at least 32 bytes to HMAC-sign the receipt; receipts are written to the server log as `AUDIT {json}` lines (not sent to the model, which saves tokens) and are not yet persisted in an append-only ledger. Docker daemon access is highly privileged; do not mount the Docker socket into an untrusted/public container.

## Sandbox inspector (blast radius zero)
`inspect_package` tests an npm package or public GitHub repo. Stage 1: a throwaway container downloads it with install scripts disabled. Stage 2: a second one-time container (no network, read-only, all capabilities dropped, non-root, CPU/memory/pid limits) runs its install scripts and imports it with a behavior hook, with fake credentials planted as honeypots. The verdict (unsafe / suspicious / looks safe / incomplete) is computed by code from the observed behavior, never by the model. Both containers and the temp files are destroyed afterwards and a containment receipt is added to the downloadable report.

### Deeper inspection (multi-runtime)
Kinds: `npm`, `pip` (PyPI), `github`, `command` (a pasted shell one-liner). The detonation container (`probe/Dockerfile`: node + python3 + sh) executes many entry points: npm lifecycle scripts, package import, CLI `bin` entries and root/scripts files; Python `setup.py`, package imports and scripts (PEP 578 audit hook); shell scripts with `sh -x` tracing; or the pasted command. Honeypot secrets (SSH/AWS/npm/git/kube/docker/wallet/browser files + env vars) reveal theft; shims log curl/wget/nc/ssh/sudo/apt/pip/npm calls. Static rules also scan strings inside executables (.exe/.dll/.so/ELF) and many languages (PowerShell, PHP, Python, C, batch...), so destructive Windows trojan patterns (raw disk/MBR access, shadow-copy deletion) are caught even when they cannot be run. Optional hardening: set `SANDBOX_RUNTIME=runsc` (gVisor) in `.env`.


## User-uploaded file inspection

The chat attachment control now uploads raw bytes to `POST /api/upload`. The backend accepts up to 64 MB per file (the proxy in front of it may allow less, see below). The backend assigns an unguessable 128-bit ID, stores the file with mode 0600 under the OS temp directory, and expires unclaimed uploads after 30 minutes. When the user asks whether an attachment is safe, the model calls `inspect_uploaded_file`; the file is mounted read-only into a fresh `neora-det:1` container with no network, no capabilities, non-root execution, memory/CPU/PID limits and a read-only root filesystem. The container and temporary working copy are removed after analysis. Uploads are single-use and deleted after inspection.

**Important platform limit:** the bundled detonation image is Linux. Windows PE files are always inspected statically first (headers, strings, embedded archives and rules). A top-level `.exe`, `.scr`, `.com` or `.pif` is additionally run for a short observation window in an offline Wine container (`neora-wine:1`, see [`WINE-INTEGRATION.md`](WINE-INTEGRATION.md)) when that image has been built on the host; if it is missing, the report says so and keeps the static result. Wine is not a Windows VM, so a Wine run is always reported as **partial** coverage, never "clean". A genuine Windows runtime verdict still requires a separate Windows VM worker with snapshot rollback, disabled/controlled egress, no host/shared credentials, and an external controller.

Upload size limits depend on the path in front of the backend: the backend itself accepts up to 64 MB, self-hosted nginx (`client_max_body_size`) is set to 5 MiB, and on Vercel `api/upload.js` caps uploads at 4 MiB to stay below serverless request-body limits. The browser limit is `maxUploadMb` in `frontend/config/neora.config.js`. To allow larger files, raise the proxy limit and `maxUploadMb` together (or set `uploadUrl` to a direct backend endpoint) and consider streaming storage. Upload IDs are in-memory and are invalidated by a backend restart; this is intentional short-lived storage, not durable file hosting.


### Uploaded-file dynamic analysis runtimes

The one-shot offline detonation image supports Node.js, Python 3, POSIX shell, Ruby, PHP CLI, Perl and Lua scripts. For each supported language, up to six obvious top-level, `scripts/`, or `bin/` entry-point files are executed under the existing container limits. This is behavioral sampling, not a guarantee that every code path runs.

Windows DLL/MSI files, PowerShell, batch/VBS, Java/JAR, .NET, native ELF/Mach-O binaries, Android packages, and compiled Go/Rust/C/C++/C#/Swift programs remain static-only in this Linux worker. Top-level `.exe`/`.scr`/`.com`/`.pif` files get the extra partial Wine run described above. Never run any of these on the host itself; real Windows behavior analysis requires a disposable Windows VM with snapshot rollback.

The upload size is limited by the proxy in the browser-to-proxy-to-backend path (4 MiB on Vercel, 5 MiB on the bundled nginx config). The server stores uploads under a random ID in a private temporary directory, and the inspection tool claims each ID once. This repository cannot prove that a particular production host or Vercel deployment is reachable; verify with the deployment smoke test and an actual upload after deploying.

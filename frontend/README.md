# Neora frontend

The canonical frontend lives in this directory. For architecture, secure setup, proxy authentication, deployment and verification instructions, see the repository root [`README.md`](../README.md).

Never put `VULTR_KEY` or `PROXY_SECRET` in `config/neora.config.js` or any browser-delivered file. Configure proxy secrets only as server environment variables or server-only Nginx includes.


File attachments are uploaded to the backend and can be inspected through the one-time offline sandbox. The effective size limit is set by the proxy: 4 MiB on Vercel (`api/upload.js`), 5 MiB with the bundled nginx config. The browser-side limit is `maxUploadMb` in `config/neora.config.js`. Windows EXE files get static analysis plus a short, partial run in an offline Wine container when the backend has the Wine image; DLL files are static-only.


Dynamic script execution inside the one-time offline sandbox is supported for Node.js, Python 3, POSIX shell, Ruby, PHP CLI, Perl and Lua. Other compiled/platform-specific binaries are statically inspected only, and Windows `.exe` runs under Wine are always reported as partial coverage; use a disposable Windows VM worker for real Windows detonation.

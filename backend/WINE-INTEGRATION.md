# Wine runtime integration

Static inspection always runs first and is never replaced. A top-level upload ending in `.exe`, `.scr`, `.com` or `.pif`
is additionally run in a fresh, offline Wine container (`neora-wine:1`).

## Install (once, on the server)
```bash
cd backend && bash deploy/build-wine.sh   # builds the image and runs a smoke test
npm test && systemctl restart neora-backend
```
The backend never builds or pulls the image; if it is missing the report says so and keeps the static result.

## What happens per run
1. `docker run` with: no network, read-only root, uid 65534, all caps dropped, no-new-privileges, 3 GiB RAM, 1 CPU, 512 pids,
   sample mounted read-only at `/work`.
2. `neora-wine-run` copies the pristine prefix to `/tmp/wp`, removes the `z:` drive (container filesystem is hidden), copies the
   sample to `C:\sample`, starts Xvfb and runs the sample under `strace -f` for `NEORA_WINE_RUN_S` seconds (default 30), then
   kills everything.
3. Evidence printed by the script: network attempts (connect/sendto), spawned Windows processes, registry changes (Run keys =
   persistence), new files in `C:` (Startup folder = persistence), stdout/stderr tail. A secret per-run nonce marks sections so
   the sample cannot forge them.
4. `wine-evidence.mjs` converts that to events; `verdict.mjs` classifies them as for any other target.

## Honest limits
- Wine is not a Windows VM: no full API/registry/process-tree instrumentation. A Wine run is always reported as PARTIAL, never "clean".
- The network is off, so only the *attempt* to connect is visible (not what would have been downloaded).
- .NET programs fail (mono is disabled on purpose); DLL/SYS/MSI and executables inside archives stay static-only.
- If `strace` is blocked by the runtime (e.g. gVisor) the report notes `trace=0`; registry/file evidence still works.
- The observation window (default 30 s) means malware that sleeps longer is not seen doing anything.

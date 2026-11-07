# Auto-loaded by every python process of the detonation run (PYTHONPATH). Observes only, never blocks.
import os, sys, re, json
_EV = os.environ.get("NEORA_EVENTS"); _PH = os.environ.get("NEORA_PHASE", "")
if _EV:
    _seen = set(); _busy = [False]; _quiet = [0]; _n = [0]
    _HOME = os.environ.get("HOME", "")
    _SENS = re.compile(r"(\.ssh|\.aws|\.npmrc|\.git-credentials|(^|/)\.env(\.|$)|id_rsa|id_ed25519|\.kube|\.docker|\.gnupg|/etc/(passwd|shadow)|\.netrc|wallet|Login Data|\.bash_history|\.config/gcloud|\.solana|\.ethereum|keystore)", re.I)
    _PERSIST = re.compile(r"(\.bashrc|\.zshrc|\.profile|\.bash_profile|crontab|/cron\.|authorized_keys|/etc/|\.config/autostart|/systemd/|\.git/hooks|LaunchAgents|/Startup/)", re.I)
    _SENS_ENV = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|AWS_|GITHUB|GH_|NPM_|CREDENTIAL|PRIVATE|SESSION|COOKIE)", re.I)
    _real_open = open
    def _log(t, d):
        if _busy[0]: return
        _busy[0] = True
        try:
            d = re.sub(r"[^\x20-\x7e]", "?", str(d))[:200]
            k = t + "|" + d
            if k in _seen or _n[0] >= 300: return
            _seen.add(k); _n[0] += 1
            with _real_open(_EV, "a") as f: f.write(json.dumps({"t": t, "d": d, "ph": _PH}) + "\n")
        except Exception: pass
        finally: _busy[0] = False
    def _hook(event, args):
        try:
            if event == "open":
                p = args[0]
                if isinstance(p, bytes): p = p.decode("latin1")
                if isinstance(p, str) and p:
                    mode = str(args[1]) if len(args) > 1 else ""
                    write = any(c in mode for c in "wax+") or (len(args) > 2 and isinstance(args[2], int) and args[2] & 0o3)
                    home = "[home] " if _HOME and p.startswith(_HOME) else ""
                    if write and _PERSIST.search(p): _log("fs.persist", "open " + p)
                    elif _SENS.search(p): _log("fs.sensitive", home + "open " + p)
            elif event == "socket.connect": _log("net.connect", args[1])
            elif event in ("socket.getaddrinfo", "socket.gethostbyname"): _log("dns.lookup", args[0] if args else "")
            elif event == "subprocess.Popen": _log("proc.spawn", "Popen " + str(args[0]) + " " + " ".join(map(str, args[1][1:] if args[1] else [])))
            elif event == "os.system": _log("proc.spawn", "system " + str(args[0]))
            elif event in ("os.exec", "os.posix_spawn", "os.spawn"): _log("proc.spawn", event + " " + str(args[0]))
            elif event == "exec": _log("dyn.exec", "exec of dynamically built code")
            elif event == "ctypes.dlopen": _log("dyn.exec", "ctypes.dlopen " + str(args[0]))
        except Exception: pass
    sys.addaudithook(_hook)
    try:
        _E = os._Environ; _g = _E.__getitem__; _it = _E.__iter__
        def _get(self, k):
            if isinstance(k, str) and _SENS_ENV.search(k):
                try:
                    if self.encodekey(k) in self._data: _log("env.read", k)
                except Exception: pass
            return _g(self, k)
        def _iter(self): _log("env.enumerate", "all"); return _it(self)
        _E.__getitem__ = _get; _E.__iter__ = _iter
    except Exception: pass

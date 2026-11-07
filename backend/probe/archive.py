#!/usr/bin/env python3
"""Read-only archive lister for the detonation container.

Usage: archive.py <path>
Prints ONE JSON document: {"kind", "members": [{"n": name, "size": int, "b64": base64|None}], "skipped": int,
"encrypted": bool, "error": str|None}.

Nothing is ever extracted to disk and nothing is executed: members are read into memory with hard caps
(member count, bytes per member, total bytes), so zip bombs cannot blow up memory.
"""
import base64
import bz2
import gzip
import json
import lzma
import os
import sys
import tarfile
import zipfile

MAX_MEMBERS = 400
MAX_MEMBER = 4 * 1024 * 1024
MAX_TOTAL = 24 * 1024 * 1024
# members whose content is never interesting (still listed by name so double extensions etc. are seen)
SKIP_DATA = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".otf", ".eot",
             ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".avi", ".mov", ".svgz")


def main():
    path = sys.argv[1]
    res = {"kind": None, "members": [], "skipped": 0, "encrypted": False, "error": None}
    total = 0

    def add(name, size, reader):
        nonlocal total
        if len(res["members"]) >= MAX_MEMBERS or total >= MAX_TOTAL:
            res["skipped"] += 1
            return
        low = name.lower()
        if low.endswith(SKIP_DATA):
            res["members"].append({"n": name[:200], "size": size, "b64": None})
            return
        try:
            data = reader()
        except Exception:
            res["skipped"] += 1
            return
        total += len(data)
        res["members"].append({"n": name[:200], "size": size, "b64": base64.b64encode(data).decode("ascii")})

    try:
        if zipfile.is_zipfile(path):
            res["kind"] = "zip"
            with zipfile.ZipFile(path) as zf:
                for m in zf.infolist():
                    if m.is_dir():
                        continue
                    if m.flag_bits & 0x1:  # encrypted member: contents are hidden from us
                        res["encrypted"] = True
                        res["skipped"] += 1
                        continue
                    add(m.filename, m.file_size, lambda m=m: zf.open(m).read(MAX_MEMBER))
        else:
            tf = None
            try:
                tf = tarfile.open(path, "r:*")
            except Exception:
                tf = None
            if tf is not None:
                res["kind"] = "tar"
                with tf:
                    for m in tf:
                        if not m.isfile():
                            continue
                        add(m.name, m.size, lambda m=m: tf.extractfile(m).read(MAX_MEMBER))
            else:
                # single compressed stream (foo.js.gz, foo.sh.xz ...)
                opener = None
                for mod in (gzip, bz2, lzma):
                    try:
                        with mod.open(path, "rb") as f:
                            f.read(1)
                        opener = mod
                        break
                    except Exception:
                        continue
                if opener is None:
                    res["error"] = "not a supported archive"
                else:
                    res["kind"] = "stream"
                    base = os.path.basename(path)
                    inner = base.rsplit(".", 1)[0] if "." in base else base
                    add(inner, 0, lambda: opener.open(path, "rb").read(MAX_MEMBER))
    except Exception as e:  # corrupt / truncated archive
        res["error"] = (type(e).__name__ + ": " + str(e))[:120]
    sys.stdout.write(json.dumps(res))


main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Someone-anon-coder
"""Write the SHA-256 of every app file into sw.js and derive the cache name from them.
Run after changing any file the app serves, then commit."""
import hashlib, json, os, re

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
FILES = [
    "index.html", "app.css", "app.js", "core.js", "worker.js",
    "vendor/argon2.umd.min.js", "manifest.webmanifest",
    "icons/icon.svg", "icons/icon-180.png", "icons/icon-192.png", "icons/icon-512.png", "icons/icon-maskable-512.png",
]
hashes = {f: hashlib.sha256(open(os.path.join(ROOT, f), "rb").read()).hexdigest() for f in FILES}
version = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()[:12]
block = f'const CACHE = "keyforge-{version}";\nconst HASHES = {json.dumps(hashes, indent=2)};\n'
sw = os.path.join(ROOT, "sw.js")
src = open(sw, encoding="utf-8").read()
src = re.sub(r"(// STAMP-BEGIN\n).*?(// STAMP-END)", lambda m: m[1] + block + m[2], src, flags=re.S)
open(sw, "w", encoding="utf-8").write(src)
print("stamped", len(hashes), "files, cache", f"keyforge-{version}")

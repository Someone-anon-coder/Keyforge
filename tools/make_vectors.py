#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Someone-anon-coder
"""Regenerate tests/vectors.json from the independent Python implementation."""
import json, os, sys
sys.path.insert(0, os.path.dirname(__file__))
from reference import master_key, password, fingerprint, norm_site_v2, PLAIN, WILDCARDS, EXCEPTIONS
from site_cases import CASES as SITE_CASES

IDS = [("Aayush", "correct horse battery staple"), ("Zoë Ñúñez", "pässwörd 🔑"), ("a", "x")]
CASES = [
    dict(site="github.com"), dict(site="https://www.GitHub.com/login?x=1"), dict(site="github.com", counter=2),
    dict(site="github.com", login="Aayush@Example.com"), dict(site="bank.example", length=6, classes=["digits"]),
    dict(site="old-site.in", length=16, classes=["lower", "upper", "digits"]), dict(site="x.y", length=4),
    dict(site="long.example", length=64), dict(site="sym.example", length=8, classes=["symbols"]),
    dict(site="max.example", counter=4294967295),
    dict(site="short.example", length=8), dict(site="mid.example", length=12), dict(site="mid.example", length=15),
    dict(site="mid.example", length=24), dict(site="mid.example", length=12, classes=["lower", "digits"]),
]
out = []
for name, secret in IDS:
    mk = master_key(name, secret)
    vecs = []
    for c in CASES:
        c = {"login": "", "counter": 1, "length": 20, "classes": ["lower", "upper", "digits", "symbols"], **c}
        vecs.append({**c, "password": password(mk, c["site"], c["login"], c["counter"], c["length"], c["classes"])})
    out.append({"name": name, "secret": secret, "masterKeyHex": mk.hex(), "fingerprint": fingerprint(mk), "cases": vecs})
json.dump(out, open(os.path.join(os.path.dirname(__file__), "..", "tests", "vectors.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
# Differential fuzz corpus: random nasty strings with Python's normalisation, checked against JS by the tests.
import random, unicodedata
from reference import norm_site, norm_name, norm_login
r = random.Random(7)
pieces = list("abcxyzABCXYZ0189:/?#\\@.-_ ") + ["xn--", "xn--bcher-kva", "www.", "https://", "HTTP://", "\u00fc", "\u03a3", "\u03c2", "\u00df", "\u0130", "\uff47", "\uff1a", "\uff0f", "\u0663", "\u00a0", "\u3000", "\ufeff", "\x1c", "\u200b", "\t", "e\u0301", "\u00e9", "\ufb01", "\u2168", "xn--zz", "--", "\U0001F600"]
FUZZ = os.path.join(os.path.dirname(__file__), "..", "tests", "normalize-fuzz.json")
LEGACY_ROWS = 20000
if os.path.exists(FUZZ):
    # The first 20,000 rows are frozen. Regenerating them depends on the Unicode database of the
    # Python running this script, so a different Python would silently change them. Keep them.
    fz = json.load(open(FUZZ, encoding="utf-8"))[:LEGACY_ROWS]
else:
    cps = [c for c in range(0x80, 0x3000) if unicodedata.category(chr(c)) not in ("Cn", "Cs")]
    fz = []
    for _ in range(20000):
        s_ = "".join(r.choice(pieces) if r.random() < .85 else chr(r.choice(cps)) for _ in range(r.randint(0, 10)))
        fz.append([s_, norm_site(s_), norm_name(s_), norm_login(s_)])
# Hosts built from real PSL rules (wildcards filled in, exceptions, deep subdomains, decorations),
# plus the hand-written cases. These rows have a fifth column, the algorithm v2 site; the 20,000
# random rows before them stay as they were (four columns) and are only checked for v1.
r2 = random.Random(11)
rules = sorted(PLAIN | {"*." + w for w in WILDCARDS} | EXCEPTIONS)
extra = ["www", "mail", "a", "b", "login", "xn--bcher-kva", "bücher", "ＧＯＯＧＬＥ", "app", "co", "com", "1", "x-y"]
for _ in range(8000):
    rule = r2.choice(rules)
    host = ".".join(r2.choice(extra) for _ in range(r2.randint(0, 3)) ) + "." + rule.replace("*", r2.choice(extra))
    host = host.strip(".")
    if r2.random() < .3: host = r2.choice(["https://", "HTTP://user@", ""]) + host + r2.choice(["", "/", ":8443/p?q#f", "."])
    if r2.random() < .1: host = host.upper()
    fz.append([host, norm_site(host), norm_name(host), norm_login(host), norm_site_v2(host)])
sites = []
for group, inp, want, want_full in SITE_CASES:
    got, got_full = norm_site_v2(inp), norm_site_v2(inp, True)
    assert (got, got_full) == (want, want_full), (inp, got, got_full, want, want_full)
    fz.append([inp, norm_site(inp), norm_name(inp), norm_login(inp), got])
    sites.append({"group": group, "input": inp, "site": want, "fullHost": want_full})
json.dump(sites, open(os.path.join(os.path.dirname(__file__), "..", "tests", "sites-v2.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
json.dump(fz, open(os.path.join(os.path.dirname(__file__), "..", "tests", "normalize-fuzz.json"), "w", encoding="utf-8"), ensure_ascii=True)
print("wrote", sum(len(o["cases"]) for o in out), "vectors")

# Algorithm v2 vectors. The master keys are the v1 ones (same unlock), only the site rule and domain differ.
from reference import password_v2
V2_EXTRA = [dict(site="github.com", counter=2), dict(site="accounts.google.com", login="Aayush@Example.com"),
            dict(site="acme.atlassian.net", full_host=True), dict(site="bank.example", length=6, classes=["digits"]),
            dict(site="old-site.in", length=16, classes=["lower", "upper", "digits"]), dict(site="max.example", counter=4294967295)]
out2 = []
for name, secret in IDS:
    mk = master_key(name, secret)
    sites_ = [dict(site=inp) for _, inp, _, _ in SITE_CASES] if name == IDS[0][0] else []
    sites_ += [dict(site=inp, full_host=True) for _, inp, _, _ in SITE_CASES[:12]] if name == IDS[0][0] else []
    vecs = []
    for c in sites_ + V2_EXTRA:
        c = {"login": "", "counter": 1, "length": 20, "classes": ["lower", "upper", "digits", "symbols"], "full_host": False, **c}
        vecs.append({"site": c["site"], "fullHost": c["full_host"], "login": c["login"], "counter": c["counter"], "length": c["length"],
                     "classes": c["classes"], "password": password_v2(mk, c["site"], c["login"], c["counter"], c["length"], c["classes"], c["full_host"])})
    out2.append({"name": name, "secret": secret, "cases": vecs})
json.dump(out2, open(os.path.join(os.path.dirname(__file__), "..", "tests", "vectors-v2.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("wrote", sum(len(o["cases"]) for o in out2), "v2 vectors")

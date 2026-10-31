#!/usr/bin/env python3
"""Regenerate tests/vectors.json from the independent Python implementation."""
import json, os, sys
sys.path.insert(0, os.path.dirname(__file__))
from reference import master_key, password, fingerprint

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
cps = [c for c in range(0x80, 0x3000) if unicodedata.category(chr(c)) not in ("Cn", "Cs")]
fz = []
for _ in range(20000):
    s_ = "".join(r.choice(pieces) if r.random() < .85 else chr(r.choice(cps)) for _ in range(r.randint(0, 10)))
    fz.append([s_, norm_site(s_), norm_name(s_), norm_login(s_)])
json.dump(fz, open(os.path.join(os.path.dirname(__file__), "..", "tests", "normalize-fuzz.json"), "w", encoding="utf-8"), ensure_ascii=True)
print("wrote", sum(len(o["cases"]) for o in out), "vectors")

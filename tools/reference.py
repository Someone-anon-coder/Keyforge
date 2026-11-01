#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Someone-anon-coder
"""Independent Python implementation of Keyforge algorithms v1 and v2 (see ALGORITHM.md).

It shares no code with the web app, so it serves two purposes:
  * the test suite checks both implementations agree;
  * if the web app is ever lost, this file plus `pip install argon2-cffi`
    regenerates every password.

Usage:
  python3 reference.py --name NAME --site github.com [--login USER] [--counter 1]
                       [--length 20] [--classes lower,upper,digits,symbols]
                       [--algo 1|2] [--full-host]          (--full-host only applies to v2)
The master secret is read from a hidden prompt (or KEYFORGE_SECRET for tests).
"""
import argparse, getpass, hashlib, hmac, os, re, struct, sys, unicodedata

from argon2.low_level import Type, hash_secret_raw

DOMAIN = "keyforge.v1"
CLASSES = {
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "digits": "0123456789",
    "symbols": "!#$%&*+-=?@^_",
}
ORDER = ["lower", "upper", "digits", "symbols"]
CODE = {"lower": "a", "upper": "A", "digits": "9", "symbols": "#"}


def enc(s: str) -> bytes:
    return unicodedata.normalize("NFC", s).encode("utf-8")


def lp(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def lps(s: str) -> bytes:
    return lp(enc(s))


def norm_name(s): return trim(unicodedata.normalize("NFKC", s))
def norm_login(s): return trim(unicodedata.normalize("NFKC", s or "")).lower()


def _adapt(delta, num, first):
    delta = delta // 700 if first else delta >> 1
    delta += delta // num
    k = 0
    while delta > ((36 - 1) * 26) >> 1:
        delta //= 35; k += 36
    return k + (36 * delta) // (delta + 38)


def puny_decode(inp):
    """RFC 3492 decode, mirroring core.js exactly. None if invalid."""
    n, i, bias, out = 128, 0, 72, []
    b = max(inp.rfind("-"), 0)
    for ch in inp[:b]:
        if ord(ch) >= 0x80: return None
        out.append(ord(ch))
    idx = b + 1 if b > 0 else 0
    while idx < len(inp):
        oldi, w, k = i, 1, 36
        while True:
            if idx >= len(inp): return None
            c = ord(inp[idx]); idx += 1
            d = c - 22 if 48 <= c <= 57 else c - 97 if 97 <= c <= 122 else c - 65 if 65 <= c <= 90 else 36
            if d >= 36: return None
            i += d * w
            t = 1 if k <= bias else 26 if k >= bias + 26 else k - bias
            if d < t: break
            w *= 36 - t
            if w > 0x7FFFFFFF: return None
            k += 36
        ln = len(out) + 1
        bias = _adapt(i - oldi, ln, oldi == 0)
        n += i // ln; i %= ln
        if n > 0x10FFFF or 0xD800 <= n <= 0xDFFF: return None
        out.insert(i, n); i += 1
    return "".join(map(chr, out))


def _label(l):
    if not l.startswith("xn--"): return l
    d = puny_decode(l[4:])
    return l if d is None else d


# Exactly the characters JavaScript's String.prototype.trim() removes.
WS = "\t\n\v\f\r \u00a0\u1680" + "".join(map(chr, range(0x2000, 0x200B))) + "\u2028\u2029\u202f\u205f\u3000\ufeff"
def trim(s): return s.strip(WS)


def norm_site(s):
    s = trim(unicodedata.normalize("NFKC", s)).lower()
    s = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", s)
    s = re.split(r"[/?#\\]", s)[0]
    s = s[s.rfind("@") + 1:]
    s = re.sub(r":[0-9]*$", "", s)
    s = re.sub(r"\.+$", "", s)
    s = ".".join(_label(l) for l in s.split("."))
    s = unicodedata.normalize("NFKC", s).lower()
    return s[4:] if s.startswith("www.") else s


def master_key(name: str, secret: str) -> bytes:
    salt = hashlib.sha256(lps(DOMAIN + ".salt") + lps(norm_name(name))).digest()
    return hash_secret_raw(enc(secret), salt, time_cost=3, memory_cost=65536,
                           parallelism=1, hash_len=32, type=Type.ID)


def H(key, msg): return hmac.new(key, msg, hashlib.sha256).digest()


class Stream:
    def __init__(self, key): self.key, self.block, self.buf = key, 0, b""

    def byte(self):
        if not self.buf:
            self.buf = H(self.key, struct.pack(">I", self.block)); self.block += 1
        b, self.buf = self.buf[0], self.buf[1:]
        return b

    def below(self, n):
        limit = 256 - (256 % n)
        while True:
            b = self.byte()
            if b < limit:
                return b % n


def password(mk, site, login="", counter=1, length=20, classes=ORDER, _v2=None):
    """_v2=None is algorithm v1; _v2=False/True is algorithm v2 without/with the full-host switch."""
    classes = [c for c in ORDER if c in classes]
    code = f"L{length}:" + "".join(CODE[c] for c in classes)
    domain, site_str = (DOMAIN, norm_site(site)) if _v2 is None else (DOMAIN2, norm_site_v2(site, _v2))
    msg = (lps(domain + ".site") + lps("password") + lps(site_str)
           + lps(norm_login(login)) + struct.pack(">I", counter) + lps(code))
    st = Stream(H(mk, msg))
    chars = [CLASSES[c][st.below(len(CLASSES[c]))] for c in classes]
    alphabet = "".join(CLASSES[c] for c in classes)
    while len(chars) < length:
        chars.append(alphabet[st.below(len(alphabet))])
    for i in range(length - 1, 0, -1):
        j = st.below(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


# ---- Algorithm v2 ----------------------------------------------------------------------
# Same master key and byte stream as v1. Only the site string and the site-key domain differ.
DOMAIN2 = "keyforge.v2"
PSL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "psl.js")


def load_psl(path=PSL_FILE):
    """The frozen snapshot is the rules text inside psl.js (the same file the web app imports)."""
    src = open(path, encoding="utf-8").read()
    rules = src.split("export const PSL_RULES = `\n", 1)[1].split("\n`;", 1)[0].split("\n")
    assert hashlib.sha256("\n".join(rules).encode("utf-8")).hexdigest() == re.search(r'PSL_SHA256 = "(\w+)"', src)[1]
    return (frozenset(r[1:] for r in rules if r.startswith("!")),
            frozenset(r[2:] for r in rules if r.startswith("*.")),
            frozenset(r for r in rules if r and r[0] != "!" and not r.startswith("*.")))


EXCEPTIONS, WILDCARDS, PLAIN = load_psl()


def suffix_length(labels):
    n = len(labels)
    for i in range(n):
        if ".".join(labels[i:]) in EXCEPTIONS:
            return n - i - 1
    for i in range(n):
        if ".".join(labels[i:]) in PLAIN or (i + 1 < n and ".".join(labels[i + 1:]) in WILDCARDS):
            return n - i
    return 1


def registrable(host):
    if re.search(r"[:\[\]]", host):
        return host
    labels = host.split(".")
    if "" in labels or re.fullmatch(r"[0-9]+", labels[-1]):
        return host
    n, k = len(labels), suffix_length(labels)
    return ".".join(labels[n - k - 1:]) if n > k else host


def norm_site_v2(s, full_host=False):
    h = norm_site(s)
    return h if full_host else registrable(h)


def password_v2(mk, site, login="", counter=1, length=20, classes=ORDER, full_host=False):
    return password(mk, site, login, counter, length, classes, _v2=full_host)


WORDS_FILE = os.path.join(os.path.dirname(__file__), "..", "core.js")


def fingerprint(mk):
    src = open(WORDS_FILE, encoding="utf-8").read()
    words = re.findall(r'"([a-z]+)"', src[src.index("WORDS = Object.freeze(["):])
    h = H(mk, lps(DOMAIN + ".fingerprint"))
    return [words[h[0]], words[h[1]], words[h[2]]]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--site", required=True)
    ap.add_argument("--login", default="")
    ap.add_argument("--counter", type=int, default=1)
    ap.add_argument("--length", type=int, default=20)
    ap.add_argument("--classes", default="lower,upper,digits,symbols")
    ap.add_argument("--algo", type=int, choices=(1, 2), default=2)
    ap.add_argument("--full-host", action="store_true", help="v2: keep the whole host instead of the registrable domain")
    a = ap.parse_args()
    secret = os.environ.get("KEYFORGE_SECRET") or getpass.getpass("Master secret: ")
    mk = master_key(a.name, secret)
    print("fingerprint:", " ".join(fingerprint(mk)), file=sys.stderr)
    v2 = None if a.algo == 1 else a.full_host
    print(password(mk, a.site, a.login, a.counter, a.length, a.classes.split(","), _v2=v2))

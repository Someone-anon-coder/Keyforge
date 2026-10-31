# Keyforge algorithm, version 1

This spec is the real backup. With it (or `tools/reference.py`) and your inputs, every password can be rebuilt without the app. **Do not change anything in v1 once you use it for real accounts.** Any change becomes v2 with a new domain string, and v1 stays in the code so old passwords still work.

## Notation

- `enc(s)`: the UTF-8 bytes of `s` after Unicode NFC normalisation.
- `u32(n)`: `n` as 4 bytes, big-endian.
- `lp(b)`: `u32(len(b)) || b`. A length-prefixed field, so no two different inputs can produce the same byte string.
- `lps(s)`: `lp(enc(s))`.
- `HMAC(k, m)`: HMAC-SHA256 (32 bytes).
- `DOMAIN = "keyforge.v1"`

## 1. Normalising inputs

| Input | Rule |
|---|---|
"Trim" means removing exactly the characters JavaScript's `String.prototype.trim()` removes. No URL parser is used, because URL parsers differ between languages and browsers (tested: they disagree on international domains, backslashes and IP shorthands).

| Input | Rule |
|---|---|
| name | NFKC, trim. **Case-sensitive.** |
| master secret | NFC only. Not trimmed, case-sensitive. |
| site | In order: NFKC, trim, lowercase; remove a leading `scheme://` (matching `^[a-z][a-z0-9+.-]*://`); cut at the first `/` `?` `#` or `\`; keep only what follows the last `@`; remove a trailing `:digits` (ASCII 0–9) and trailing dots; decode each `xn--` label with RFC 3492 Punycode (leave it as is if invalid); NFKC and lowercase again; drop one leading `www.`. |
| login | NFKC, trim, lowercase. Empty string if unused. |
| counter | Integer, 1 to 4294967295. Default 1. |

The result is that `https://user@www.Bücher.de:443/x`, `bücher.de` and `xn--bcher-kva.de` all give the same password, and so do full-width letters like `ｇｉｔｈｕｂ.com` and `github.com`. NFKC and lowercasing follow the Unicode version of the browser. A few dozen characters added in Unicode 16–17 (obscure scripts) can come out differently on older devices, so keep names, sites and logins to ordinary characters.

## 2. Master key (once per unlock)

```
salt      = SHA-256( lps(DOMAIN + ".salt") || lps(name) )          32 bytes
masterKey = Argon2id(password = enc(secret), salt,
                     t = 3, m = 65536 KiB (64 MiB), p = 1, len = 32)  (Argon2 v1.3 / 0x13)
```

The parameters follow RFC 9106's second recommended option, but with p = 1 because browser WASM runs single-threaded. Measured times: about 0.3 s in Node and about 0.35 s in desktop Chromium. Expect about 1 s on a mid-range phone.

## 3. Site key

```
template  = "L" + length + ":" + codes      codes in fixed order: a (lower) A (upper) 9 (digits) # (symbols)
                                            e.g. "L20:aA9#", "L6:9"
siteKey   = HMAC(masterKey, lps(DOMAIN + ".site") || lps("password") || lps(site)
                            || lps(login) || u32(counter) || lps(template))
```

Because the template is part of the input, changing the length or the character set gives an unrelated password, not a longer or shorter version of the same one.

## 4. Turning the site key into characters

Byte stream: `HMAC(siteKey, u32(0)) || HMAC(siteKey, u32(1)) || ...`, read one byte at a time.

`below(n)` is an unbiased integer in `[0, n)`: read a byte `b`; if `b < 256 − (256 mod n)`, return `b mod n`, otherwise discard it and read the next byte.

Character classes:

```
lower   abcdefghijklmnopqrstuvwxyz        (26)
upper   ABCDEFGHIJKLMNOPQRSTUVWXYZ        (26)
digits  0123456789                        (10)
symbols !#$%&*+-=?@^_                     (13)  no quotes, backslash, space or brackets
```

For a template with the selected classes `C1..Ck` (in the fixed order above) and length `L` (4–64, `L ≥ k`):

1. For each selected class in order, append `class[below(len(class))]`. This guarantees one character of each kind.
2. Let `A` be the selected classes joined in order. While fewer than `L` characters, append `A[below(len(A))]`.
3. Fisher–Yates shuffle: for `i = L−1` down to `1`, `j = below(i+1)`, swap positions `i` and `j`.

## 5. Fingerprint

```
h     = HMAC(masterKey, lps(DOMAIN + ".fingerprint"))
words = WORDS[h[0]], WORDS[h[1]], WORDS[h[2]]        (256-word list in core.js, order fixed)
cuts  = the same 24 bits as eight 3-bit values, most significant first (drawn as the key's teeth)
```

This catches a mistyped name or secret. It shows only 24 bits about the key, which is far too little to help an attacker.

## Strength

The app offers lengths 8, 12, 15, 20 (default) and 24, plus any other length from 4 to 64. The length choices are only part of the interface; the algorithm itself doesn't change.

| Length | All four kinds (75 chars) | No symbols (62 chars) |
|---|---|---|
| 8 | ≈ 48 bits | ≈ 46 bits |
| 12 | ≈ 73 bits | ≈ 70 bits |
| 15 | ≈ 92 bits | ≈ 88 bits |
| 20 (default) | ≈ 123 bits | ≈ 117 bits |
| 24 | ≈ 148 bits | ≈ 141 bits |

Use 8 only for sites that cap length. That's about the strength of a random 8-character password, so it's weak if the site stores passwords in plain text.

The bound on all of these is your **master secret**. If any site leaks a password in plain text, an attacker who knows (or guesses) your name can test master-secret guesses offline at Argon2id speed. Use a random passphrase of at least 6 diceware words (about 77 bits). Anything you made up yourself is weaker than it feels.

## What you have to remember

The master secret, your name exactly as typed, and, for each site, anything that isn't the default: the username (if you used one), the version, and the type.

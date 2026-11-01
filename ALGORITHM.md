# Keyforge algorithm

There are two versions. **v1** is below, unchanged. **v2** (the default in the app) differs only in how the site is turned into a string; it is described in [Algorithm v2](#algorithm-v2). Everything not mentioned under v2 is identical.

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

The master secret, your name exactly as typed, and, for each site, anything that isn't the default: the username (if you used one), the version (counter), the type, the algorithm (v1 or v2), and, for v2, whether you used the full hostname.

---

# Algorithm v2

v2 exists so that the site comes from the page's real address and a lookalike domain gets a different, useless password. v1 is unchanged and stays selectable, because passwords already made with it must keep working.

## What changes, and what doesn't

| | v1 | v2 |
|---|---|---|
| Master key (section 2) | `keyforge.v1` salt | **same**, so one unlock serves both algorithms |
| Fingerprint (section 5) | `keyforge.v1` | **same** |
| Site key domain string | `keyforge.v1.site` | `keyforge.v2.site` |
| Site string | the whole host | the registrable domain, or the whole host if you ask for it (below) |
| Byte stream, character rules, templates, counter, login | | **same** |

`DOMAIN2 = "keyforge.v2"`. The master key keeps the v1 salt label on purpose: the secret is wiped after unlocking, so switching algorithm can't re-derive a key. The only thing v2 changes in the HMAC is the label and the site string:

```
siteKey = HMAC(masterKey, lps(DOMAIN2 + ".site") || lps("password") || lps(site2)
                          || lps(login) || u32(counter) || lps(template))
```

## The v2 site string

1. Compute `h`, the v1 site string (section 1, including dropping one leading `www.`). Pasting a full address, an international name in Unicode or `xn--` form, and so on, therefore all behave as in v1.
2. **Full hostname switch on:** `site2 = h`. (This is exactly the v1 site string; the password still differs from v1 because of the domain label.)
3. **Otherwise** `site2 = registrable(h)`:
   - If `h` contains `:`, `[` or `]`, has an empty label, or its last label is all ASCII digits `0-9` (IP addresses and odd inputs): `site2 = h`.
   - Otherwise split `h` on `.` into labels and find the length *k* of the public suffix using the frozen list below. If `h` has more than *k* labels, `site2` is the last *k + 1* labels joined with `.`; if it has *k* or fewer (a host that is itself a public suffix, or `localhost`), `site2 = h`.

Finding *k*, with `tail(i)` the labels from position `i` joined by `.`, and `n` the number of labels:

1. If some `tail(i)` is an exception rule (`!…`), take the smallest such `i`: `k = n − i − 1`.
2. Otherwise `k` is the largest `n − i` for which `tail(i)` is a plain rule, or `tail(i+1)` is the part after `*.` of a wildcard rule (`*.x` matches one extra label above `x`). If nothing matches, `k = 1` (the implicit rule `*`).

Matching is on the NFKC-lowercase Unicode form, as produced by section 1. Rules are stored in that form too.

Consequences worth knowing:

- `accounts.google.com`, `mail.google.com` and `google.com` all give `google.com`: one account, one password.
- `amazon.in` and `amazon.com` stay separate, as do `google.co.in` and `google.com`. v2 can't know that two different registrable domains share an account; for those, type one name yourself (for example `microsoft.com` for `login.live.com` and `login.microsoftonline.com`) and remember it.
- `a.github.io` and `b.github.io` stay separate because `github.io` is a public suffix (the private section of the list covers `myshopify.com`, `blogspot.com`, `herokuapp.com`, `vercel.app`, `netlify.app`, …).
- **The list does not cover every tenant-style service.** At this snapshot `atlassian.net`, `slack.com`, `zendesk.com` and `my.salesforce.com` are not public suffixes, so `a.atlassian.net` and `b.atlassian.net` both give `atlassian.net`. Use the full hostname switch for those, and remember that you did.
- `www.` is removed before the list is consulted, so `www.github.io` gives `github.io`.
- A host such as `paypal.com.evil.com` or `paypal.com@evil.com` gives `evil.com`, never `paypal.com`.

## The frozen Public Suffix List snapshot

v2's output depends on the [Public Suffix List](https://publicsuffix.org/list/), so the exact list is part of the algorithm. It is bundled, versioned and never fetched or refreshed:

| | |
|---|---|
| File | [`psl.js`](psl.js) (the web app imports it; `tools/reference.py` reads the rules text out of the same file) |
| Snapshot id | `psl-2026-10-31` (upstream VERSION `2026-10-31_14-17-28_UTC`, COMMIT `73f8cc701c084fe07d888ec552b2f0b53281a674`) |
| Upstream file SHA-256 | `617d1b276660e5a01209d7b58159450e400cf636634a7a9c2cfd50a1c6675d01` |
| Rules | 10,396: 6,948 ICANN and 3,448 PRIVATE. Both sections are used |
| Rules text SHA-256 | `084fa8cddda9f4d3fb66525c42542ab80831bd80061ef774c214bc91f39d3493`: the rules joined with `\n`, no comments, no trailing newline |
| Size | 148,806 bytes (about 45 KB gzipped) |

A different list is a **different algorithm version** (v3), never an update of `psl.js`. The tests pin the id, the rule count and the hash, and Python refuses to run if its copy doesn't match the hash. The list is licensed MPL-2.0 (see the header of `psl.js`).

All 10,396 rules are needed for the algorithm to be correct for every host; the 79 cases in `tests/sites-v2.json` between them decide on only 25 of them. Dropping rules to save space would silently change the answer for some hosts, so none are dropped.

## v2 and the interface

The app shows the v2 site string it used under the Site box. If it contains non-ASCII characters it also shows the `xn--` form and warns about lookalikes, and it warns when the site is near a short built-in list of well-known domains. Those are interface-only warnings (`link.js`) and never change a password. The `xn--` form shown is for display and is not used in any calculation.

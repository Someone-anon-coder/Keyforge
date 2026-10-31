# Attack report (2026-10-31)

All of this was tested, not just reasoned about. The scripts live outside the repo; the checks worth keeping are now in `tests/`.

## What held

| Attack | Result |
|---|---|
| Inverting a password back to the master key or secret | Not possible except by guessing the secret (Argon2id followed by HMAC). |
| Per-position bias (60,000 passwords) | Worst position χ² = 92, below the 116 threshold. No position leaks anything. |
| Bias within each character set | Lowercase, uppercase, digits and symbols are each uniform (χ² well under the limits). |
| Bias across character sets | Digits and symbols appear slightly more often (15.7% vs 13.3%) because every password must contain one. Exact entropy cost: **0.05–0.11 bits** (8 chars: 48.69 vs 48.73 max; 20 chars: 124.35 vs 124.46). Negligible. |
| Related inputs: version n vs n+1, site vs near-identical site, empty vs non-empty username, length 20 vs the first 20 of 24, master key with one bit flipped | Characters match in the same position 1.3% of the time, the same as unrelated random passwords (1.34%). Knowing one gives nothing about the other. |
| Collisions | No repeats among 60,000 twenty-character passwords. 8-digit PINs repeated 19 times against 18 expected by chance. Two sites sharing a short PIN happens with any generator. |
| Encoding tricks (fields running into each other) | Every field is length-prefixed and each use has its own label, so no two different inputs produce the same HMAC message. |
| Injecting script through the site field | Output is written with `textContent`, and the CSP blocks inline script and all network requests. |

## What broke, and the fixes

| # | Finding | Fix |
|---|---|---|
| 1 | **Same input, different password.** `bücher.de` typed and `https://bücher.de` pasted gave *different* passwords, because the browser's URL parser converts international names to `xn--…` form. Full-width `ｇｉｔｈｕｂ.com` did the same. | A hand-written normaliser (NFKC, explicit steps, Punycode decoded both ways). All of these now give one password. |
| 2 | **The Python backup disagreed with the app** on international domains, `\` in URLs, IP shorthands and Unicode whitespace. The backup would have rebuilt wrong passwords. | Both now follow ALGORITHM.md step by step. 20,000 fuzzed inputs match exactly, and that check is in the test suite. |
| 3 | **The master key stayed in memory after Lock:** 9 copies found by scanning the browser's process memory. | Lock now destroys the worker (freeing its memory) and reloads the page, and the key lives as a non-extractable WebCrypto key. Rescanned: **0 copies after Lock.** |
| 4 | **Another page on the same GitHub Pages address could replace the offline app.** Demonstrated: a page at `/otherrepo/` rewrote Keyforge's cache, and the next offline launch sent the typed secret to the attacker. | The service worker checks every file against SHA-256 hashes and refuses tampered files. Rerun: attack blocked, and that's now a browser test. Same-origin pages can still read the window directly, so **host it on its own origin** (README). |
| 5 | The secret's **Show** button turned the field into plain text, which phone keyboards learn from and can sync. | Removed. The fingerprint key tells you when you mistyped. |
| 6 | A revealed password stayed visible in the phone's recent-apps screenshot. | It's hidden again as soon as the app goes to the background. |
| 7 | Could be framed by another page. | Refuses to run in a frame. On Cloudflare, `_headers` adds `frame-ancestors 'none'`. |

## What can't be fixed in code

**1. A weak master secret is the whole game.** Demonstrated with `sunshine@2024`: one leaked site password, or just a *glimpse of the three fingerprint words*, plus a 720-guess list of "word + symbol + year" patterns found it in 4 seconds on 2 CPU cores. From there, every password for every site follows. Rough cost for an attacker with 100 high-end GPUs (about 200,000 guesses/s, a bandwidth-based estimate):

| Secret | Time to crack |
|---|---|
| Human-made, e.g. `Word@2024` | seconds to hours |
| 4 random diceware words | about 300 years |
| 5 words | about 2 million years |
| 6 words | about 10¹⁰ years |

Use 6 random diceware words. The name being public makes no difference.

**2. The fingerprint can be used to check guesses.** Its 24 bits on screen let anyone who sees them (shoulder-surfing, a screenshot, screen sharing) test guesses offline without any site being breached. With a 6-word secret, the fingerprint alone still leaves about 2⁵³ candidates, so it's harmless. With a weak secret, see point 1.

**3. A compromised device sees everything.** Malware, a malicious keyboard app, or a browser extension allowed on "all sites" can read the secret as you type it. Unlike a vault-based password manager, that one capture gives every past and future password, and the only recovery is changing the secret *and* every site's password. Install the PWA from a browser profile with no extensions.

**4. Lock doesn't fully wipe a browser tab.** After Lock, the browser's memory still held 3–5 copies of the *secret*, in the page's fields and Chrome's input handling. After **closing the tab or app, 0 copies.** The installed app now closes itself on Lock. In a tab, close it yourself.

**5. Clipboard history.** Windows Clipboard History, Gboard and Samsung keyboards keep copied items even after Keyforge clears the clipboard. Turn clipboard history off, or read the password and type it in.

**6. Whoever controls the hosting controls the app.** A malicious update with matching hashes would be trusted. Turn on two-factor authentication for that GitHub or Cloudflare account.

**7. Newer Unicode characters.** NFKC and lowercasing differ for about 90 recently added characters between Unicode 15 and 17. Stick to ordinary characters in names, sites and usernames.

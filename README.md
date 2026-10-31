# Keyforge

An offline, stateless password generator for your laptop and phone.

You type your name and one master secret, and Keyforge works out a different strong password for every site from those two things. Nothing is stored: no vault, no account, no sync, no list of your sites. If you know the name and secret, you can get every password back on any device.

**Try it:** https://keyforge.aayush-c2684.workers.dev

## How it works

1. Your name and master secret go through Argon2id (64 MiB, 3 passes) to make a master key. This takes about a second and is the only slow step.
2. For each site, the master key is combined with the site name, an optional login and a counter using HMAC-SHA256. The result is turned into a password of the length and character types you choose, with no bias towards any character.
3. The same inputs always give the same password. Change the counter to get a new one for a site.

The full specification is in [ALGORITHM.md](ALGORITHM.md). Because it's written down, and because [`tools/reference.py`](tools/reference.py) is a second implementation in Python that is tested against the app, your passwords don't depend on this app staying online.

## Using it

1. Open the app and type your **name** and **master secret**. Three fingerprint words appear; if they differ from last time, you mistyped.
2. Type the **site** (`github.com`, or paste a full address; they give the same password).
3. Optionally set a login, length, character types, or the counter.
4. Copy the password. It is cleared from the clipboard after 30 seconds.

**Choose a strong master secret.** Everything depends on it. Use six random words (for example, from [diceware](https://theworld.com/~reinhold/diceware.htm)), not something a person would pick. See [SECURITY.md](SECURITY.md) for how fast weak secrets fall.

## Install

Open the app once while online, then:

- **Laptop (Chrome/Edge):** click the install icon at the right of the address bar.
- **Android (Chrome):** menu, then **Install app** (or **Add to Home screen**).
- **iPhone (Safari):** Share, then **Add to Home Screen**.

After that it works in airplane mode. Install from a browser profile with no extensions, and choose **Never** if the browser offers to save the master secret.

## Privacy and security

- Everything runs on your device. The page's Content Security Policy blocks all network requests, so it can't send anything anywhere.
- The master key is held in a Web Worker as a non-extractable key. The app locks after 5 minutes of inactivity, which destroys the key. The installed app then closes itself; in a browser tab the page reloads, and the browser may keep traces of the secret in memory until you close the tab.
- A revealed password is hidden again when the app goes to the background.
- The service worker checks every file against a SHA-256 hash and refuses tampered copies.

Limits you should know about:

- **A weak master secret defeats everything.** And unlike a vault, anyone who captures your secret (malware, a malicious keyboard or extension) gets every password; recovery means changing the secret and every site's password.
- Phone and desktop **clipboard history** may keep copied passwords even after Keyforge clears the clipboard.
- Whoever controls the hosting controls the app. If you run your own copy, give it its own origin and protect the account.

[SECURITY.md](SECURITY.md) lists what was attacked, what held, what was fixed, and what can't be fixed in code.

**Found a vulnerability?** Please use **Security → Report a vulnerability** on this repository rather than a public issue.

## Run your own copy

There's no build step, framework or runtime dependency; it's plain static files. A PWA has to be served over HTTPS to install.

**It must be the only thing on its web address (origin).** Every GitHub Pages project of one account shares `https://<username>.github.io`, so another page there could read what you type. Use a host that gives each site its own origin, such as Cloudflare. GitHub Pages also ignores [`_headers`](_headers), so the extra security headers (`frame-ancestors 'none'`, `nosniff`, `Permissions-Policy`) wouldn't be sent.

**Cloudflare** (what the live copy uses):

1. In the dashboard: **Workers & Pages → Create application → Import a repository**, and pick your fork.
2. Set **Build command** to `sh tools/build_site.sh` and keep **Deploy command** as `npx wrangler deploy`. [`wrangler.jsonc`](wrangler.jsonc) serves only the app files, plus `_headers`.
3. Deploy, and turn on two-factor authentication for your Cloudflare and GitHub accounts.

Locally: `npm run serve` serves the folder at http://localhost:8080.

## Contributing

| Path | What it is |
|---|---|
| `index.html`, `app.css`, `app.js` | The interface |
| `worker.js` | Holds the master key in a Web Worker; the page never sees it |
| `core.js` | The algorithm (pure functions, also used by the tests) |
| `vendor/argon2.umd.min.js` | Argon2id from [hash-wasm](https://github.com/Daninet/hash-wasm) 4.12.0, MIT. SHA-256 `dcec617a2e1b700fa132d1583a186cb70611113395e869f2dd6cc82b415d3094` |
| `sw.js`, `manifest.webmanifest`, `icons/` | Offline support and install |
| `tools/stamp.py` | Writes every file's SHA-256 into `sw.js` |
| `tools/reference.py` | Independent Python implementation (`pip install argon2-cffi`) |
| `tools/build_site.sh`, `wrangler.jsonc` | Builds the folder Cloudflare serves |
| `tests/` | Unit tests, cross-implementation vectors, browser test |

After changing any served file, run `python3 tools/stamp.py` and commit the result; CI fails if `sw.js` is out of date. **Never change anything in `core.js` that affects output**, because that would change everyone's passwords. Add a v2 alongside it instead, as ALGORITHM.md explains.

```
npm test                       # algorithm: vectors from the Python version, normalisation, bias check
npm run e2e                    # real browser: UI, CSP, copy, lock, offline reload (needs Playwright)
python3 tools/make_vectors.py  # regenerate vectors from the Python implementation
```

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs the unit tests, the `sw.js` check and the browser test on pushes to `main` and on pull requests.

## License

Keyforge is free software under the [GNU General Public License v3.0](LICENSE) or, at your option, any later version. You can use, study, change and share it, but anyone who distributes a modified version, including by serving it as a web app, must do so under the same licence and make the source available.

It includes Argon2 from hash-wasm, which is MIT-licensed and compatible ([licence](vendor/hash-wasm.LICENSE)).

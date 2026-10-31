# Keyforge

An offline password generator for your laptop and phone. You type your name and a master secret, and every site's password is worked out from those. No password, name, secret or site list is stored anywhere. The algorithm is described in [ALGORITHM.md](ALGORITHM.md).

## Files

| Path | What it is |
|---|---|
| `index.html`, `app.css`, `app.js` | The interface |
| `worker.js` | Holds the master key in a Web Worker; the page never sees it |
| `core.js` | The algorithm (pure functions, also used by the tests) |
| `vendor/argon2.umd.min.js` | Argon2id from [hash-wasm](https://github.com/Daninet/hash-wasm) 4.12.0, MIT. SHA-256 `dcec617a2e1b700fa132d1583a186cb70611113395e869f2dd6cc82b415d3094` |
| `sw.js`, `manifest.webmanifest`, `icons/` | Offline support and install |
| `tools/stamp.py` | Writes every file's SHA-256 into `sw.js`; run it after any change |
| `SECURITY.md` | What was attacked, what held, what was fixed, what's left |
| `tools/reference.py` | A second, independent implementation in Python (`pip install argon2-cffi`) |
| `tests/` | Unit tests, cross-implementation vectors, browser test |
| `.github/workflows/` | CI (`ci.yml`) |
| `_headers` | Security headers, applied by Cloudflare and Netlify |
| `wrangler.jsonc`, `tools/build_site.sh` | Cloudflare deploy: serves only the app files |

There's no build step, framework or npm dependency at runtime. Everything is plain files.

## Put it online

A PWA has to be served over HTTPS once before it can be installed. After that it runs fully offline.

**It must be the only thing on its web address (origin).** Every GitHub Pages project of one account shares `https://<username>.github.io`. Any page on that origin can open Keyforge's window and read what you type, and SECURITY.md shows one of them rewriting its offline copy. So don't put it next to your other projects.

**Recommended: Cloudflare Pages.** It gives the app its own `https://<project>.pages.dev` and applies the security headers in [`_headers`](_headers) (`frame-ancestors 'none'`, `nosniff`, `Permissions-Policy`), which GitHub Pages ignores.

1. Cloudflare dashboard, **Workers & Pages → Create application → Import a repository**, and pick this repository.
2. Set **Build command** to `sh tools/build_site.sh` and leave **Deploy command** as `npx wrangler deploy`. [`wrangler.jsonc`](wrangler.jsonc) tells it to serve only the `_site/` folder that the script builds, which includes `_headers`.
3. Deploy, and turn on two-factor authentication for the Cloudflare account. The live copy is at https://keyforge.aayush-c2684.workers.dev.

(The older Pages flow also works: no build command, output directory `/`. It publishes the whole repository, including `tests/` and `tools/`.)

Other safe options: a separate GitHub account or organisation used only for this, with a repository named `<that-name>.github.io`.

GitHub Pages is not used for this repository: it shares an origin with the account's other Pages sites and ignores `_headers`.

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on pushes to `main` and on pull requests: unit tests, a check that `sw.js` hashes are current (`python3 tools/stamp.py` must leave no diff), and the browser test.

## Install

- **Laptop (Chrome/Edge):** click the install icon at the right of the address bar.
- **Android (Chrome):** menu, then **Install app** (or **Add to Home screen**).
- **iPhone (Safari):** Share, then **Add to Home Screen**.

Open it once while online. From then on it works in airplane mode.

## Updating

Change files, run `python3 tools/stamp.py`, and push. Installed copies pick up the new version the next time they open while online. **Never change anything in `core.js` that affects output.** Add a v2 alongside it instead, as ALGORITHM.md explains.

## Tests

```
npm test                       # algorithm: 45 vectors from the Python version, normalisation, bias check
npm run e2e                    # real browser: UI, CSP, copy, lock, offline reload (needs Playwright)
python3 tools/make_vectors.py  # regenerate vectors from the Python implementation
```

## Behaviour worth knowing

- The page's Content Security Policy blocks all network requests (`connect-src 'none'`), so the page itself can't send anything anywhere.
- The app locks itself after 5 minutes without use. Locking destroys the master key. The installed app also closes itself; in a browser tab it reloads instead, and the browser may keep traces of the secret in memory until you close the tab. Closing clears everything.
- Copying clears the clipboard after 30 seconds, but only if Keyforge is still open and focused. Phones may keep their own clipboard history.
- The browser may offer to save the master secret. Choose **Never**.
- Anyone who can push to your repository can change the app. Keep two-factor authentication on that GitHub account.
- Found a vulnerability? Use **Security → Report a vulnerability** on GitHub rather than a public issue.

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Someone-anon-coder
// Interface helpers for getting a site in from a link and warning about lookalikes.
// Nothing here is part of the algorithm: it never changes what a password is, only what is shown.

// ---- Getting a link in -----------------------------------------------------

const URL_RE = /https?:\/\/[^\s<>"'`/?#\\][^\s<>"'`]*/i;
const TRAILING = /[.,;:!?'")}>\]]+$/;

/** First http(s) URL found in the given strings, checked in order. null if none. */
export function extractUrl(...texts) {
  for (const t of texts) {
    const m = URL_RE.exec(String(t ?? "").normalize("NFKC"));
    if (!m) continue;
    let u = m[0];
    // Sentences wrap links in punctuation; put a bracket back only if it closes an IPv6 literal.
    u = u.replace(TRAILING, "");
    if (u.split("[").length > u.split("]").length) u += "]";
    if (u.replace(/^https?:\/\//i, "")) return u;
  }
  return null;
}

/**
 * The link in a Web Share Target launch (?title=&text=&url=). Android apps disagree about which
 * field holds the link (Chrome usually puts it in `text`), so the first http(s) URL in url, text
 * or title wins. Unrelated parameters such as ?locked= are ignored. null if there is no link.
 */
export function sharedUrl(search) {
  const q = new URLSearchParams(search);
  return extractUrl(...["url", "text", "title"].map((k) => (q.get(k) ?? "").slice(0, 8192)));
}

/**
 * Text from the clipboard: a link, or something that is plainly an address ("github.com/login").
 * Anything else (a password, a sentence) gives "" so it is never copied into the visible site field.
 */
export function linkOrHost(text) {
  const t = String(text ?? "").trim();
  if (!t || t.length > 4096) return "";
  const url = extractUrl(t);
  if (url) return url;
  return /^[\p{L}\p{N}][\p{L}\p{N}.-]*\.[\p{L}\p{N}-]{2,}(:[0-9]+)?([/?#]\S*)?$/u.test(t) ? t : "";
}

// ---- Punycode encode (RFC 3492), for showing the xn-- form ------------------

function adapt(delta, numPoints, first) {
  delta = first ? Math.floor(delta / 700) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > 455) { delta = Math.floor(delta / 35); k += 36; }
  return k + Math.floor((36 * delta) / (delta + 38));
}
const digit = (d) => String.fromCharCode(d < 26 ? 97 + d : 22 + d);

export function punycodeEncode(input) {
  const cps = [...input].map((c) => c.codePointAt(0));
  let out = cps.filter((c) => c < 0x80).map((c) => String.fromCharCode(c)).join("");
  const b = out.length;
  let h = b, n = 128, delta = 0, bias = 72;
  if (b) out += "-";
  while (h < cps.length) {
    const m = Math.min(...cps.filter((c) => c >= n));
    delta += (m - n) * (h + 1);
    n = m;
    for (const c of cps) {
      if (c < n) delta++;
      if (c === n) {
        let q = delta;
        for (let k = 36; ; k += 36) {
          const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
          if (q < t) break;
          out += digit(t + ((q - t) % (36 - t)));
          q = Math.floor((q - t) / (36 - t));
        }
        out += digit(q);
        bias = adapt(delta, h + 1, h === b);
        delta = 0;
        h++;
      }
    }
    delta++; n++;
  }
  return out;
}

/** Display-only ASCII form of a host: each non-ASCII label becomes xn--… */
export const toAscii = (host) =>
  host.split(".").map((l) => (/[^\x00-\x7f]/.test(l) ? "xn--" + punycodeEncode(l) : l)).join(".");

// ---- Lookalike hosts ---------------------------------------------------------

const SCRIPTS = ["Latin", "Cyrillic", "Greek", "Armenian", "Hebrew", "Arabic", "Devanagari", "Bengali", "Gurmukhi", "Gujarati",
  "Tamil", "Telugu", "Kannada", "Malayalam", "Thai", "Georgian", "Hangul", "Hiragana", "Katakana", "Han", "Bopomofo", "Ethiopic"]
  .map((s) => [s, new RegExp(`^\\p{Script=${s}}$`, "u")]);
const CJK_MIXES = [["Han", "Hiragana", "Katakana"], ["Han", "Hangul"], ["Han", "Bopomofo"]];

function scriptsOf(label) {
  const found = new Set();
  for (const ch of label) {
    if (!/^\p{L}$/u.test(ch)) continue; // digits, hyphen and marks don't count
    found.add((SCRIPTS.find(([, re]) => re.test(ch)) || ["Other"])[0]);
  }
  return found;
}

/**
 * What to tell the user about the characters of a host (already in site form, so Unicode).
 * nonAscii: any label has non-ASCII characters. mixed: one label mixes alphabets in a way real
 * names rarely do (Latin with Cyrillic, say). Japanese, Korean and Chinese mixes are allowed.
 */
export function hostFlags(host) {
  const nonAscii = /[^\x00-\x7f]/.test(host);
  const mixed = host.split(".").some((label) => {
    const s = scriptsOf(label);
    if (s.size < 2) return false;
    const rest = [...s].filter((x) => x !== "Latin");
    return !CJK_MIXES.some((mix) => rest.every((x) => mix.includes(x)));
  });
  return { nonAscii, mixed, ascii: nonAscii ? toAscii(host) : host };
}

// A small list of sites worth impersonating. Used only to warn, never to change a password.
export const HIGH_VALUE = Object.freeze([
  "google.com", "google.co.in", "youtube.com", "gmail.com", "googleapis.com", "googleusercontent.com",
  "apple.com", "icloud.com", "microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com",
  "amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com", "paypal.com", "facebook.com", "instagram.com",
  "whatsapp.com", "twitter.com", "linkedin.com", "github.com", "githubusercontent.com", "gitlab.com",
  "dropbox.com", "netflix.com", "spotify.com", "ebay.com", "coinbase.com", "binance.com", "adobe.com",
  "yahoo.com", "protonmail.com", "cloudflare.com", "stripe.com", "discord.com", "reddit.com", "steampowered.com",
  "epicgames.com", "revolut.com", "robinhood.com", "fidelity.com", "vanguard.com", "chase.com", "bankofamerica.com",
  "wellsfargo.com", "americanexpress.com", "hdfcbank.com", "icicibank.com", "onlinesbi.sbi", "paytm.com",
  "phonepe.com", "flipkart.com", "zoho.com", "zoho.in", "slack.com", "atlassian.com",
]);

// Digits and letters that stand in for other letters in fake names.
const LOOKALIKE = { 0: "o", 1: "l", 3: "e", 5: "s", $: "s", "ı": "i" };
const skeleton = (s) => s.replace(/[0135$ı]/g, (c) => LOOKALIKE[c] ?? c).replace(/rn/g, "m").replace(/vv/g, "w");

/** Optimal-string-alignment distance: insert, delete, replace, swap neighbours. */
export function editDistance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

/**
 * Does this site imitate a well-known one? site: what the password is made for; host: the whole
 * host it came from. Returns { domain, why } for the first match, or null. Exactly a listed
 * domain is never flagged.
 */
export function lookalike(site, host = site) {
  if (!site || HIGH_VALUE.includes(site)) return null;
  const skel = skeleton(site);
  for (const d of HIGH_VALUE) {
    if (("." + host + ".").includes("." + d + ".")) return { domain: d, why: "contains" };
  }
  for (const d of HIGH_VALUE) {
    if (d.length >= 8 && Math.min(editDistance(site, d), editDistance(skel, d)) <= 2) return { domain: d, why: "close" };
  }
  const first = skel.split(".")[0];
  for (const d of HIGH_VALUE) {
    const brand = d.split(".")[0];
    if (brand.length >= 6 && first.length > brand.length && first.includes(brand)) return { domain: d, why: "name" };
  }
  return null;
}

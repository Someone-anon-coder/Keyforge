// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Someone-anon-coder
// Keyforge algorithm v2 — see ALGORITHM.md. Pure functions, no DOM.
// v1 (core.js) is untouched. v2 changes only the site rule and the site-key domain string:
// the master key and fingerprint are still derived with "keyforge.v1" so one unlock serves both.

import { hmac, enc, normalizeSite, normalizeLogin, validateTemplate, templateCode, renderPassword, LIMITS } from "./core.js";
import { PSL_RULES } from "./psl.js";

export const VERSION = 2;
export const DOMAIN = "keyforge.v2";
export { PSL_ID, PSL_SHA256 } from "./psl.js";

function u32(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, false);
  return b;
}
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
const lps = (str) => { const b = enc(str); return concat(u32(b.length), b); };

// ---- Public Suffix List ---------------------------------------------------
// Frozen snapshot in psl.js. Rules: "x" (suffix), "*.x" (any one label above x), "!x.y" (exception).
const EXCEPTIONS = new Set(), WILDCARDS = new Set(), PLAIN = new Set();
for (const r of PSL_RULES.split("\n")) {
  if (!r) continue;
  if (r.startsWith("!")) EXCEPTIONS.add(r.slice(1));
  else if (r.startsWith("*.")) WILDCARDS.add(r.slice(2));
  else PLAIN.add(r);
}
export const PSL_RULE_COUNT = EXCEPTIONS.size + WILDCARDS.size + PLAIN.size;

/** Number of labels in the public suffix of a host given as its labels. */
function suffixLength(labels) {
  const n = labels.length;
  const tail = (i) => labels.slice(i).join(".");
  for (let i = 0; i < n; i++) if (EXCEPTIONS.has(tail(i))) return n - i - 1; // exception wins outright
  let best = 1; // the implicit rule "*"
  for (let i = 0; i < n; i++) {
    if (PLAIN.has(tail(i)) || (i + 1 < n && WILDCARDS.has(tail(i + 1)))) { best = n - i; break; } // longest first
  }
  return best;
}

/**
 * Registrable domain (public suffix plus one label) of a host already in v1 site form.
 * Returned unchanged when there is no such thing: IP-like or bracketed hosts, empty labels,
 * or a host that is itself a public suffix.
 */
export function registrableDomain(host) {
  if (/[:[\]]/.test(host)) return host;
  const labels = host.split(".");
  if (labels.includes("") || /^[0-9]+$/.test(labels[labels.length - 1])) return host;
  const n = labels.length, k = suffixLength(labels);
  return n > k ? labels.slice(n - k - 1).join(".") : host;
}

/** The v2 site string. fullHost keeps the whole host (the v1 site string) for tenant-style sites. */
export function siteV2(input, fullHost = false) {
  const h = normalizeSite(input);
  return fullHost ? h : registrableDomain(h);
}

// ---- Site key and password --------------------------------------------------

export async function siteKeyV2(masterKey, { site, fullHost = false, login = "", counter = 1, template }) {
  const s = siteV2(site, fullHost);
  if (!s) throw new RangeError("site is empty");
  if (!Number.isInteger(counter) || counter < 1 || counter > LIMITS.maxCounter)
    throw new RangeError("counter must be 1-4294967295");
  const t = validateTemplate(template);
  const msg = concat(
    lps(DOMAIN + ".site"),
    lps("password"),
    lps(s),
    lps(normalizeLogin(login)),
    u32(counter),
    lps(templateCode(t)),
  );
  return hmac(masterKey, msg);
}

export async function generateV2(masterKey, opts) {
  return renderPassword(await siteKeyV2(masterKey, opts), opts.template);
}

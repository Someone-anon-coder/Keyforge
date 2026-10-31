// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Someone-anon-coder
// Keyforge algorithm v1 — see ALGORITHM.md. Pure functions, no DOM.
// Runs in browsers (Worker) and Node >= 20 (uses globalThis.crypto.subtle).
// The Argon2id implementation is injected so this file has no imports.

export const VERSION = 1;
export const DOMAIN = "keyforge.v1";

export const ARGON2 = Object.freeze({
  iterations: 3,
  memoryKiB: 65536, // 64 MiB
  parallelism: 1,
  hashLength: 32,
});

export const CLASSES = Object.freeze({
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!#$%&*+-=?@^_",
});
const CLASS_ORDER = ["lower", "upper", "digits", "symbols"];
const CLASS_CODE = { lower: "a", upper: "A", digits: "9", symbols: "#" };

export const LIMITS = Object.freeze({ minLength: 4, maxLength: 64, maxCounter: 0xffffffff });

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();

export const enc = (s) => te.encode(String(s).normalize("NFC"));

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

// Length-prefixed field: uint32be(len) || bytes. Makes every input boundary unambiguous.
const lp = (bytes) => concat(u32(bytes.length), bytes);
const lps = (str) => lp(enc(str));

export async function sha256(bytes) {
  return new Uint8Array(await subtle.digest("SHA-256", bytes));
}

/** key: raw bytes or a non-extractable HMAC CryptoKey. */
export async function hmac(key, msg) {
  const k = key instanceof Uint8Array ? await importHmacKey(key) : key;
  return new Uint8Array(await subtle.sign("HMAC", k, msg));
}
export const importHmacKey = (bytes) =>
  subtle.importKey("raw", bytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);

// ---- Input normalisation -------------------------------------------------
// Hand-written (no URL parser) so every implementation gets identical results.

export const normalizeName = (name) => String(name).normalize("NFKC").trim();

const PUNY = { base: 36, tMin: 1, tMax: 26, skew: 38, damp: 700 };
function punyAdapt(delta, numPoints, first) {
  const { base, tMin, tMax, skew, damp } = PUNY;
  delta = first ? Math.floor(delta / damp) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base; }
  return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
}
/** RFC 3492 decode of the part after "xn--". Returns null if invalid. */
export function punycodeDecode(input) {
  const { base, tMin, tMax } = PUNY;
  let n = 128, i = 0, bias = 72;
  const out = [];
  const b = Math.max(input.lastIndexOf("-"), 0);
  for (let j = 0; j < b; j++) {
    const c = input.charCodeAt(j);
    if (c >= 0x80) return null;
    out.push(c);
  }
  for (let idx = b > 0 ? b + 1 : 0; idx < input.length;) {
    const oldi = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (idx >= input.length) return null;
      const c = input.charCodeAt(idx++);
      const d = c >= 48 && c <= 57 ? c - 22 : c >= 97 && c <= 122 ? c - 97 : c >= 65 && c <= 90 ? c - 65 : base;
      if (d >= base) return null;
      i += d * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (d < t) break;
      w *= base - t;
      if (w > 0x7fffffff) return null;
    }
    const len = out.length + 1;
    bias = punyAdapt(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    i %= len;
    if (n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff)) return null;
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}

export function normalizeSite(input) {
  let s = String(input).normalize("NFKC").trim().toLowerCase();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");      // scheme
  s = s.split(/[/?#\\]/)[0];                           // path, query, fragment
  s = s.slice(s.lastIndexOf("@") + 1);                   // user:pass@
  s = s.replace(/:[0-9]*$/, "").replace(/\.+$/, "");      // port, trailing dots
  s = s.split(".").map((l) => (l.startsWith("xn--") ? punycodeDecode(l.slice(4)) ?? l : l)).join(".");
  s = s.normalize("NFKC").toLowerCase();
  if (s.startsWith("www.")) s = s.slice(4);
  return s;
}

export const normalizeLogin = (login) => String(login ?? "").normalize("NFKC").trim().toLowerCase();

// ---- Templates -----------------------------------------------------------

export function templateCode({ length, classes }) {
  const picked = CLASS_ORDER.filter((c) => classes.includes(c));
  return `L${length}:${picked.map((c) => CLASS_CODE[c]).join("")}`;
}

export function validateTemplate(t) {
  if (!Number.isInteger(t.length) || t.length < LIMITS.minLength || t.length > LIMITS.maxLength)
    throw new RangeError(`length must be ${LIMITS.minLength}-${LIMITS.maxLength}`);
  const picked = CLASS_ORDER.filter((c) => t.classes.includes(c));
  if (picked.length === 0) throw new RangeError("pick at least one character class");
  if (picked.length > t.length) throw new RangeError("length is shorter than the number of classes");
  return { length: t.length, classes: picked };
}

// UI choices only. Any length from 4 to 64 is valid input to the algorithm.
export const LENGTH_CHOICES = Object.freeze([8, 12, 15, 20, 24]);
export const DEFAULT_TEMPLATE = Object.freeze({ length: 20, classes: Object.freeze(["lower", "upper", "digits", "symbols"]) });

// ---- Key derivation ------------------------------------------------------

export async function nameSalt(name) {
  return sha256(concat(lps(DOMAIN + ".salt"), lps(normalizeName(name))));
}

/**
 * argon2id: (opts) => Promise<Uint8Array>, matching hash-wasm's signature with outputType "binary".
 * secret: a string, or its bytes already NFC/UTF-8 encoded (so the caller can wipe them).
 */
export async function deriveMasterKey(name, secret, argon2id, params = ARGON2) {
  if (!normalizeName(name)) throw new RangeError("name is empty");
  const pw = secret instanceof Uint8Array ? secret : enc(secret);
  if (!pw.length) throw new RangeError("secret is empty");
  const salt = await nameSalt(name);
  const key = await argon2id({
    password: pw,
    salt,
    iterations: params.iterations,
    memorySize: params.memoryKiB,
    parallelism: params.parallelism,
    hashLength: params.hashLength,
    outputType: "binary",
  });
  return new Uint8Array(key);
}

export async function siteKey(masterKey, { site, login = "", counter = 1, template }) {
  const s = normalizeSite(site);
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

// Deterministic byte stream: HMAC(key, uint32be(i)) for i = 0, 1, 2, ...
export class ByteStream {
  constructor(key) { this.key = key; this.block = 0; this.buf = new Uint8Array(0); this.pos = 0; }
  async next() {
    if (this.pos >= this.buf.length) {
      this.buf = await hmac(this.key, u32(this.block++));
      this.pos = 0;
    }
    return this.buf[this.pos++];
  }
  // Unbiased integer in [0, n) by rejection sampling. n must be 1..256.
  async below(n) {
    if (n < 1 || n > 256) throw new RangeError("n out of range");
    const limit = 256 - (256 % n);
    for (;;) {
      const b = await this.next();
      if (b < limit) return b % n;
    }
  }
}

export async function renderPassword(key, template) {
  const t = validateTemplate(template);
  const st = new ByteStream(key);
  const chars = [];
  // 1. One character from each selected class, so site rules are always met.
  for (const c of t.classes) chars.push(CLASSES[c][await st.below(CLASSES[c].length)]);
  // 2. Fill the rest from the union of selected classes.
  const all = t.classes.map((c) => CLASSES[c]).join("");
  while (chars.length < t.length) chars.push(all[await st.below(all.length)]);
  // 3. Fisher–Yates shuffle so the guaranteed characters are not at fixed positions.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = await st.below(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

export async function generate(masterKey, opts) {
  return renderPassword(await siteKey(masterKey, opts), opts.template);
}

// ---- Fingerprint (detects a mistyped name or secret) ----------------------

export async function fingerprint(masterKey) {
  const h = await hmac(masterKey, lps(DOMAIN + ".fingerprint"));
  // 24 bits: three words from a 256-word list, and the same bits as 8 key cuts (3 bits each).
  const words = [WORDS[h[0]], WORDS[h[1]], WORDS[h[2]]];
  const bits = (h[0] << 16) | (h[1] << 8) | h[2];
  const cuts = Array.from({ length: 8 }, (_, i) => (bits >>> (21 - 3 * i)) & 7);
  return { words, cuts };
}

export const WORDS = Object.freeze([
  "acorn","agate","alder","amber","anchor","apple","apron","arch","arrow","aspen","atlas","attic","badge","bagel","bamboo","banjo",
  "barn","basil","beacon","beetle","bell","berry","birch","bison","blade","bloom","bobcat","bonnet","boot","bramble","brick","bridge",
  "brook","bucket","bugle","butter","cabin","cactus","camel","candle","canoe","canyon","carrot","castle","cedar","cello","chalk","cherry",
  "chess","cider","cinder","clover","cobalt","comet","copper","coral","cotton","cougar","crane","crater","cricket","crown","cymbal","daisy",
  "delta","denim","desert","dingo","dolphin","domino","donkey","dragon","drum","dune","eagle","easel","ember","emerald","falcon","fennel",
  "fern","ferry","fiddle","fig","finch","flint","forest","fossil","fox","frost","gable","garnet","gecko","geyser","ginger","glacier",
  "goblet","goose","granite","grape","gravel","guitar","gull","harbor","harp","hazel","heron","hickory","hive","holly","honey","hornet",
  "iceberg","igloo","indigo","iris","island","ivory","jackal","jade","jaguar","jasmine","jelly","jetty","juniper","kayak","kettle","kiwi",
  "koala","lagoon","lantern","larch","lava","lemon","lentil","lilac","linen","lizard","llama","lobster","locket","lotus","lynx","magnet",
  "mango","maple","marble","meadow","melon","mesa","meteor","mint","mitten","molar","monsoon","moose","mosaic","moss","mule","nectar",
  "needle","nettle","nickel","nutmeg","oak","oasis","oboe","ocean","olive","onyx","orbit","orchid","osprey","otter","oyster","paddle",
  "panda","papaya","parrot","peach","pebble","pelican","pepper","piano","pine","pigeon","plum","pollen","poppy","prairie","puffin","quail",
  "quartz","quill","rabbit","radish","raven","reef","ribbon","river","robin","rocket","saddle","saffron","salmon","sapphire","satchel","sequoia",
  "shovel","silver","sparrow","spruce","squid","stork","summit","swan","tablet","tango","teapot","thistle","thunder","tiger","timber","topaz",
  "toucan","trout","tulip","tundra","turnip","umber","valley","velvet","violin","volcano","walnut","walrus","willow","wombat","yarrow","zebra",
  "anvil","bluebell","compass","dahlia","feather","gazelle","hammock","inkwell","kestrel","lemur","nomad","pumpkin","raisin","sunflower","tortoise","wren",
]);
if (WORDS.length !== 256 || new Set(WORDS).size !== 256) throw new Error("WORDS must be 256 unique words");

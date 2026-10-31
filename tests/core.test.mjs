// Run: node --test tests/
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import * as c from "../core.js";

const { argon2id } = createRequire(import.meta.url)("../vendor/argon2.umd.min.js");
const vectors = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
const hex = (b) => Buffer.from(b).toString("hex");
const ALL = ["lower", "upper", "digits", "symbols"];

test("matches the independent Python implementation (all vectors)", async () => {
  for (const id of vectors) {
    const mk = await c.deriveMasterKey(id.name, id.secret, argon2id);
    assert.equal(hex(mk), id.masterKeyHex, `master key for ${id.name}`);
    assert.deepEqual((await c.fingerprint(mk)).words, id.fingerprint);
    for (const v of id.cases) {
      const pw = await c.generate(mk, { site: v.site, login: v.login, counter: v.counter, template: { length: v.length, classes: v.classes } });
      assert.equal(pw, v.password, `${id.name} / ${JSON.stringify(v)}`);
    }
  }
});

test("Argon2id parameters are frozen", () => {
  assert.deepEqual({ ...c.ARGON2 }, { iterations: 3, memoryKiB: 65536, parallelism: 1, hashLength: 32 });
});

test("site normalisation", () => {
  const cases = {
    "github.com": "github.com",
    "  GitHub.COM ": "github.com",
    "https://www.github.com/login?next=/": "github.com",
    "http://github.com:8080/": "github.com",
    "www.github.com/settings": "github.com",
    "github.com.": "github.com",
    "mail.google.com": "mail.google.com",
    "bücher.de": "bücher.de",
    "https://bücher.de/": "bücher.de",
    "xn--bcher-kva.de": "bücher.de",
    "ｇｉｔｈｕｂ.com": "github.com",
    "https://user:pw@www.GitHub.com:443/x": "github.com",
    "https://evil.com\\@github.com": "evil.com",
    "xn--zz.com": "xn--zz.com",
    "": "",
  };
  for (const [input, want] of Object.entries(cases)) assert.equal(c.normalizeSite(input), want, input);
});

test("JS and Python normalise 20,000 fuzzed inputs identically", async () => {
  const fz = JSON.parse(readFileSync(new URL("./normalize-fuzz.json", import.meta.url), "utf8"));
  for (const [input, site, name, login] of fz) {
    assert.deepEqual([c.normalizeSite(input), c.normalizeName(input), c.normalizeLogin(input)], [site, name, login], JSON.stringify(input));
  }
});

test("name is trimmed but case-sensitive; login is case-insensitive", async () => {
  assert.deepEqual(await c.nameSalt(" Aayush "), await c.nameSalt("Aayush"));
  assert.notDeepEqual(await c.nameSalt("aayush"), await c.nameSalt("Aayush"));
  const mk = new Uint8Array(32).fill(7);
  const t = c.DEFAULT_TEMPLATE;
  assert.equal(await c.generate(mk, { site: "a.com", login: "Bob", template: t }), await c.generate(mk, { site: "a.com", login: " bob ", template: t }));
});

test("every input changes the password", async () => {
  const mk = new Uint8Array(32).fill(1);
  const base = { site: "a.com", login: "", counter: 1, template: c.DEFAULT_TEMPLATE };
  const p0 = await c.generate(mk, base);
  for (const change of [{ site: "b.com" }, { login: "x" }, { counter: 2 }, { template: { length: 20, classes: ["lower", "upper", "digits"] } }, { template: { length: 21, classes: ALL } }]) {
    assert.notEqual(await c.generate(mk, { ...base, ...change }), p0, JSON.stringify(change));
  }
  assert.notEqual(await c.generate(new Uint8Array(32).fill(2), base), p0);
});

test("length, alphabet and guaranteed classes hold across 2000 sites", async () => {
  const mk = new Uint8Array(32).fill(9);
  for (const tpl of [c.DEFAULT_TEMPLATE, { length: 12, classes: ["lower", "upper", "digits"] }, { length: 8, classes: ["digits"] }, { length: 4, classes: ALL }]) {
    const alphabet = new Set(tpl.classes.flatMap((k) => [...c.CLASSES[k]]));
    for (let i = 0; i < 500; i++) {
      const pw = await c.generate(mk, { site: `s${i}.com`, template: tpl });
      assert.equal(pw.length, tpl.length);
      for (const ch of pw) assert.ok(alphabet.has(ch), `${ch} not allowed`);
      for (const k of tpl.classes) assert.ok([...pw].some((ch) => c.CLASSES[k].includes(ch)), `missing ${k} in ${pw}`);
    }
  }
});

test("rejection sampling is unbiased (chi-square, alphabet of 75)", async () => {
  const n = 75, draws = 150000, counts = new Array(n).fill(0);
  const st = new c.ByteStream(new Uint8Array(32).fill(3));
  for (let i = 0; i < draws; i++) counts[await st.below(n)]++;
  const exp = draws / n;
  const chi2 = counts.reduce((s, o) => s + (o - exp) ** 2 / exp, 0);
  // df = 74; p = 0.001 critical value ≈ 116. A plain `byte % 75` gives chi2 in the thousands here.
  assert.ok(chi2 < 116, `chi2 = ${chi2.toFixed(1)}`);
});

test("rejects bad inputs", async () => {
  const mk = new Uint8Array(32);
  const t = c.DEFAULT_TEMPLATE;
  await assert.rejects(c.generate(mk, { site: " ", template: t }), /site is empty/);
  await assert.rejects(c.generate(mk, { site: "a.com", counter: 0, template: t }), /counter/);
  await assert.rejects(c.generate(mk, { site: "a.com", counter: 1.5, template: t }), /counter/);
  await assert.rejects(c.generate(mk, { site: "a.com", template: { length: 3, classes: ["digits"] } }), /length/);
  await assert.rejects(c.generate(mk, { site: "a.com", template: { length: 65, classes: ["digits"] } }), /length/);
  await assert.rejects(c.generate(mk, { site: "a.com", template: { length: 10, classes: [] } }), /at least one/);
  await assert.rejects(c.deriveMasterKey(" ", "x", argon2id), /name is empty/);
  await assert.rejects(c.deriveMasterKey("a", "", argon2id), /secret is empty/);
});

test("template code ignores class order", () => {
  assert.equal(c.templateCode({ length: 20, classes: ["symbols", "lower", "digits", "upper"] }), "L20:aA9#");
});

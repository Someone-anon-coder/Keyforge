// Run: npm test   (algorithm v2, the frozen Public Suffix List snapshot, and the link helpers)
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { domainToASCII } from "node:url";
import * as c from "../core.js";
import * as v2 from "../v2.js";
import { PSL_RULES } from "../psl.js";
import * as link from "../link.js";

const { argon2id } = createRequire(import.meta.url)("../vendor/argon2.umd.min.js");
const json = (f) => JSON.parse(readFileSync(new URL(f, import.meta.url), "utf8"));
const vectorsV1 = json("./vectors.json");
const vectorsV2 = json("./vectors-v2.json");
const sitesV2 = json("./sites-v2.json");
const T = c.DEFAULT_TEMPLATE;
const mk = new Uint8Array(32).fill(5);

test("the Public Suffix List snapshot is frozen", () => {
  // Changing any of these means changing every v2 password. A different list must be a new algorithm version.
  const rules = PSL_RULES.split("\n").filter(Boolean);
  const sha = createHash("sha256").update(rules.join("\n")).digest("hex");
  assert.equal(v2.PSL_ID, "psl-2026-10-31");
  assert.equal(rules.length, 10396);
  assert.equal(sha, v2.PSL_SHA256);
  assert.equal(sha, "084fa8cddda9f4d3fb66525c42542ab80831bd80061ef774c214bc91f39d3493");
  assert.equal(v2.PSL_RULE_COUNT, 10396);
});

test("v2 uses its own domain string and leaves v1 alone", () => {
  assert.equal(v2.DOMAIN, "keyforge.v2");
  assert.equal(c.DOMAIN, "keyforge.v1");
  assert.equal(c.VERSION, 1);
});

test("site rule: every case from the subdomain study", () => {
  assert.ok(sitesV2.length >= 79);
  for (const { input, site, fullHost } of sitesV2) {
    assert.equal(v2.siteV2(input), site, `domain of ${input}`);
    assert.equal(v2.siteV2(input, true), fullHost, `full host of ${input}`);
  }
});

test("site rule: JS agrees with Python on the fuzz corpus (v2 column)", () => {
  const fz = json("./normalize-fuzz.json");
  const rows = fz.filter((r) => r.length === 5);
  assert.ok(rows.length >= 8000, `only ${rows.length} rows carry a v2 site`);
  for (const [input, , , , want] of rows) assert.equal(v2.siteV2(input), want, JSON.stringify(input));
});

test("v2 passwords match the independent Python implementation", async () => {
  for (const id of vectorsV2) {
    const key = await c.deriveMasterKey(id.name, id.secret, argon2id);
    assert.equal(Buffer.from(key).toString("hex"), vectorsV1.find((v) => v.name === id.name).masterKeyHex, "same master key as v1");
    for (const v of id.cases) {
      const pw = await v2.generateV2(key, { site: v.site, fullHost: v.fullHost, login: v.login, counter: v.counter, template: { length: v.length, classes: v.classes } });
      assert.equal(pw, v.password, `${id.name} / ${JSON.stringify(v)}`);
    }
  }
});

test("v2 differs from v1, and the subdomain switch behaves", async () => {
  const o = { login: "", counter: 1, template: T };
  const g2 = (site, fullHost = false) => v2.generateV2(mk, { ...o, site, fullHost });
  assert.notEqual(await c.generate(mk, { ...o, site: "github.com" }), await g2("github.com"));
  // one account, many subdomains
  assert.equal(await g2("https://accounts.google.com/signin"), await g2("mail.google.com"));
  assert.equal(await g2("gist.github.com"), await g2("github.com"));
  assert.notEqual(await c.generate(mk, { ...o, site: "accounts.google.com" }), await c.generate(mk, { ...o, site: "google.com" }));
  // separate accounts
  assert.notEqual(await g2("amazon.in"), await g2("amazon.com"));
  assert.notEqual(await g2("someone.github.io"), await g2("other.github.io"));
  assert.notEqual(await g2("a.myshopify.com"), await g2("b.myshopify.com"));
  // tenants the list lacks collapse, and the full-host switch separates them
  assert.equal(await g2("a.atlassian.net"), await g2("b.atlassian.net"));
  assert.notEqual(await g2("a.atlassian.net", true), await g2("b.atlassian.net", true));
  // the switch changes nothing when the host is already the registrable domain
  assert.equal(await g2("github.com", true), await g2("github.com"));
});

test("phishing: lookalike and embedded domains give different, unrelated passwords", async () => {
  const real = await v2.generateV2(mk, { site: "https://paypal.com/signin", template: T });
  const seen = new Set([real]), done = new Set();
  // (paypal.com@evil.com and evil.com/paypal.com are both really evil.com, so they share one password; that is right)
  for (const fake of ["https://paypa1-secure-login.com/", "https://paypal.com.evil.com/", "https://evil.com/paypal.com",
    "https://paypal.com.evil.co.uk/", "https://paypal.evil.github.io/", "https://раураl.com/", "https://xn--80ak6aa92e.com/", "https://paypal.co/", "https://paypaI.com/"]) {
    const site = v2.siteV2(fake);
    assert.notEqual(site, "paypal.com", fake);
    if (done.has(site)) continue; // several fakes can really be the same site (evil.com), which is fine
    done.add(site);
    const pw = await v2.generateV2(mk, { site: fake, template: T });
    assert.ok(!seen.has(pw), `${fake} gave a password already seen`);
    seen.add(pw);
  }
  assert.equal(await v2.generateV2(mk, { site: "https://paypal.com@evil.com/", template: T }), await v2.generateV2(mk, { site: "evil.com", template: T }));
  // …and the same real site reached any normal way is the same password
  assert.equal(await v2.generateV2(mk, { site: "www.PayPal.com", template: T }), real);
  assert.equal(await v2.generateV2(mk, { site: "https://www.paypal.com:443/a?b=c#d", template: T }), real);
  // no matching characters beyond chance between the real password and the lookalike's
  const fake = await v2.generateV2(mk, { site: "paypa1-secure-login.com", template: T });
  assert.ok([...real].filter((ch, i) => ch === fake[i]).length < 8);
});

test("v2 rejects bad inputs like v1", async () => {
  await assert.rejects(v2.generateV2(mk, { site: " ", template: T }), /site is empty/);
  await assert.rejects(v2.generateV2(mk, { site: "a.com", counter: 0, template: T }), /counter/);
  await assert.rejects(v2.generateV2(mk, { site: "a.com", template: { length: 3, classes: ["digits"] } }), /length/);
});

// ---- link helpers ----------------------------------------------------------------

test("share target: finds the link in url, text or title, and ignores junk", () => {
  const s = (o) => link.sharedUrl("?" + new URLSearchParams(o));
  assert.equal(s({ url: "https://accounts.google.com/signin" }), "https://accounts.google.com/signin");
  assert.equal(s({ title: "Sign in", text: "https://github.com/login", url: "" }), "https://github.com/login");   // Chrome: link in text
  assert.equal(s({ title: "Sign in", text: "Sign in to Zoho https://accounts.zoho.in/signin?x=1 now" }), "https://accounts.zoho.in/signin?x=1");
  assert.equal(s({ title: "Look at https://example.com/page." }), "https://example.com/page");
  assert.equal(s({ text: "(see https://example.com)" }), "https://example.com");
  assert.equal(s({ text: "see http://[::1]:8080/x]" }), "http://[::1]:8080/x");
  assert.equal(s({ url: "https://a.example", text: "https://b.example" }), "https://a.example");               // url field wins
  assert.equal(s({ url: "not a link", text: "HTTPS://B.EXAMPLE/x" }), "HTTPS://B.EXAMPLE/x");                 // falls through
  assert.equal(link.sharedUrl("?locked=1&text=https%3A%2F%2Fa.example%2F"), "https://a.example/");           // coexists with ?locked=
  for (const junk of [{}, { text: "" }, { text: "hello world" }, { url: "javascript:alert(1)" }, { text: "ftp://files.example/x" },
    { text: "data:text/html,<b>x</b>" }, { text: "http://" }, { text: "https:///x" }, { text: "https://?x" }, { title: "example.com" }]) {
    assert.equal(s(junk), null, JSON.stringify(junk));
  }
  assert.equal(link.sharedUrl(""), null);
  assert.equal(link.sharedUrl("?locked=idle"), null);
  // a share that arrives with a hostile-looking link still only yields a string for the site field
  // (a browser reads a backslash as a slash, so these are paypal.com and evil.com respectively)
  assert.equal(v2.siteV2(s({ text: "https://paypal.com\\@evil.com/" })), "paypal.com");
  assert.equal(v2.siteV2(s({ text: "https://evil.com\\@paypal.com/" })), "evil.com");
});

test("paste link: accepts links and addresses, refuses everything else", () => {
  assert.equal(link.linkOrHost("  https://mail.google.com/mail/u/0/  "), "https://mail.google.com/mail/u/0/");
  assert.equal(link.linkOrHost("github.com/login"), "github.com/login");
  assert.equal(link.linkOrHost("accounts.zoho.in"), "accounts.zoho.in");
  assert.equal(link.linkOrHost("bücher.de"), "bücher.de");
  for (const no of ["", "   ", "I_fiR2lN6_Srp3=%#5lP", "hunter2", "correct horse battery staple", "hello. world", "a.b", "x".repeat(5000)])
    assert.equal(link.linkOrHost(no), "", JSON.stringify(no.slice(0, 30)));
});

test("punycode encode agrees with Node's IDNA for many names", () => {
  for (const host of ["bücher.de", "münchen.de", "пример.рф", "例え.jp", "食狮.公司.cn", "аррӏе.com", "ドメイン.テスト", "عربي.com", "españa.es", "日本語.jp", "a-b.ü.de"]) {
    assert.equal(link.toAscii(host), domainToASCII(host), host);
  }
  assert.equal(link.toAscii("github.com"), "github.com");
});

test("lookalike flags: non-ASCII and mixed alphabets", () => {
  assert.deepEqual(link.hostFlags("github.com"), { nonAscii: false, mixed: false, ascii: "github.com" });
  assert.deepEqual(link.hostFlags("bücher.de"), { nonAscii: true, mixed: false, ascii: "xn--bcher-kva.de" });
  assert.equal(link.hostFlags("раураl.com").mixed, true);        // Cyrillic letters plus a Latin l
  assert.equal(link.hostFlags("раураl.com").ascii.startsWith("xn--"), true);
  assert.equal(link.hostFlags("аррӏе.com").mixed, false);         // all Cyrillic: non-ASCII flag only
  assert.equal(link.hostFlags("аррӏе.com").nonAscii, true);
  assert.equal(link.hostFlags("日本語テスト.jp").mixed, false);   // Japanese mixes scripts normally
  assert.equal(link.hostFlags("食狮.公司.cn").mixed, false);
  assert.equal(link.hostFlags("αbc.com").mixed, true);            // Greek alpha with Latin
});

test("lookalike warning: UI only, close to a known site but not equal", () => {
  const l = (site, host) => link.lookalike(site, host)?.domain ?? null;
  assert.equal(l("paypa1-secure-login.com"), "paypal.com");
  assert.equal(l("paypal-secure-login.com"), "paypal.com");
  assert.equal(l("gooogle.com"), "google.com");
  assert.equal(l("arnazon.com"), "amazon.com");
  assert.equal(l("micros0ft.com"), "microsoft.com");
  assert.equal(l("paypal.co"), "paypal.com");
  assert.equal(l("evil.com", "paypal.com.evil.com"), "paypal.com");
  for (const fine of ["paypal.com", "google.com", "github.com", "amazon.in", "example.com", "bücher.de", "acme.myshopify.com", "localhost", "192.168.1.1", "zoho.in", ""])
    assert.equal(l(fine), null, fine);
  assert.equal(link.editDistance("kitten", "sitting"), 3);
  assert.equal(link.editDistance("ab", "ba"), 1);
});

// Browser test: serves the folder, drives the UI, checks CSP, offline mode and output.
// Run: npm run e2e   (needs Playwright + Chromium; python3 for the static server)
const { chromium } = require("playwright");
const { spawn } = require("child_process");
const path = require("path");
const assert = require("assert/strict");
const vectors = require("./vectors.json");
const vectorsV2 = require("./vectors-v2.json");
const shots = process.env.SHOTS || "";
const root = path.join(__dirname, "..");

(async () => {
  const srv = spawn("python3", ["-m", "http.server", "8765", "--bind", "127.0.0.1"], { cwd: root, stdio: "ignore" });
  await new Promise((r) => setTimeout(r, 800));
  const browser = await chromium.launch();
  const problems = [];
  try {
    const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, permissions: ["clipboard-read", "clipboard-write"] });
    const page = await ctx.newPage();
    page.on("console", (m) => { if (["error", "warning"].includes(m.type())) problems.push(m.text()); });
    page.on("pageerror", (e) => problems.push(e.message));
    await page.goto("http://127.0.0.1:8765/");
    const manifest = await (await ctx.request.get("http://127.0.0.1:8765/manifest.webmanifest")).json();
    assert.deepEqual(manifest.share_target, { action: "./", method: "GET", params: { title: "title", text: "text", url: "url" } });

    const id = vectors[0];
    async function unlock() {
      await page.fill("#name", id.name);
      await page.fill("#secret", id.secret);
      const t0 = Date.now();
      await page.click("#unlock-btn");
      await page.waitForSelector("#vault:not([hidden])", { timeout: 20000 });
      return Date.now() - t0;
    }
    const ms = await unlock();
    console.log(`unlock (Argon2id 64 MiB, t=3) in browser: ${ms} ms`);
    assert.equal(await page.textContent("#fp-words"), id.fingerprint.join(" "));
    assert.equal(await page.inputValue("#secret"), "", "secret field cleared");
    if (shots) await page.screenshot({ path: `${shots}/unlocked-empty.png` });

    async function pw() {
      await page.waitForTimeout(250);
      const btn = await page.textContent("#reveal");
      if (btn === "Show") await page.click("#reveal");
      return page.textContent("#password");
    }
    async function setTemplate(length, classes) {
      const choice = [8, 12, 15, 20, 24].includes(length) ? String(length) : "other";
      await page.check(`#lengths input[value="${choice}"]`);
      if (choice === "other") await page.fill("#length", String(length));
      for (const k of ["lower", "upper", "digits", "symbols"])
        await page.setChecked(`#charsets input[value="${k}"]`, classes.includes(k));
    }
    async function setAlgo(n) { await page.check(`#algos input[value="${n}"]`); }
    assert.ok(await page.isChecked('#algos input[value="2"]'), "v2 is the default algorithm");
    await setAlgo(1);
    // every v1 vector, through the UI (covers the 5 length buttons, "Other", and charset toggles)
    for (const v of id.cases) {
      await page.fill("#site", v.site);
      await page.fill("#login", v.login);
      await page.fill("#counter", String(v.counter));
      await setTemplate(v.length, v.classes);
      assert.equal(await pw(), v.password, JSON.stringify(v));
    }
    const cv = id.cases.find((v) => v.site === "old-site.in");
    await page.fill("#site", cv.site); await page.fill("#login", ""); await page.fill("#counter", "1");
    await setTemplate(cv.length, cv.classes);
    assert.equal(await pw(), cv.password);
    assert.match(await page.textContent("#tpl-note"), /L16:aA9/);
    if (shots) await page.screenshot({ path: `${shots}/custom.png`, fullPage: true });

    assert.match(await page.textContent("#algo-note"), /Remember v1/);

    // v2: the real page address decides the site. Sample of the vectors, through the UI.
    await setAlgo(2);
    assert.equal(await page.textContent("#algo-note"), "");
    const v2cases = vectorsV2[0].cases.filter((v, i) => i % 5 === 0 || i >= vectorsV2[0].cases.length - 6);
    for (const v of v2cases) {
      await page.fill("#site", v.site);
      await page.fill("#login", v.login);
      await page.fill("#counter", String(v.counter));
      await page.setChecked("#full-host", v.fullHost);
      await setTemplate(v.length, v.classes);
      assert.equal(await pw(), v.password, JSON.stringify(v));
    }
    console.log(`v2 through the UI: ${v2cases.length} vectors ok`);
    await page.setChecked("#full-host", false); await page.fill("#login", ""); await page.fill("#counter", "1");
    await setTemplate(20, ["lower", "upper", "digits", "symbols"]);

    // the "made for" card
    await page.fill("#site", "https://accounts.google.com/signin?x=1");
    await page.waitForTimeout(250);
    assert.equal(await page.textContent("#su-site"), "google.com");
    assert.equal(await page.textContent("#su-from"), "from accounts.google.com");
    assert.ok(await page.isHidden("#su-idn") && await page.isHidden("#su-look"), "no warnings for a normal site");
    const googlePw = await pw();
    await page.fill("#site", "mail.google.com");
    assert.equal(await pw(), googlePw, "subdomains share the account password in v2");
    await page.check("#full-host");
    await page.waitForTimeout(250);
    assert.equal(await page.textContent("#su-site"), "mail.google.com");
    assert.notEqual(await pw(), googlePw, "full hostname gives a different password");
    assert.match(await page.textContent("#algo-note"), /full hostname/);
    await page.uncheck("#full-host");
    await setAlgo(1);
    assert.ok(await page.isHidden("#full-host-row"), "full-hostname switch is a v2 option");
    await setAlgo(2);

    // phishing: lookalike domains give different passwords and are flagged
    await page.fill("#site", "https://www.paypal.com/signin");
    const realPw = await pw();
    assert.ok(await page.isHidden("#su-look"));
    await page.fill("#site", "https://paypa1-secure-login.com/");
    const fakePw = await pw();
    assert.notEqual(fakePw, realPw);
    assert.ok(await page.isVisible("#su-look"));
    assert.match(await page.textContent("#su-look"), /paypal\.com/);
    await page.fill("#site", "https://paypal.com.evil.com/");
    await page.waitForTimeout(250);
    assert.equal(await page.textContent("#su-site"), "evil.com");
    assert.match(await page.textContent("#su-look"), /contains paypal\.com/);
    await page.fill("#site", "https://раураl.com/");
    await page.waitForTimeout(250);
    assert.ok(await page.isVisible("#su-idn"));
    assert.match(await page.textContent("#su-idn"), /xn--/);
    assert.match(await page.textContent("#su-idn"), /раураl\.com/);
    if (shots) await page.screenshot({ path: `${shots}/lookalike.png`, fullPage: true });

    // Paste link
    await page.evaluate(() => navigator.clipboard.writeText("Sign in https://accounts.zoho.in/signin?token=abc123"));
    await page.click("#paste-link");
    await page.waitForTimeout(250);
    assert.equal(await page.inputValue("#site"), "accounts.zoho.in", "only the host is kept");
    assert.equal(await page.textContent("#su-site"), "zoho.in");
    await page.evaluate(() => navigator.clipboard.writeText("I_fiR2lN6_Srp3=%#5lP"));
    await page.click("#paste-link");
    await page.waitForTimeout(250);
    assert.equal(await page.inputValue("#site"), "accounts.zoho.in", "a copied password is never pasted into the site field");
    assert.match(await page.textContent("#vault-msg"), /doesn't hold a link/);
    await page.evaluate(() => { Object.defineProperty(navigator.clipboard, "readText", { value: undefined, configurable: true }); });
    await page.click("#paste-link");
    assert.match(await page.textContent("#vault-msg"), /won't let Keyforge read the clipboard/);
    await page.evaluate(() => { delete navigator.clipboard.readText; });
    console.log("paste link: ok");
    await page.fill("#site", cv.site); await page.fill("#login", ""); await page.fill("#counter", "1");
    await setAlgo(1); await setTemplate(cv.length, cv.classes);
    assert.equal(await pw(), cv.password);

    // masked by default after hide
    await page.click("#reveal");
    assert.match(await page.textContent("#password"), /^•+$/);
    await page.click("#copy");
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), cv.password);

    // lock clears everything
    await page.click("#lock");
    await page.waitForSelector("#unlock-form:not([hidden])");
    assert.equal(await page.inputValue("#site"), "");
    assert.ok(await page.isChecked('#lengths input[value="20"]'), "length reset to 20");

    // offline: service worker must serve everything
    await page.waitForFunction(() => navigator.serviceWorker.controller !== null, null, { timeout: 10000 }).catch(async () => { await page.reload(); });
    await page.waitForFunction(() => navigator.serviceWorker.controller !== null, null, { timeout: 10000 });
    await ctx.setOffline(true);
    srv.kill();
    await page.reload();
    await unlock();
    await page.fill("#site", "https://github.com/login");
    const off = vectorsV2[0].cases.find((v) => v.site === "https://github.com/login" && !v.fullHost);
    assert.equal(await pw(), off.password, "works offline (v2)");
    console.log("offline reload + generate: ok");

    // Share Target launches go through the service worker too, query string and all
    const share = await ctx.newPage();
    share.on("pageerror", (e) => problems.push(e.message));
    await share.goto("http://127.0.0.1:8765/?title=Sign%20in&text=" + encodeURIComponent("Sign in https://accounts.google.com/signin?next=1") + "&locked=1");
    assert.equal(share.url(), "http://127.0.0.1:8765/", "query cleared");
    assert.match(await share.textContent("#share-note"), /Link received.*google\.com/);
    assert.match(await share.textContent("#unlock-msg"), /^Locked\./, "?locked= still works beside a share");
    await share.fill("#name", id.name); await share.fill("#secret", id.secret); await share.click("#unlock-btn");
    await share.waitForSelector("#vault:not([hidden])", { timeout: 20000 });
    assert.equal(await share.inputValue("#site"), "accounts.google.com");
    assert.equal(await share.textContent("#su-site"), "google.com");
    await share.waitForTimeout(300);
    await share.click("#reveal");
    const gv = vectorsV2[0].cases.find((v) => v.site === "accounts.google.com" && v.login === "");
    assert.ok(gv, "vector for accounts.google.com");
    assert.equal(await share.textContent("#password"), gv.password, "shared link gives the v2 password");
    await share.close();
    for (const junk of ["?text=hello%20world", "?url=javascript%3Aalert(1)", "?locked=idle"]) {
      const j = await ctx.newPage();
      await j.goto("http://127.0.0.1:8765/" + junk);
      assert.equal(j.url(), "http://127.0.0.1:8765/");
      assert.ok(await j.isHidden("#share-note"), junk);
      assert.equal(await j.inputValue("#site"), "");
      await j.close();
    }
    console.log("share target: ok");

    // dark mode screenshot
    if (shots) {
      const d = await browser.newContext({ viewport: { width: 390, height: 844 }, colorScheme: "dark" });
      const dp = await d.newPage();
      await d.setOffline(false);
      // reuse the cached SW? new context has none, so restart server just for the screenshot
      const s2 = spawn("python3", ["-m", "http.server", "8766", "--bind", "127.0.0.1"], { cwd: root, stdio: "ignore" });
      await new Promise((r) => setTimeout(r, 800));
      await dp.goto("http://127.0.0.1:8766/");
      await dp.screenshot({ path: `${shots}/locked-dark.png` });
      await dp.fill("#name", id.name); await dp.fill("#secret", id.secret); await dp.click("#unlock-btn");
      await dp.waitForSelector("#vault:not([hidden])", { timeout: 20000 });
      await dp.fill("#site", "github.com"); await dp.waitForTimeout(300); await dp.click("#reveal");
      await dp.waitForTimeout(700);
      await dp.screenshot({ path: `${shots}/vault-dark.png` });
      const w = await browser.newContext({ viewport: { width: 1280, height: 800 } });
      const wp = await w.newPage(); await wp.goto("http://127.0.0.1:8766/"); await wp.screenshot({ path: `${shots}/locked-desktop.png` });
      s2.kill();
    }

    const real = problems.filter((p) => !/Failed to load resource/.test(p) || !/offline|ERR_INTERNET/.test(p));
    assert.deepEqual(real, [], "console errors / CSP violations");
    // tampered offline cache must be refused (another page on the same origin could do this)
    await page.evaluate(async () => {
      for (const n of await caches.keys()) {
        const c = await caches.open(n);
        for (const r of await c.keys()) await c.put(r, new Response("<input id=secret>", { headers: { "content-type": "text/html" } }));
      }
    });
    await page.reload();
    assert.match(await page.textContent("body"), /failed their integrity check/, "poisoned cache refused");
    console.log("poisoned cache refused: ok");
    console.log("e2e: all checks passed");
  } finally {
    await browser.close();
    srv.kill();
  }
})().catch((e) => { console.error(e); process.exit(1); });

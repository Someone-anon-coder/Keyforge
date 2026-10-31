// Browser test: serves the folder, drives the UI, checks CSP, offline mode and output.
// Run: npm run e2e   (needs Playwright + Chromium; python3 for the static server)
const { chromium } = require("playwright");
const { spawn } = require("child_process");
const path = require("path");
const assert = require("assert/strict");
const vectors = require("./vectors.json");
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
    // every vector, through the UI (covers the 5 length buttons, "Other", and charset toggles)
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
    await page.fill("#site", "github.com");
    assert.equal(await pw(), id.cases[0].password, "works offline");
    console.log("offline reload + generate: ok");

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

import { LENGTH_CHOICES, DEFAULT_TEMPLATE, enc, normalizeSite, templateCode } from "./core.js";

// Refuse to run inside another page's frame (a same-origin page could read the fields).
if (window.top !== window.self) {
  document.documentElement.textContent = "Keyforge can't run inside another page. Open it directly.";
  throw new Error("framed");
}

const $ = (id) => document.getElementById(id);
const AUTO_LOCK_MS = 5 * 60 * 1000;
const CLIPBOARD_CLEAR_MS = 30 * 1000;

// ---- Worker RPC ----------------------------------------------------------
const worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
let nextId = 1;
const pending = new Map();
worker.onmessage = ({ data }) => {
  const p = pending.get(data.id);
  if (!p) return;
  pending.delete(data.id);
  data.ok ? p.resolve(data.result) : p.reject(new Error(data.error));
};
const call = (cmd, payload = {}, transfer = []) =>
  new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, cmd, ...payload }, transfer);
  });

// ---- Elements ------------------------------------------------------------
const form = $("unlock-form"), vault = $("vault"), lockBtn = $("lock");
const nameEl = $("name"), secretEl = $("secret"), unlockBtn = $("unlock-btn"), unlockMsg = $("unlock-msg");
const siteEl = $("site"), siteNorm = $("site-norm"), loginEl = $("login"), counterEl = $("counter");
const segRow = document.querySelector("#lengths .seg-row"), otherEl = $("other-length");
const lengthEl = $("length"), lengthOut = $("length-out"), charsetEl = $("charsets"), tplNote = $("tpl-note");
const pwEl = $("password"), revealBtn = $("reveal"), copyBtn = $("copy"), vaultMsg = $("vault-msg");

for (const v of [...LENGTH_CHOICES, "other"]) {
  const l = document.createElement("label");
  const r = document.createElement("input");
  r.type = "radio"; r.name = "kf-length"; r.value = String(v);
  r.checked = v === DEFAULT_TEMPLATE.length;
  l.append(r, v === "other" ? "Other" : String(v));
  segRow.append(l);
}

let current = "";       // last generated password, kept only in memory
let revealed = false;
let genSeq = 0;
let lockTimer = 0;
let clipTimer = 0;

// ---- Unlock / lock -------------------------------------------------------
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!nameEl.value.trim() || !secretEl.value) {
    setMsg(unlockMsg, "Enter your name and master secret.", true);
    return;
  }
  unlockBtn.disabled = true;
  setMsg(unlockMsg, "Working out your key…");
  try {
    // Send the secret as bytes and transfer them, so the worker can wipe the only copy it gets.
    const secret = enc(secretEl.value);
    secretEl.value = "";
    const fp = await call("unlock", { name: nameEl.value, secret }, [secret.buffer]);
    nameEl.value = "";
    showVault(fp);
  } catch (err) {
    setMsg(unlockMsg, `Couldn't unlock: ${err.message}`, true);
  } finally {
    unlockBtn.disabled = false;
  }
});

function showVault(fp) {
  setMsg(unlockMsg, "");
  drawKey($("fp-key"), fp.cuts);
  $("fp-words").textContent = fp.words.join(" ");
  form.hidden = true;
  vault.hidden = false;
  lockBtn.hidden = false;
  siteEl.focus();
  bumpLockTimer();
  regenerate();
}

// Locking kills the worker (freeing its WASM memory and heap) and reloads the page,
// so the old JavaScript heap with any copies of the secret is thrown away too.
// Only closing the app releases every copy of the secret (tested by scanning the browser's
// memory), so the installed app closes itself on lock when the browser allows it.
function lock(reason = "") {
  clearTimeout(lockTimer);
  worker.terminate();
  current = "";
  document.body.hidden = true;
  if (matchMedia("(display-mode: standalone)").matches) window.close();
  setTimeout(() => location.replace(location.pathname + (reason ? "?locked=idle" : "?locked=1")), 50);
}
const lockedParam = new URLSearchParams(location.search).get("locked");
if (lockedParam) {
  setMsg(unlockMsg, (lockedParam === "idle" ? "Locked after 5 minutes without use. " : "Locked. ") +
    "Close Keyforge completely when you're done; that clears your secret from memory.");
  history.replaceState(null, "", location.pathname);
}
lockBtn.addEventListener("click", () => lock());

function bumpLockTimer() {
  clearTimeout(lockTimer);
  if (!vault.hidden) lockTimer = setTimeout(() => lock("idle"), AUTO_LOCK_MS);
}
for (const ev of ["pointerdown", "keydown", "input"]) document.addEventListener(ev, bumpLockTimer, { passive: true });

// ---- Generation ----------------------------------------------------------
function readTemplate() {
  const choice = segRow.querySelector("input:checked").value;
  const length = choice === "other" ? Number(lengthEl.value) : Number(choice);
  const classes = [...charsetEl.querySelectorAll("input:checked")].map((c) => c.value);
  return { length, classes };
}

function syncCustom() {
  otherEl.hidden = segRow.querySelector("input:checked").value !== "other";
  lengthOut.textContent = lengthEl.value;
}

function resetTemplate() {
  for (const r of segRow.querySelectorAll("input")) r.checked = r.value === String(DEFAULT_TEMPLATE.length);
  for (const c of charsetEl.querySelectorAll("input")) c.checked = DEFAULT_TEMPLATE.classes.includes(c.value);
  lengthEl.value = String(DEFAULT_TEMPLATE.length);
  tplNote.textContent = "";
  syncCustom();
}

async function regenerate() {
  const seq = ++genSeq;
  const site = normalizeSite(siteEl.value);
  const template = readTemplate();
  const counter = Number(counterEl.value);

  siteNorm.innerHTML = "";
  if (site && site !== siteEl.value.trim()) {
    siteNorm.append("Using ");
    const c = document.createElement("code");
    c.textContent = site;
    siteNorm.append(c);
  }
  tplNote.textContent = "";
  if (template.classes.length && templateCode(template) !== templateCode(DEFAULT_TEMPLATE)) {
    const c = document.createElement("code");
    c.textContent = templateCode(template);
    tplNote.append("Not the default. Remember ", c, " for this site.");
  }

  if (!site) { current = ""; showPassword(); setMsg(vaultMsg, ""); return; }
  try {
    const pw = await call("generate", { opts: { site, login: loginEl.value, counter, template } });
    if (seq !== genSeq) return;
    current = pw;
    setMsg(vaultMsg, "");
  } catch (err) {
    if (seq !== genSeq) return;
    current = "";
    setMsg(vaultMsg, err.message === "locked" ? "" : fixMessage(err.message), true);
  }
  showPassword();
}

function fixMessage(m) {
  if (m.startsWith("counter")) return "Version must be a whole number from 1 upward.";
  if (m.startsWith("pick")) return "Pick at least one kind of character.";
  if (m.startsWith("length is shorter")) return "Make it longer, or pick fewer kinds of character.";
  return m.charAt(0).toUpperCase() + m.slice(1) + ".";
}

function showPassword() {
  copyBtn.disabled = !current;
  if (!current) { pwEl.textContent = "—"; pwEl.classList.remove("masked"); return; }
  pwEl.textContent = revealed ? current : "•".repeat(current.length);
  pwEl.classList.toggle("masked", !revealed);
}

let debounce = 0;
const schedule = () => { clearTimeout(debounce); debounce = setTimeout(regenerate, 120); };
for (const el of [siteEl, loginEl, counterEl]) el.addEventListener("input", schedule);
segRow.addEventListener("change", () => { syncCustom(); regenerate(); });
lengthEl.addEventListener("input", () => { syncCustom(); schedule(); });
charsetEl.addEventListener("change", regenerate);

function stepCounter(d) {
  const n = Math.min(4294967295, Math.max(1, (Number(counterEl.value) | 0) + d));
  counterEl.value = String(n);
  regenerate();
}
$("counter-dec").addEventListener("click", () => stepCounter(-1));
$("counter-inc").addEventListener("click", () => stepCounter(1));

revealBtn.addEventListener("click", () => {
  revealed = !revealed;
  revealBtn.textContent = revealed ? "Hide" : "Show";
  revealBtn.setAttribute("aria-pressed", String(revealed));
  showPassword();
});

document.addEventListener("visibilitychange", () => {
  if (document.hidden && revealed) revealBtn.click();
});

copyBtn.addEventListener("click", async () => {
  if (!current) return;
  const copied = current;
  try {
    await navigator.clipboard.writeText(copied);
    setMsg(vaultMsg, "Copied. The clipboard is cleared in 30 seconds if Keyforge is still open.");
    clearTimeout(clipTimer);
    clipTimer = setTimeout(async () => {
      try { await navigator.clipboard.writeText(""); setMsg(vaultMsg, "Clipboard cleared."); } catch { /* page not focused */ }
    }, CLIPBOARD_CLEAR_MS);
  } catch {
    setMsg(vaultMsg, "Couldn't copy. Tap Show and copy it by hand.", true);
  }
});

function setMsg(el, text, isError = false) {
  el.textContent = text;
  el.classList.toggle("error", isError);
}

// ---- Fingerprint key drawing ---------------------------------------------
const SVG = "http://www.w3.org/2000/svg";
function drawKey(svg, cuts) {
  svg.replaceChildren();
  // Blade bottom edge runs right-to-left through 8 cuts; deeper cut = larger value.
  let d = "M58 30 L204 30 L214 40 L204 50";
  for (let i = 7; i >= 0; i--) {
    const x0 = 80 + i * 15, x1 = x0 + 15, depth = 54 + cuts[i] * 3;
    d += ` L${x1} 50 L${x1 - 4} ${depth} L${x0 + 4} ${depth} L${x0} 50`;
  }
  d += " L58 50 Z";
  const g = document.createElementNS(SVG, "g");
  g.setAttribute("class", "key");
  const bow = document.createElementNS(SVG, "circle");
  bow.setAttribute("cx", "34"); bow.setAttribute("cy", "40"); bow.setAttribute("r", "26");
  const blade = document.createElementNS(SVG, "path");
  blade.setAttribute("d", d);
  g.append(bow, blade);
  const hole = document.createElementNS(SVG, "circle");
  hole.setAttribute("class", "hole");
  hole.setAttribute("cx", "26"); hole.setAttribute("cy", "40"); hole.setAttribute("r", "8");
  const groove = document.createElementNS(SVG, "line");
  groove.setAttribute("class", "groove");
  groove.setAttribute("x1", "66"); groove.setAttribute("y1", "38"); groove.setAttribute("x2", "200"); groove.setAttribute("y2", "38");
  svg.append(g, hole, groove);
  svg.classList.remove("cut");
  void svg.getBoundingClientRect();
  svg.classList.add("cut");
}

// ---- Offline support -----------------------------------------------------
if ("serviceWorker" in navigator && location.protocol !== "file:") {
  navigator.serviceWorker.register("./sw.js").catch(() => {});
}

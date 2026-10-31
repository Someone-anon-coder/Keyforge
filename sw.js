// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Someone-anon-coder
// Cache-first service worker: after the first visit the app works with no network.
// Every file is checked against the SHA-256 list below before it is served, so a
// tampered cache (e.g. from another page on the same origin) is refused.
// Don't edit the block below by hand: run `python3 tools/stamp.py` after changing any file.
// STAMP-BEGIN
const CACHE = "keyforge-9d05601b4755";
const HASHES = {
  "index.html": "a021df78bf913c42abd77bb9a89646de8a7e52e20e922806f34e703561cb6c3d",
  "app.css": "8468394cf817df0ef85946dd7b80caee032bd70611a8d732e5eef541a120fa71",
  "app.js": "54cd94e3db5ab84dfc94f075880aba7fa838c6e2206c1ada2f9b919d24738dc3",
  "core.js": "118cd421cd93a02cc401cb526b276cbca69cd358a6b1f32ad715e9d7e3916903",
  "worker.js": "5701dc3eba5e3fb16e8ead3cd52bf96c2cfac55546df9d7d4580a8644e204cbe",
  "vendor/argon2.umd.min.js": "dcec617a2e1b700fa132d1583a186cb70611113395e869f2dd6cc82b415d3094",
  "manifest.webmanifest": "51877754793af2ed43f97b052e6d9e1b7b54430c4b07cfcb988c9fb2207cc70c",
  "icons/icon.svg": "4c721b900a426c78d2d80d77f084a4a9f9f0c1af5420d85ac805a504e7ea1435",
  "icons/icon-180.png": "86b14a090cdc6eb3685cebc0fd93a4721a1706eeb487e83349ab64ba68f06c65",
  "icons/icon-192.png": "33b9e5d29db08958008e435e55702cba560ff743aabb6fdc63e11e2c04a78109",
  "icons/icon-512.png": "9ba39cae42bc12e20451a04cd3a7f1d3fdd038f250401797444aa32644dd3c32",
  "icons/icon-maskable-512.png": "d80582a14f9f35668a176750541ba75dfe472f8a7acc5b74631595612af5c713"
};
// STAMP-END

const scopePath = new URL(self.registration.scope).pathname;
const rel = (url) => {
  const p = new URL(url).pathname;
  if (!p.startsWith(scopePath)) return null;
  const r = p.slice(scopePath.length);
  return r === "" ? "index.html" : r;
};
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function ok(path, res) {
  if (!res || !res.ok) return false;
  const digest = await crypto.subtle.digest("SHA-256", await res.clone().arrayBuffer());
  return hex(digest) === HASHES[path];
}
const refuse = () =>
  new Response("Keyforge's files failed their integrity check. Connect to the internet and reload.", {
    status: 503,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });

async function fetchVerified(path) {
  const res = await fetch(scopePath + (path === "index.html" ? "" : path), { cache: "no-store" });
  if (!(await ok(path, res))) throw new Error(`integrity check failed for ${path}`);
  return res;
}

self.addEventListener("install", (e) => {
  e.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    for (const path of Object.keys(HASHES)) await cache.put(scopePath + path, await fetchVerified(path));
    await self.skipWaiting();
  })());
});

self.addEventListener("activate", (e) => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k !== CACHE) await caches.delete(k);
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (e) => {
  if (e.request.method !== "GET") return;
  const path = rel(e.request.url);
  if (path === null) return;
  if (!(path in HASHES)) { e.respondWith(refuse()); return; }
  e.respondWith((async () => {
    const cache = await caches.open(CACHE);
    const hit = await cache.match(scopePath + path);
    if (await ok(path, hit)) return hit;
    try {
      const res = await fetchVerified(path);
      await cache.put(scopePath + path, res.clone());
      return res;
    } catch {
      return refuse();
    }
  })());
});

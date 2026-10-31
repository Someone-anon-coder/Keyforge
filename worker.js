// Holds the master key. The key never leaves this worker; the page only
// receives the fingerprint and finished passwords. On lock the page
// terminates this worker, which unmaps its WASM memory and heap.
import "./vendor/argon2.umd.min.js"; // sets globalThis.hashwasm
import { deriveMasterKey, fingerprint, generate, importHmacKey } from "./core.js";

let masterKey = null; // non-extractable CryptoKey

self.onmessage = async ({ data }) => {
  const { id, cmd } = data;
  try {
    let result;
    if (cmd === "unlock") {
      const secret = data.secret; // Uint8Array, transferred from the page
      let raw;
      try {
        raw = await deriveMasterKey(data.name, secret, globalThis.hashwasm.argon2id);
        masterKey = await importHmacKey(raw);
      } finally {
        secret.fill(0);
        if (raw) raw.fill(0);
      }
      result = await fingerprint(masterKey);
    } else if (cmd === "generate") {
      if (!masterKey) throw new Error("locked");
      result = await generate(masterKey, data.opts);
    } else {
      throw new Error(`unknown command ${cmd}`);
    }
    self.postMessage({ id, ok: true, result });
  } catch (e) {
    self.postMessage({ id, ok: false, error: e.message });
  }
};

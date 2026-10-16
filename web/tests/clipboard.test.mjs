/* Behavioural tests for web/frontend/secure-clipboard.js.
 *
 * The previous "clipboard hardening" was only ever asserted by grepping the
 * source for function names, which proves nothing about behaviour. These tests
 * run the real module in a VM with a fake clipboard, so the properties that
 * matter are actually exercised:
 *
 *   • a credential-shaped value is never written to the clipboard;
 *   • the user's own clipboard content is never destroyed (the TTL wipe is
 *     conditional on the clipboard still holding the value we wrote);
 *   • failures are reported instead of silently swallowed.
 *
 * Run: node --test web/tests/
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import vm from "node:vm";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SOURCE = readFileSync(path.join(HERE, "..", "frontend", "secure-clipboard.js"), "utf8");

/** Load the IIFE with a fake browser around it. */
function loadHelper({ clipboard = {}, storage = {} } = {}) {
  const writes = [];
  const fakeClipboard = clipboard === null ? null : {
    readText: clipboard.readText,
    writeText: clipboard.writeText ?? (async (value) => { writes.push(value); }),
  };
  const sandbox = {
    window: {},
    navigator: fakeClipboard ? { clipboard: fakeClipboard } : {},
    localStorage: {
      getItem: (key) => (key in storage ? storage[key] : null),
      setItem: (key, value) => { storage[key] = value; },
    },
    setTimeout,
    clearTimeout,
    console,
  };
  vm.createContext(sandbox);
  vm.runInContext(SOURCE, sandbox);
  return { api: sandbox.window.FeeFixClipboard, writes, fakeClipboard, storage };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test("refuses to copy a token-shaped value (never writes it)", async () => {
  const { api, writes } = loadHelper();
  const result = await api.secureCopy("A".repeat(43));
  assert.equal(result.ok, false);
  assert.equal(result.copied, false);
  assert.equal(result.reason, "refused-credential-shaped");
  assert.deepEqual(writes, []);
});

test("refuses to copy the live session token from localStorage", async () => {
  const token = "session-token-value-1234";
  const { api, writes } = loadHelper({ storage: { "feefix.token": token } });
  assert.equal(api.looksLikeSecret(token), true);
  const result = await api.secureCopy(token);
  assert.equal(result.copied, false);
  assert.deepEqual(writes, []);
});

test("copies ordinary text and reports success", async () => {
  const { api, writes } = loadHelper();
  const result = await api.secureCopy("Scheme: WB MCM Scholarship", { ttl: 0 });
  assert.equal(result.ok, true);
  assert.equal(result.copied, true);
  assert.deepEqual(writes, ["Scheme: WB MCM Scholarship"]);
});

test("reports a failure instead of silently dropping it when the API is missing", async () => {
  const { api } = loadHelper({ clipboard: null });
  const result = await api.secureCopy("hello world", { ttl: 0 });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "clipboard-unavailable");
});

test("reports a failure when the browser denies the write", async () => {
  const { api } = loadHelper({
    clipboard: { writeText: async () => { throw new Error("NotAllowedError"); } },
  });
  const result = await api.secureCopy("hello world", { ttl: 0 });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "write-denied");
});

test("TTL wipe clears the clipboard only while it still holds our value", async () => {
  const clipboard = { value: "" };
  const { api } = loadHelper({
    clipboard: {
      writeText: async (value) => { clipboard.value = value; },
      readText: async () => clipboard.value,
    },
  });
  await api.secureCopy("temp code 1234", { ttl: 10 });
  assert.equal(clipboard.value, "temp code 1234");
  await sleep(40);
  assert.equal(clipboard.value, "", "our value should have been wiped after the TTL");
});

test("TTL wipe leaves a different value alone (user copied something else)", async () => {
  const clipboard = { value: "" };
  const { api } = loadHelper({
    clipboard: {
      writeText: async (value) => { clipboard.value = value; },
      readText: async () => clipboard.value,
    },
  });
  await api.secureCopy("temp code 1234", { ttl: 10 });
  clipboard.value = "the user's own password they just copied"; // user action
  await sleep(40);
  assert.equal(
    clipboard.value,
    "the user's own password they just copied",
    "the helper must not destroy content it did not write"
  );
});

test("cannot verify ⇒ nothing is wiped (no blind writeText(''))", async () => {
  const clipboard = { value: "user content" };
  const { api } = loadHelper({
    clipboard: {
      writeText: async (value) => { clipboard.value = value; },
      // readText intentionally absent
    },
  });
  const result = await api.clearClipboard({ expect: "user content" });
  assert.equal(result.cleared, false);
  assert.equal(result.reason, "cannot-verify");
  assert.equal(clipboard.value, "user content");
});

test("explicit clear with a matching value does wipe", async () => {
  const clipboard = { value: "123456" };
  const { api } = loadHelper({
    clipboard: {
      writeText: async (value) => { clipboard.value = value; },
      readText: async () => clipboard.value,
    },
  });
  const result = await api.clearClipboard({ expect: "123456" });
  assert.equal(result.cleared, true);
  assert.equal(clipboard.value, "");
});

test("capability probe is honest about verification being unavailable", async () => {
  const { api } = loadHelper({ clipboard: { writeText: async () => {} } });
  const caps = api.canProtect();
  assert.equal(caps.available, true);
  assert.equal(caps.verifyBeforeClear, false);
  assert.match(caps.note, /never guarantees/i);
});

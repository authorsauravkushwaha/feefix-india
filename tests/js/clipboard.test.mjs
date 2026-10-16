/* =========================================================================
   Tests for web/frontend/secure-clipboard.js

   Run with:  node tests/js/clipboard.test.mjs
   ========================================================================== */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(
  resolve(here, "..", "..", "web", "frontend", "secure-clipboard.js"),
  "utf8"
);

let failures = 0;
const check = (name, condition, detail = "") => {
  if (condition) {
    console.log(`  ✓ ${name}`);
  } else {
    failures += 1;
    console.error(`  ✗ ${name}${detail ? ` — ${detail}` : ""}`);
  }
};

function load({ clipboard = true, writeText, storage = {} } = {}) {
  const written = [];
  const listeners = {};
  const navigator = clipboard
    ? {
        clipboard: {
          writeText:
            writeText ||
            (async (text) => {
              written.push(text);
            }),
        },
      }
    : {};
  const localStorage = {
    getItem: (key) => (key in storage ? storage[key] : null),
  };
  const document = {
    visibilityState: "visible",
    addEventListener: (event, handler) => {
      (listeners[event] ||= []).push(handler);
    },
  };
  const window = {};
  const setTimeoutCalls = [];
  const factory = new Function(
    "window",
    "navigator",
    "localStorage",
    "document",
    "setTimeout",
    `${source}\nreturn window.FeeFixClipboard;`
  );
  const api = factory(window, navigator, localStorage, document, (...args) => {
    setTimeoutCalls.push(args);
    return 0;
  });
  return { api, written, listeners, setTimeoutCalls };
}

console.log("FeeFix clipboard hygiene:");

{
  const { api, written, setTimeoutCalls } = load();
  const result = await api.copyWithHygiene("Application reference 12345");
  check("copies ordinary text", result.ok === true && result.reason === "copied");
  check("wrote the value through", written[0] === "Application reference 12345");
  check("does not schedule a clear", setTimeoutCalls.length === 0);
  check("does not claim a ttl", result.ttlMs === undefined);
}

{
  const { api, written } = load();
  const cases = [
    ["opaque session token", "A".repeat(40)],
    ["6-digit one-time code", "123456"],
    ["the stored auth token", "stored-token-value"],
  ];
  const storage = { "feefix.token": "stored-token-value" };
  const withStorage = load({ storage });
  for (const [label, value] of cases) {
    const target = label === "the stored auth token" ? withStorage.api : api;
    const result = await target.copyWithHygiene(value);
    check(
      `refuses ${label}`,
      result.ok === false && result.reason === "refused-credential-shaped-value"
    );
  }
  check("nothing credential-shaped reached the clipboard", written.length === 0);
  check("empty values are refused too", (await api.copyWithHygiene("")).ok === false);
}

{
  const unavailable = load({ clipboard: false });
  const r1 = await unavailable.api.copyWithHygiene("hello");
  check(
    "reports clipboard-unavailable",
    r1.ok === false && r1.reason === "clipboard-unavailable"
  );

  const denied = load({
    writeText: async () => {
      throw new Error("NotAllowedError");
    },
  });
  const r2 = await denied.api.copyWithHygiene("hello");
  check(
    "reports denied-or-unfocused instead of pretending success",
    r2.ok === false && r2.reason === "denied-or-unfocused"
  );
  check(
    "clearClipboard reports the same failure honestly",
    (await denied.api.clearClipboard()).ok === false
  );
}

{
  const { api, listeners } = load();
  check("does not register visibilitychange", !(listeners.visibilitychange || []).length);
  check("source does not call addEventListener", !source.includes("addEventListener"));
  check("clear timers always verify before wiping", source.includes("clearClipboard({ expect: value })"));
}

{
  const { api } = load();
  const described = api.describe();
  check("declares itself non-security", described.securityControl === false);
  check("declares it does not auto-clear", described.autoClears === false);
  check("declares it does not clear on hide", described.clearsOnHide === false);
  check(
    "lists its limitations",
    Array.isArray(described.limitations) && described.limitations.length >= 4
  );
  check(
    "limitations mention malware/keyloggers",
    described.limitations.join(" ").toLowerCase().includes("malware")
  );
  check("exposes the legacy boolean API", typeof api.secureCopy === "function");
  check("legacy API still refuses tokens", (await api.secureCopy("B".repeat(40))).ok === false);
}

if (failures > 0) {
  console.error(`\n${failures} clipboard test(s) failed`);
  process.exit(1);
}
console.log("\nall clipboard tests passed");

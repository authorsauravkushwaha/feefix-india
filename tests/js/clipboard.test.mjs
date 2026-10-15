/* ==========================================================================
   Tests for web/frontend/secure-clipboard.js

   Run with:  node tests/js/clipboard.test.mjs
   (pytest invokes this from tests/test_clipboard_js.py so it runs with the
   normal suite; no npm dependency is required.)

   The module is loaded with stub DOM/Clipboard globals so we can assert on the
   one thing that is objectively testable — that it refuses credential-shaped
   values, reports failures instead of swallowing them, and does not claim to be
   a security control it cannot be.
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

/** Build a fresh module instance with captured globals. */
function load({ clipboard = true, writeText, storage = {}, hidden = false } = {}) {
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
    visibilityState: hidden ? "hidden" : "visible",
    addEventListener: (event, handler) => {
      (listeners[event] ||= []).push(handler);
    },
  };
  const window = {};
  // The module is an IIFE that reads these as free variables: pass them in.
  const factory = new Function(
    "window",
    "navigator",
    "localStorage",
    "document",
    `${source}\nreturn window.FeeFixClipboard;`
  );
  const api = factory(window, navigator, localStorage, document);
  return { api, written, listeners, document };
}

console.log("FeeFix clipboard hygiene:");

// 1) ordinary values are copied
{
  const { api, written } = load();
  const result = await api.copyWithHygiene("Application reference 12345");
  check("copies ordinary text", result.ok === true && result.reason === "copied");
  check("wrote the value through", written[0] === "Application reference 12345");
}

// 2) credential-shaped values are refused *before* touching the clipboard
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
    check(`refuses ${label}`, result.ok === false && result.reason === "refused-credential-shaped-value");
  }
  check("nothing credential-shaped reached the clipboard", written.length === 0);
  check("empty values are refused too", (await api.copyWithHygiene("")).ok === false);
}

// 3) failures are reported, never swallowed
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

// 4) the TTL clear actually fires
{
  const { api, written } = load();
  await api.copyWithHygiene("temporary value", { ttl: 5 });
  await new Promise((r) => setTimeout(r, 30));
  check("clears the clipboard after the TTL", written.includes(""));
}

// 5) clearing on page hide
{
  const { api, written, listeners } = load({ hidden: true });
  check("registers a visibilitychange listener", (listeners.visibilitychange || []).length === 1);
  await listeners.visibilitychange[0]();
  check("clears the clipboard when the page is hidden", written.includes(""));
}

// 6) honesty: the module must not claim to be a security control
{
  const { api } = load();
  const described = api.describe();
  check("declares itself non-security", described.securityControl === false);
  check("lists its limitations", Array.isArray(described.limitations) && described.limitations.length >= 4);
  check(
    "limitations mention malware/keyloggers",
    described.limitations.join(" ").toLowerCase().includes("malware")
  );
  check("exposes the legacy boolean API", typeof api.secureCopy === "function");
  check("legacy API still refuses tokens", (await api.secureCopy("B".repeat(40))) === false);
}

if (failures > 0) {
  console.error(`\n${failures} clipboard test(s) failed`);
  process.exit(1);
}
console.log("\nall clipboard tests passed");

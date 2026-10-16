/* ==========================================================================
   FeeFix clipboard hygiene — a USABILITY measure, not a security control.

   WHAT THIS FILE CAN DO
     • refuse to copy credential-shaped values (the auth token, an OTP code
       pattern) so *the user* cannot accidentally paste a session credential
       into a chat, a form, or a support ticket;
     • clear the clipboard shortly after a copy, and again when the page is
       hidden, so a copied value does not sit there indefinitely;
     • report honestly whether the write/clear actually happened.

   WHAT THIS FILE CANNOT DO — and must never be claimed to do
     • It cannot stop clipboard *theft*. Malware, a rogue extension or a
       keylogger reads the value the instant it is written — long before any
       timer fires. The timer is a housekeeping nicety, not a defence.
     • It cannot stop keyloggers or memory scraping, and it cannot revoke what
       has already been read.
     • It is browser- and permission-dependent: the async Clipboard API needs a
       secure context, a user gesture and (on some browsers) explicit consent,
       and the "clear" step silently fails when the document is not focused.
       That is why every entry point returns a structured result instead of a
       bare boolean — failures are visible to the caller, not swallowed.
     • It says nothing about other devices or about data already in transit.

   THE REAL CONTROLS for the token live server-side: opaque 256-bit tokens,
   only their SHA-256 hash stored, rotation with replay detection, revocation on
   logout, `Cache-Control: no-store`, and a CSP that forbids remote scripts.
   This helper is the least important layer; it is documented as such in
   docs/security/HARDENING.md so nobody mistakes it for defence in depth it
   cannot provide.
   ========================================================================== */
(() => {
  "use strict";

  const CLIPBOARD_TTL_MS = 20000; // housekeeping: drop a copied value after 20s
  const TOKEN_HINT = /^[A-Za-z0-9_-]{32,}$/; // opaque session-token shape
  const CODE_HINT = /^\d{6}$/; // one-time codes are 6 digits here

  const LIMITATIONS = Object.freeze([
    "Cannot stop malware, extensions or keyloggers from reading the clipboard.",
    "Cannot undo a value that has already been copied and read.",
    "Clearing may fail silently if the page loses focus or the browser denies permission.",
    "Protects only this browser profile — not other devices or already-sent data.",
  ]);

  function looksLikeSecret(value) {
    if (typeof value !== "string" || !value.trim()) return true;
    try {
      const stored = localStorage.getItem("feefix.token");
      if (stored && value.trim() === stored.trim()) return true;
    } catch (_) {
      /* localStorage can be blocked; the shape checks below still apply */
    }
    const trimmed = value.trim();
    return TOKEN_HINT.test(trimmed) || CODE_HINT.test(trimmed);
  }

  function clipboardAvailable() {
    return !!(navigator.clipboard && navigator.clipboard.writeText);
  }

  async function clearClipboard() {
    if (!clipboardAvailable()) return { ok: false, reason: "clipboard-unavailable" };
    try {
      await navigator.clipboard.writeText("");
      return { ok: true, reason: "cleared" };
    } catch (_) {
      return { ok: false, reason: "denied-or-unfocused" };
    }
  }

  /**
   * Copy `text` if it is not credential-shaped.
   * @returns {Promise<{ok: boolean, reason: string, ttlMs?: number}>}
   */
  async function copyWithHygiene(text, { ttl = CLIPBOARD_TTL_MS } = {}) {
    if (looksLikeSecret(text)) {
      // The one genuinely useful thing here: a credential never reaches the
      // clipboard because *we* refuse to put it there.
      return { ok: false, reason: "refused-credential-shaped-value" };
    }
    if (!clipboardAvailable()) return { ok: false, reason: "clipboard-unavailable" };
    try {
      await navigator.clipboard.writeText(String(text));
    } catch (_) {
      return { ok: false, reason: "denied-or-unfocused" };
    }
    if (ttl > 0) setTimeout(clearClipboard, ttl);
    return { ok: true, reason: "copied", ttlMs: ttl };
  }

  /** Back-compat boolean wrapper (older call sites). */
  async function secureCopy(text, options) {
    const result = await copyWithHygiene(text, options);
    return result.ok;
  }

  // Housekeeping: drop a copied value when the user leaves the page/tab.
  if (typeof document !== "undefined" && document.addEventListener) {
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "hidden") clearClipboard();
    });
  }

  window.FeeFixClipboard = {
    secureCopy, // legacy boolean API
    copyWithHygiene, // structured API — prefer this
    clearClipboard,
    looksLikeSecret,
    limitations: LIMITATIONS,
    describe: () => ({
      available: clipboardAvailable(),
      ttlMs: CLIPBOARD_TTL_MS,
      // Explicit, in-code admission of what this module is not.
      securityControl: false,
      limitations: LIMITATIONS.slice(),
    }),
  };
})();

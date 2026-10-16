/* ==========================================================================
   FeeFix clipboard helper — UX hygiene, NOT a security control.

   Read this before trusting it. This module cannot stop clipboard theft:
   malware (or any process with clipboard access) reads the value the instant
   it is written, keyloggers and memory scrapers bypass the clipboard entirely,
   and the browser clipboard API is permission- and focus-dependent, so it
   fails on some devices. A "clipboard clears itself after 20 s" line is a
   usability nicety, not a defence — anyone claiming otherwise is selling
   comfort.

   What is actually enforced here (and that a control *can* enforce):

     1. CREDENTIALS ARE NEVER COPIED. secureCopy() refuses the session token or
        anything token-shaped. This is a real, testable rule — FeeFix never
        needs a session token on the clipboard, so refusing is free.
     2. NEVER CLOBBER THE USER'S CLIPBOARD. The old implementation called
        writeText("") on a timer, destroying whatever the user had copied since
        (and happily erasing *unrelated* sensitive content). Now a wipe happens
        only after reading the clipboard back and confirming it still holds the
        value we wrote — otherwise we leave it alone.
     3. FAILURES ARE REPORTED, NOT SWALLOWED. Every call resolves to
        {ok, reason} so the UI can tell the user "copy failed, select it
        manually" instead of silently doing nothing.

   The real controls against credential theft live server-side: opaque
   hashed-at-rest session tokens, rotation, replay quarantine, short-lived OTPs,
   and rate limits.
   ========================================================================== */
(() => {
  "use strict";

  const CLIPBOARD_TTL_MS = 20000; // courtesy wipe, only if the value is still ours
  const TOKEN_HINT = /^[A-Za-z0-9_-]{32,}$/; // opaque session tokens

  let lastWritten = null;   // value we wrote, so we can verify before wiping
  let pendingTimer = null;

  function clipboardApi() {
    const api = (typeof navigator !== "undefined" && navigator.clipboard) || null;
    if (!api || typeof api.writeText !== "function") return null;
    return api;
  }

  function looksLikeSecret(value) {
    if (typeof value !== "string") return true;
    if (TOKEN_HINT.test(value.trim())) return true;
    try {
      const stored = localStorage.getItem("feefix.token");
      if (stored && value === stored) return true;
    } catch (_) {
      /* localStorage unavailable (private mode / blocked) — the regex still applies */
    }
    return false;
  }

  /* Clipboard access is permission-gated; tell the caller what is possible. */
  function canProtect() {
    const api = clipboardApi();
    return {
      available: Boolean(api),
      verifyBeforeClear: Boolean(api && typeof api.readText === "function"),
      note:
        "Clipboard writes/reads depend on browser permission and page focus; " +
        "this helper never guarantees that a copied value is unreachable by " +
        "other software on the device.",
    };
  }

  function cancelPendingWipe() {
    if (pendingTimer) {
      clearTimeout(pendingTimer);
      pendingTimer = null;
    }
  }

  /**
   * Wipe the clipboard only if it still contains the value we put there.
   * @returns {Promise<{ok: boolean, cleared: boolean, reason?: string}>}
   */
  async function clearClipboard({ force = false, expect = null } = {}) {
    cancelPendingWipe();
    const api = clipboardApi();
    if (!api) return { ok: false, cleared: false, reason: "clipboard-unavailable" };

    const target = expect !== null ? expect : lastWritten;
    if (!force) {
      if (target === null) return { ok: true, cleared: false, reason: "nothing-of-ours" };
      if (typeof api.readText !== "function") {
        // Cannot verify ⇒ do not destroy the user's clipboard content.
        return { ok: true, cleared: false, reason: "cannot-verify" };
      }
      let current = null;
      try {
        current = await api.readText();
      } catch (_) {
        return { ok: true, cleared: false, reason: "read-denied" };
      }
      if (current !== target) return { ok: true, cleared: false, reason: "clipboard-changed" };
    }

    try {
      await api.writeText("");
      lastWritten = null;
      return { ok: true, cleared: true };
    } catch (_) {
      return { ok: false, cleared: false, reason: "write-denied" };
    }
  }

  /**
   * Copy a non-credential value, optionally wiping it later — but only if the
   * clipboard still holds exactly that value.
   * @returns {Promise<{ok: boolean, copied: boolean, ttlMs: number, reason?: string}>}
   */
  async function secureCopy(text, { ttl = CLIPBOARD_TTL_MS } = {}) {
    if (looksLikeSecret(text)) {
      // Never place a credential on the clipboard. Refusal is the feature.
      return { ok: false, copied: false, ttlMs: 0, reason: "refused-credential-shaped" };
    }
    const api = clipboardApi();
    if (!api) return { ok: false, copied: false, ttlMs: 0, reason: "clipboard-unavailable" };

    const value = String(text);
    try {
      await api.writeText(value);
    } catch (_) {
      return { ok: false, copied: false, ttlMs: 0, reason: "write-denied" };
    }
    lastWritten = value;

    if (ttl > 0 && typeof setTimeout === "function") {
      cancelPendingWipe();
      pendingTimer = setTimeout(() => {
        pendingTimer = null;
        void clearClipboard({ expect: value });
      }, ttl);
    }
    return { ok: true, copied: true, ttlMs: ttl };
  }

  window.FeeFixClipboard = {
    secureCopy,
    clearClipboard,
    looksLikeSecret,
    canProtect,
    CLIPBOARD_TTL_MS,
  };
})();

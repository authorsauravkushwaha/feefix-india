/* ==========================================================================
   FeeFix secure clipboard — clipboard-attack hardening.

   A "clipboard attack" is anything that reads what a user copies: malware, a
   malicious page, or a lingering clipboard entry that a later paste leaks into
   the wrong place. This module gives the app ONE safe way to copy:

     • secureCopy(text)  — writes, then clears the clipboard after a short TTL
                            so a copied code/OTP doesn't sit in the clipboard
                            forever, and REFUSES to copy the auth token or any
                            value that looks like a session credential.
     • clearClipboard()  — best-effort immediate wipe (used after OTP paste-fill).

   The auth token is never a valid copy target here — it lives in localStorage,
   never the clipboard, never a URL, never a log.
   ========================================================================== */
(() => {
  "use strict";

  const CLIPBOARD_TTL_MS = 20000; // wipe a copied value after 20s
  const TOKEN_HINT = /feefix\.token|^[A-Za-z0-9_-]{32,}$/; // opaque session tokens

  function looksLikeSecret(value) {
    if (typeof value !== "string") return true;
    try {
      const stored = localStorage.getItem("feefix.token");
      if (stored && value === stored) return true;
    } catch (_) {}
    return TOKEN_HINT.test(value.trim());
  }

  async function clearClipboard() {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText("");
      }
    } catch (_) { /* clipboard may be permission-restricted — best effort */ }
  }

  async function secureCopy(text, { ttl = CLIPBOARD_TTL_MS } = {}) {
    if (looksLikeSecret(text)) {
      // Never place a credential on the clipboard.
      return false;
    }
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(String(text));
      } else {
        return false;
      }
    } catch (_) {
      return false;
    }
    if (ttl > 0) setTimeout(clearClipboard, ttl);
    return true;
  }

  window.FeeFixClipboard = { secureCopy, clearClipboard, looksLikeSecret };
})();

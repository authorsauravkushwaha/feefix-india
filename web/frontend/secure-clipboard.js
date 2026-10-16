/* =========================================================================
   FeeFix clipboard helper — NOT a security control.

   The only behaviour here that changes an outcome is refusal: credential-shaped
   values (the session token, a 6-digit OTP, anything equal to feefix.token)
   are never written to the clipboard by this page.

   Everything else people attach to "clipboard protection" is theatre:

     • A timer that clears the clipboard ~20s later does not stop malware.
       Malware, a rogue extension or a keylogger reads the value the instant
       it is written, long before any timer fires.
     • Clearing on visibilitychange is worse: it wipes whatever the user
       copied, including text they meant to paste into another app, and it
       fails silently when the document is unfocused.
     • The async Clipboard API needs a secure context, a user gesture and
       (on some browsers) permission. Failures used to be swallowed, which
       made the control look like it had worked.

   This module therefore does not auto-clear, does not register a
   visibilitychange handler, and describe() reports securityControl: false
   and autoClears: false. clearClipboard() exists only for a caller that has
   already consumed a value inside this page (the OTP boxes) and wants to
   drop it as a courtesy. That call is best-effort and reports why it failed.
   It is not protection against malware, keyloggers or memory scraping.

   The real controls for the session token are server-side: opaque 256-bit
   tokens, only their SHA-256 hash stored, rotation that does not log every
   device out, revocation on logout, Cache-Control: no-store, and a CSP that
   forbids remote scripts. The token is never placed on the clipboard, never
   in a URL, and never logged.
   ========================================================================== */
(() => {
  "use strict";

  const TOKEN_HINT = /^[A-Za-z0-9_-]{32,}$/;
  const CODE_HINT = /^\d{6}$/;

  const LIMITATIONS = Object.freeze([
    "Cannot stop malware, extensions or keyloggers from reading the clipboard.",
    "Does not auto-clear. A timer cannot outrun a process that already read the value.",
    "Does not wipe the clipboard when the tab is hidden — that destroyed unrelated copies and still was not protection.",
    "Clearing, when a caller asks for it, may fail if the page is unfocused or permission is denied. The failure is reported, not hidden.",
    "Protects only this page's decision not to write a credential. It says nothing about other devices or data already sent.",
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
   * There is no TTL. Passing one is ignored — scheduling a clear was the
   * false control.
   * @returns {Promise<{ok: boolean, reason: string}>}
   */
  async function copyWithHygiene(text) {
    if (looksLikeSecret(text)) {
      return { ok: false, reason: "refused-credential-shaped-value" };
    }
    if (!clipboardAvailable()) return { ok: false, reason: "clipboard-unavailable" };
    try {
      await navigator.clipboard.writeText(String(text));
    } catch (_) {
      return { ok: false, reason: "denied-or-unfocused" };
    }
    return { ok: true, reason: "copied" };
  }

  /** Back-compat boolean wrapper (older call sites). */
  async function secureCopy(text) {
    const result = await copyWithHygiene(text);
    return result.ok;
  }

  window.FeeFixClipboard = {
    secureCopy,
    copyWithHygiene,
    clearClipboard,
    looksLikeSecret,
    limitations: LIMITATIONS,
    describe: () => ({
      available: clipboardAvailable(),
      securityControl: false,
      autoClears: false,
      clearsOnHide: false,
      limitations: LIMITATIONS.slice(),
    }),
  };
})();

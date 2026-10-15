/* ==========================================================================
   FeeFix client security layer — loaded first, used everywhere.

   The server is the authority on every decision that matters. This file exists
   for the three things only the browser can do:

     1. OUTPUT ENCODING. XSS is not prevented by "being careful"; it is
        prevented by making the dangerous operation impossible to express. The
        helpers here are the only supported way to put data into the DOM.

     2. INPUT HYGIENE. Length caps and invisible-character stripping applied
        *before* a request is sent, so a hostile paste or a stuck key cannot
        turn into a 400 KB payload or a bidi-smuggled string.

     3. TRANSPORT PROOF. A fresh nonce + timestamp on every mutating request,
        which is what lets the server reject a replayed capture.

   Everything is dependency-free and CSP-compatible: this file is same-origin
   static JS, so `script-src 'self'` serves it without an inline-script or
   eval exception.
   ========================================================================== */

(() => {
  "use strict";

  /* Mirrors backend/services/security.py LIMITS. The server re-checks all of
     these; the client copy exists so an honest user gets an immediate, local
     explanation instead of a 422 round trip. */
  const LIMITS = Object.freeze({
    email: 254,
    password: 128,
    passwordMin: 8,
    name: 80,
    chatMessage: 2000,
    question: 1000,
    search: 200,
    phone: 32,
    otp: 6,
    sessionId: 64,
  });

  /* ---------------------------------------------------------------- output --
   * HTML-escape for text context. Note what this does NOT do: it cannot make a
   * `javascript:` URL safe, because such a URL contains none of these five
   * characters. That is why safeUrl() exists and why href sinks must use it.
   */
  const ESCAPES = {
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;",
    "'": "&#39;", "`": "&#96;",
  };
  const esc = (v) =>
    String(v ?? "").replace(/[&<>"'`]/g, (c) => ESCAPES[c]);

  /* Characters that are invisible but change meaning. U+202A..U+202E and
     U+2066..U+2069 are bidi overrides: they make a string *display* as
     something other than what it is. Pasted from a hostile webpage or document,
     they can make "₹5,000 fee" render while the underlying bytes say something
     else — and they survive into our logs and into other users' screens. */
  const INVISIBLE_RE =
    /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u00AD]/g;
  const CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;

  const stripInvisible = (v) =>
    String(v ?? "").replace(INVISIBLE_RE, "").replace(CONTROL_RE, "");

  /* ------------------------------------------------------------- safe URLs --
   * The one sink that escaping cannot protect. `esc()` on
   * `javascript:alert(document.cookie)` returns it unchanged — no `<`, no `"`,
   * no `&`. Scheme allow-listing is the only real defence.
   *
   * FeeFix's scheme URLs come from a curated dataset that accepts community
   * contributions (see .github/ISSUE_TEMPLATE/scheme-data.yml), which makes
   * this a *stored* XSS path, not a theoretical one: one malicious data pull
   * request would execute in every visitor's session.
   */
  const SAFE_SCHEME_RE = /^https?:\/\//i;
  const RELATIVE_RE = /^(?:\/(?!\/)|#|\.{1,2}\/)/;

  function safeUrl(value, { allowRelative = true, fallback = "#" } = {}) {
    const raw = stripInvisible(String(value ?? "")).trim();
    if (!raw) return fallback;
    if (SAFE_SCHEME_RE.test(raw)) return raw;
    if (allowRelative && RELATIVE_RE.test(raw)) return raw;
    // mailto:/tel: are legitimate on a scholarship site but are not emitted by
    // the dataset today; refuse rather than guess.
    return fallback;
  }

  /* --------------------------------------------------------------- inputs -- */
  const clamp = (value, max) => {
    const s = stripInvisible(value);
    return s.length > max ? s.slice(0, max) : s;
  };

  const KIND_RULES = {
    otp:    { max: LIMITS.otp,      keep: /[^0-9]/g },
    digits: { max: LIMITS.phone,    keep: /[^0-9+]/g },
    email:  { max: LIMITS.email,    keep: /[\s<>"]/g },
    phone:  { max: LIMITS.phone,    keep: /[^0-9+\s\-()]/g },
    name:   { max: LIMITS.name,     keep: /[<>]/g },
    text:   { max: LIMITS.chatMessage, keep: /[<>]/g },
    search: { max: LIMITS.search,   keep: null },
    any:    { max: LIMITS.chatMessage, keep: null },
  };

  /* Sanitise one pasted/typed value for a field kind. Used for clipboard input
     and for the global input guard. */
  function sanitize(value, kind = "any") {
    const rule = KIND_RULES[kind] || KIND_RULES.any;
    let out = stripInvisible(String(value ?? ""));
    if (rule.keep) out = out.replace(rule.keep, "");
    return out.length > rule.max ? out.slice(0, rule.max) : out;
  }

  /* Attach a live guard to an input element: enforces the ceiling on every
     keystroke and paste, so the limit holds even in a browser that ignores
     `maxlength` for programmatic value assignment. */
  function guardInput(el, kind = "any") {
    if (!el || el.dataset.ffGuarded) return el;
    el.dataset.ffGuarded = kind;
    const rule = KIND_RULES[kind] || KIND_RULES.any;
    if (!el.getAttribute("maxlength")) el.setAttribute("maxlength", String(rule.max));

    el.addEventListener("input", () => {
      const cleaned = sanitize(el.value, kind);
      if (cleaned !== el.value) {
        const pos = el.selectionStart;
        el.value = cleaned;
        try { el.setSelectionRange(Math.min(pos, cleaned.length), Math.min(pos, cleaned.length)); }
        catch (_) { /* not a text input */ }
      }
    });

    el.addEventListener("paste", (e) => {
      const text = (e.clipboardData || window.clipboardData)?.getData("text");
      if (text == null) return;
      e.preventDefault();
      const cleaned = sanitize(text, kind);
      const start = el.selectionStart ?? el.value.length;
      const end = el.selectionEnd ?? el.value.length;
      el.value = (el.value.slice(0, start) + cleaned + el.value.slice(end)).slice(0, rule.max);
      const caret = Math.min(start + cleaned.length, rule.max);
      try { el.setSelectionRange(caret, caret); } catch (_) {}
      el.dispatchEvent(new Event("input", { bubbles: true }));
      if (text !== cleaned && cleaned.length < text.length) {
        notifyPasteTrimmed(text.length - cleaned.length);
      }
    });
    return el;
  }

  let _trimTimer = null;
  function notifyPasteTrimmed(n) {
    const el = document.getElementById("ffPasteNote");
    if (!el) return;
    el.textContent = `⚠ Removed ${n} character${n === 1 ? "" : "s"} that can't be used here `
                   + `(control/invisible characters or too long).`;
    el.hidden = false;
    clearTimeout(_trimTimer);
    _trimTimer = setTimeout(() => { el.hidden = true; }, 6000);
  }

  /* Guard every input in a subtree, inferring kind from type/id/name. */
  function installGuards(root = document) {
    root.querySelectorAll("input, textarea").forEach((el) => {
      if (el.dataset.ffGuarded) return;
      const id = `${el.id || ""} ${el.name || ""} ${el.className || ""}`.toLowerCase();
      let kind = "any";
      if (el.dataset.ffKind) kind = el.dataset.ffKind;
      else if (/otp|code|pin/.test(id) && el.maxLength === 1) kind = "otp";
      else if (el.type === "email" || /email/.test(id)) kind = "email";
      else if (el.type === "tel" || /phone|mobile/.test(id)) kind = "phone";
      else if (el.type === "password") kind = "text";
      else if (el.type === "search" || /search/.test(id)) kind = "search";
      else if (/name/.test(id)) kind = "name";
      if (el.type === "password") el.setAttribute("autocomplete", "current-password");
      guardInput(el, kind);
    });
  }

  /* ------------------------------------------------------------ clipboard --
   * THE CLIPBOARD IS A SHARED, UNAUTHENTICATED, PERSISTENT CHANNEL.
   *
   * Three distinct attacks live there, and FeeFix defends all three:
   *
   *  (a) SUBSTITUTION. Malware (or a malicious browser extension with the
   *      "clipboardWrite" permission) watches for a copy and replaces the
   *      content — the classic crypto-wallet address swap. On this site the
   *      equivalent is swapping a scheme's official application URL for a
   *      phishing one, which sends a student's Aadhaar and bank details to an
   *      attacker. Defence: after writing, read the clipboard *back* and
   *      compare. A mismatch means something else owns the clipboard, and the
   *      user is told rather than silently betrayed.
   *
   *  (b) EXFILTRATION / PERSISTENCE. Anything copied stays readable by every
   *      other application indefinitely — on Android, any app can read the
   *      clipboard without a permission prompt at all. Defence: never put a
   *      secret on the clipboard; when something sensitive must go there,
   *      clear it on a timer and on page hide/unload.
   *
   *  (c) INJECTION. Pasted text is attacker input. It can carry bidi overrides
   *      (which make a field display something other than its bytes), control
   *      characters, or a 400 KB blob. Defence: sanitizePaste() on every paste.
   */
  const clipboard = {
    _pendingClear: null,

    async copy(text, { sensitive = false, ttlMs = 30000 } = {}) {
      const value = stripInvisible(String(text ?? ""));
      if (!value) return { ok: false, reason: "empty" };

      let written = false;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(value);
          written = true;
        }
      } catch (_) { written = false; }

      if (!written) written = this._legacyCopy(value);
      if (!written) return { ok: false, reason: "blocked" };

      /* (a) Verify the write survived. Reading requires the clipboard-read
         permission and is denied in some browsers; a denial is not a failure —
         it just means we could not check. */
      let tampered = null;
      try {
        if (navigator.clipboard?.readText && document.hasFocus()) {
          const readBack = await navigator.clipboard.readText();
          tampered = readBack !== value;
        }
      } catch (_) { tampered = null; }

      /* (b) Sensitive values get wiped, and the wipe also runs if the user
         switches away or closes the tab. */
      if (sensitive) this._scheduleClear(ttlMs);

      return { ok: true, tampered, sensitive };
    },

    _legacyCopy(value) {
      /* Fallback for non-secure contexts. The textarea is created off-screen,
         never inside the visible layout, and removed synchronously. */
      try {
        const ta = document.createElement("textarea");
        ta.value = value;
        ta.setAttribute("readonly", "");
        ta.style.cssText = "position:fixed;top:-1000px;left:-1000px;opacity:0";
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand("copy");
        document.body.removeChild(ta);
        return ok;
      } catch (_) {
        return false;
      }
    },

    _scheduleClear(ttlMs) {
      clearTimeout(this._pendingClear);
      this._pendingClear = setTimeout(() => this.clear(), ttlMs);
    },

    async clear() {
      clearTimeout(this._pendingClear);
      this._pendingClear = null;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText("");
          return true;
        }
      } catch (_) {}
      return this._legacyCopy("");
    },

    sanitizePaste(text, kind = "any") {
      return sanitize(text, kind);
    },
  };

  /* Wipe a sensitive clipboard when the page stops being visible. Covers the
     tab-switch, minimise and close cases that a timer alone would miss. */
  ["pagehide", "visibilitychange"].forEach((evt) =>
    window.addEventListener(evt, () => {
      if (evt === "visibilitychange" && document.visibilityState === "visible") return;
      if (clipboard._pendingClear) clipboard.clear();
    })
  );

  /* ------------------------------------------------------------ transport --
   * Anti-replay proof. The server rejects a mutating request whose timestamp
   * is outside its window or whose (IP, nonce) pair it has already seen, so a
   * captured request is worth exactly one use.
   *
   * crypto.getRandomValues is used rather than Math.random: a nonce an attacker
   * can predict is a nonce they can pre-register, which inverts the control.
   */
  const NONCE_HEADER = "X-FeeFix-Nonce";
  const TS_HEADER = "X-FeeFix-Ts";
  const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  function nonce() {
    const bytes = new Uint8Array(24);
    if (window.crypto?.getRandomValues) window.crypto.getRandomValues(bytes);
    else for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
    let out = "";
    for (let i = 0; i < bytes.length; i++) out += B64URL[bytes[i] & 63];
    return out;
  }

  function replayHeaders() {
    return { [NONCE_HEADER]: nonce(), [TS_HEADER]: String(Math.floor(Date.now() / 1000)) };
  }

  /* Build headers for a mutating request: content type, bearer token and a
     fresh replay proof. GET/HEAD are exempt (a replayed read gains nothing). */
  function headers(method = "GET", extra = {}) {
    const out = { ...extra };
    const token = tokenStore.get();
    if (token) out.Authorization = `Bearer ${token}`;
    const m = String(method).toUpperCase();
    if (m !== "GET" && m !== "HEAD" && m !== "OPTIONS") Object.assign(out, replayHeaders());
    return out;
  }

  /* --------------------------------------------------------------- tokens --
   * Session tokens live in localStorage so a returning student stays signed
   * in. That is a deliberate trade: localStorage is readable by any script on
   * this origin, so it is only acceptable because (1) CSP is `script-src 'self'`
   * with no inline and no eval, (2) every value rendered into the DOM goes
   * through esc()/safeUrl(), and (3) the server binds each token to the client
   * that created it and caps its absolute lifetime — so a token that does leak
   * is revoked the moment it is replayed from anywhere else.
   *
   * Nothing else secret is ever stored here. In particular an OTP code is never
   * persisted: it is read out of the DOM, sent, and the boxes are cleared.
   */
  const KEYS = Object.freeze({
    token: "feefix.token", user: "feefix.user", sid: "feefix.sid",
    lang: "feefix.lang", chat: "feefix.chat",
  });

  const TOKEN_RE = /^[A-Za-z0-9_-]{32,128}$/;

  const tokenStore = {
    get() {
      try {
        const raw = localStorage.getItem(KEYS.token);
        /* Validate on read. A token mutated by another script on this origin,
           or a stale value from an older schema, must not be sent — and must
           not be sent unbounded, since it becomes an Authorization header. */
        return raw && TOKEN_RE.test(raw) ? raw : null;
      } catch (_) { return null; }
    },
    set(value) {
      if (!value || !TOKEN_RE.test(String(value))) return false;
      try { localStorage.setItem(KEYS.token, String(value)); return true; }
      catch (_) { return false; }
    },
    clear() {
      try {
        localStorage.removeItem(KEYS.token);
        localStorage.removeItem(KEYS.user);
      } catch (_) {}
    },
    user() {
      try {
        const raw = localStorage.getItem(KEYS.user);
        if (!raw) return null;
        const parsed = JSON.parse(raw);
        /* The stored user object is rendered into the nav. Re-validate its
           shape so a tampered value cannot carry markup into the DOM. */
        if (!parsed || typeof parsed !== "object") return null;
        return {
          id: typeof parsed.id === "string" ? parsed.id.slice(0, 64) : "",
          email: sanitize(parsed.email, "email"),
          name: sanitize(parsed.name, "name"),
        };
      } catch (_) { return null; }
    },
    setUser(user) {
      try {
        localStorage.setItem(KEYS.user, JSON.stringify({
          id: String(user?.id ?? "").slice(0, 64),
          email: sanitize(user?.email, "email"),
          name: sanitize(user?.name, "name"),
        }));
      } catch (_) {}
    },
  };

  /* --------------------------------------------------------------- DOM ----- */
  /* Setting text through the DOM API rather than innerHTML is the only way to
     be certain no parser is involved. Prefer these over template strings for
     anything that is not a compile-time constant. */
  const setText = (el, value) => { if (el) el.textContent = String(value ?? ""); return el; };

  function clearSensitiveInputs(root = document) {
    /* OTP boxes and password fields are wiped after use so a shared or stolen
       device does not retain them in the DOM, in autofill, or in a screenshot
       taken by a backgrounded tab. */
    root.querySelectorAll('input[type="password"], [data-ff-sensitive]').forEach((el) => {
      el.value = "";
    });
    root.querySelectorAll("[data-boxes] input").forEach((el) => { el.value = ""; });
  }

  /* ------------------------------------------------------------- exports -- */
  const FFSec = Object.freeze({
    LIMITS,
    KEYS,
    NONCE_HEADER,
    TS_HEADER,
    esc,
    safeUrl,
    sanitize,
    stripInvisible,
    clamp,
    guardInput,
    installGuards,
    notifyPasteTrimmed,
    clipboard,
    nonce,
    replayHeaders,
    headers,
    token: tokenStore,
    setText,
    clearSensitiveInputs,
    isSafeUrl: (v) => safeUrl(v, { fallback: "" }) !== "",
  });

  window.FFSec = FFSec;

  /* Guard the inputs already in index.html, and any injected later. A
     MutationObserver means the auth gate (which builds its own DOM) and every
     dynamically rendered view are covered without each call site remembering. */
  const boot = () => {
    installGuards(document);
    try {
      new MutationObserver((records) => {
        for (const r of records) for (const node of r.addedNodes) {
          if (node.nodeType === 1) installGuards(node);
        }
      }).observe(document.body, { childList: true, subtree: true });
    } catch (_) { /* observer unavailable — static guards still apply */ }
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();

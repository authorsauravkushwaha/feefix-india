/* GitHub OAuth handoff — reads the sealed JSON data block and stores the session.
 *
 * CSP is `script-src 'self'`, so inline script is blocked and this same-origin
 * file does the move. The token arrives in a non-executable
 * `<script type="application/json">` block rather than in the URL: a token in a
 * fragment would land in the Referer header, in proxy logs and in browser
 * history, and would be readable by any script on the destination page.
 *
 * Everything read out of the block is treated as untrusted and shape-checked
 * before it is stored. The block is written by our own server, but the values
 * inside it originate from a third-party profile (GitHub display name), so
 * "we generated this HTML" is not the same claim as "this data is safe".
 */
(() => {
  "use strict";

  const SEC = window.FFSec;
  const TOKEN_RE = /^[A-Za-z0-9_-]{32,128}$/;

  const clamp = (v, max) =>
    String(v ?? "").replace(/[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\uFEFF]/g, "")
                   .slice(0, max);

  const store = (key, value) => {
    try { localStorage.setItem(key, value); } catch (_) { /* private mode */ }
  };

  try {
    const node = document.getElementById("p");
    if (!node) throw new Error("no payload");

    const data = JSON.parse(node.textContent || "{}");
    if (!data || typeof data !== "object") throw new Error("bad payload");

    /* The token is the only genuinely secret value here, so it gets the
       strictest check: exact shape, bounded length, and stored through the
       security layer when it is available. A value that fails is dropped rather
       than persisted — signing the user out is recoverable, storing an
       attacker-shaped token is not. */
    const token = typeof data.token === "string" ? data.token.trim() : "";
    if (!TOKEN_RE.test(token)) throw new Error("bad token");

    if (SEC) {
      if (!SEC.token.set(token)) throw new Error("token rejected by store");
      if (data.user && typeof data.user === "object") SEC.token.setUser(data.user);
    } else {
      store("feefix.token", token);
      store("feefix.user", JSON.stringify({
        id: clamp(data.user?.id, 64),
        email: clamp(data.user?.email, 254),
        name: clamp(data.user?.name, 80),
      }));
    }

    if (typeof data.session_id === "string" && /^[A-Za-z0-9_-]{4,64}$/.test(data.session_id)) {
      store("feefix.sid", data.session_id);
    }

    /* Wipe the block so the token is not sitting in the DOM (readable by an
       extension with content-script access, or captured by a screenshot) for
       the moment before navigation completes. */
    node.textContent = "";
  } catch (_) {
    /* Fall through — the home reload shows the sign-in gate. Deliberately
       silent: this page must not become an oracle for what went wrong. */
  }

  /* replace, not assign: the callback URL (which carried ?code= and ?state=)
     must not remain in the session history, or Back would re-issue it. */
  location.replace("/");
})();

/* GitHub OAuth handoff — reads the sealed JSON data block (CSP-safe; inline
   JS is blocked by script-src 'self', so this same-origin file does the move). */
(() => {
  "use strict";
  try {
    const data = JSON.parse(document.getElementById("p").textContent);
    if (data.token) localStorage.setItem("feefix.token", data.token);
    if (data.user) localStorage.setItem("feefix.user", JSON.stringify(data.user));
    if (data.session_id) localStorage.setItem("feefix.sid", data.session_id);
  } catch (_) { /* fall through — home reload shows the gate */ }
  location.replace("/");
})();

/* ==========================================================================
   FeeFix Auth Gate — blocks the app until sign-in (password · email OTP ·
   phone OTP · GitHub). Fully self-contained: injects its own DOM & CSS so
   no other source file needs to change. Loaded after app.js.
   ========================================================================== */

(() => {
  "use strict";

  const LS_TOKEN = "feefix.token";
  const LS_USER = "feefix.user";

  if (localStorage.getItem(LS_TOKEN)) return;      // already signed in → no gate

  /* ------------------------------------------------------------ markup -- */
  const css = `
  #ffGate{position:fixed;inset:0;z-index:9999;display:flex;align-items:center;
    justify-content:center;background:rgba(6,9,18,.86);backdrop-filter:blur(14px);
    font-family:Inter,system-ui,sans-serif;padding:16px}
  #ffGate *{box-sizing:border-box}
  .ff-card{width:100%;max-width:400px;background:#0d1322;border:1px solid #1e2a45;
    border-radius:22px;padding:30px 26px 24px;box-shadow:0 30px 80px rgba(0,0,0,.55);
    color:#e7edfb;animation:ffIn .35s cubic-bezier(.2,.9,.3,1.2)}
  @keyframes ffIn{from{transform:translateY(18px) scale(.96);opacity:0}}
  .ff-logo{display:flex;align-items:center;gap:10px;justify-content:center;margin-bottom:6px}
  .ff-logo img{width:30px;height:30px}
  .ff-logo b{font-family:Sora,Inter,sans-serif;font-size:1.3rem;letter-spacing:.2px}
  .ff-logo b em{font-style:normal;color:#6ea8ff}
  .ff-sub{text-align:center;color:#93a3c8;font-size:.82rem;margin:0 0 18px}
  .ff-tabs{display:flex;gap:6px;margin-bottom:18px;background:#0a0f1c;
    border:1px solid #1a2440;border-radius:12px;padding:4px}
  .ff-tab{flex:1;text-align:center;font-size:.76rem;font-weight:600;color:#8fa0c7;
    padding:8px 4px;border-radius:9px;cursor:pointer;user-select:none;transition:.15s}
  .ff-tab.on{background:#1b2a4d;color:#fff}
  .ff-field{margin-bottom:12px}
  .ff-field label{display:block;font-size:.72rem;font-weight:600;color:#7f92bb;margin-bottom:5px}
  .ff-input{width:100%;background:#0a0f1c;border:1px solid #22314f;border-radius:11px;
    color:#e7edfb;padding:11px 13px;font-size:.92rem;outline:none;transition:border .15s}
  .ff-input:focus{border-color:#4d7fff}
  .ff-row{display:flex;gap:10px}
  .ff-row .ff-field{flex:1}
  .ff-btn{width:100%;margin-top:6px;background:linear-gradient(135deg,#3b6cff,#7c5cff);
    border:0;border-radius:12px;color:#fff;font-weight:700;font-size:.92rem;
    padding:12px 14px;cursor:pointer;transition:filter .15s,transform .1s}
  .ff-btn:hover{filter:brightness(1.12)}
  .ff-btn:disabled{opacity:.55;cursor:default;filter:none}
  .ff-gh{display:flex;align-items:center;justify-content:center;gap:9px;
    background:#161d2f;border:1px solid #2b3a5f;margin-top:10px}
  .ff-gh svg{flex:none}
  .ff-or{display:flex;align-items:center;gap:10px;color:#64779f;font-size:.72rem;margin:14px 0}
  .ff-or::before,.ff-or::after{content:"";flex:1;height:1px;background:#1e2a45}
  .ff-err{color:#ff9c9c;font-size:.78rem;min-height:16px;margin:8px 0 0;text-align:center}
  .ff-otp-row{display:flex;gap:8px;justify-content:center;margin:14px 0 4px}
  .ff-otp-row input{width:44px;height:52px;text-align:center;font-size:1.4rem;font-weight:700;
    background:#0a0f1c;border:1px solid #22314f;border-radius:12px;color:#fff;outline:none}
  .ff-otp-row input:focus{border-color:#4d7fff}
  .ff-hint{text-align:center;color:#7f92bb;font-size:.76rem;margin-top:10px}
  .ff-hint b{color:#a9bcff}
  .ff-resend{background:none;border:0;color:#6ea8ff;font-size:.78rem;cursor:pointer;
    text-decoration:underline;padding:0}
  .ff-resend:disabled{color:#55648c;cursor:default;text-decoration:none}
  .ff-phone-pre{display:flex;gap:8px}
  .ff-phone-pre select{background:#0a0f1c;border:1px solid #22314f;border-radius:11px;
    color:#e7edfb;padding:11px 8px;font-size:.85rem;max-width:110px}
  body.ff-locked{overflow:hidden}
  .ff-spin{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,.35);
    border-top-color:#fff;border-radius:50%;animation:ffSpin .7s linear infinite;vertical-align:-3px;margin-right:6px}
  @keyframes ffSpin{to{transform:rotate(360deg)}}
  `;

  const html = `
  <div id="ffGate">
    <div class="ff-card" role="dialog" aria-modal="true" aria-label="Sign in to FeeFix">
      <div class="ff-logo">
        <img src="/assets/logo.svg" alt="" />
        <b>Fee<em>Fix</em></b>
      </div>
      <p class="ff-sub">Sign in to discover scholarships made for <b>you</b>🎓</p>

      <div class="ff-tabs">
        <div class="ff-tab on" data-tab="otp">OTP Login</div>
        <div class="ff-tab" data-tab="phone">Phone OTP</div>
        <div class="ff-tab" data-tab="password">Password</div>
      </div>

      <!-- EMAIL OTP -->
      <form class="ff-pane" data-pane="otp" autocomplete="on">
        <div class="ff-field" data-step="to">
          <label for="ffEmail">Email — any provider (Gmail, Yahoo, Outlook…)</label>
          <input class="ff-input" id="ffEmail" type="email" placeholder="you@example.com" required />
          <div class="ff-field" style="margin:10px 0 0">
            <label for="ffNameE">Name <span style="color:#5b6b93">(first time? we'll create your account)</span></label>
            <input class="ff-input" id="ffNameE" type="text" placeholder="Your name (optional)" />
          </div>
          <button class="ff-btn" type="submit" data-act="send">Send my code →</button>
        </div>
        <div class="ff-field" data-step="code" hidden>
          <label>Enter the 6-digit code sent to <b data-addr></b></label>
          <div class="ff-otp-row" data-boxes>
            <input maxlength="1" inputmode="numeric" /><input maxlength="1" inputmode="numeric" />
            <input maxlength="1" inputmode="numeric" /><input maxlength="1" inputmode="numeric" />
            <input maxlength="1" inputmode="numeric" /><input maxlength="1" inputmode="numeric" />
          </div>
          <p class="ff-hint" data-msg></p>
          <button class="ff-btn" type="submit" data-act="verify">Verify & enter →</button>
          <p class="ff-hint">Didn't get it?
            <button type="button" class="ff-resend" data-act="resend" disabled>Resend (<span data-cd>40</span>s)</button>
          </p>
        </div>
      </form>

      <!-- PHONE OTP -->
      <form class="ff-pane" data-pane="phone" hidden>
        <div class="ff-field" data-step="to">
          <label for="ffPhone">Mobile number (works for every country)</label>
          <div class="ff-phone-pre">
            <select id="ffCountry">
              <option value="+91">🇮🇳 +91</option><option value="+1">🇺🇸🇨🇦 +1</option>
              <option value="+44">🇬🇧 +44</option><option value="+971">🇦🇪 +971</option>
              <option value="+966">🇸🇦 +966</option><option value="+61">🇦🇺 +61</option>
              <option value="+49">🇩🇪 +49</option><option value="+65">🇸🇬 +65</option>
              <option value="+880">🇧🇩 +880</option><option value="+94">🇱🇰 +94</option>
              <option value="+977">🇳🇵 +977</option><option value="">Other…</option>
            </select>
            <input class="ff-input" id="ffPhone" type="tel" placeholder="98765 43210" style="flex:1" required />
          </div>
          <button class="ff-btn" type="submit" data-act="send">Text me a code →</button>
        </div>
        <div class="ff-field" data-step="code" hidden>
          <label>Enter the 6-digit SMS code sent to <b data-addr></b></label>
          <div class="ff-otp-row" data-boxes>
            <input maxlength="1" inputmode="numeric" /><input maxlength="1" inputmode="numeric" />
            <input maxlength="1" inputmode="numeric" /><input maxlength="1" inputmode="numeric" />
            <input maxlength="1" inputmode="numeric" /><input maxlength="1" inputmode="numeric" />
          </div>
          <p class="ff-hint" data-msg></p>
          <button class="ff-btn" type="submit" data-act="verify">Verify & enter →</button>
          <p class="ff-hint">Didn't get it?
            <button type="button" class="ff-resend" data-act="resend" disabled>Resend (<span data-cd>40</span>s)</button>
          </p>
        </div>
      </form>

      <!-- PASSWORD -->
      <form class="ff-pane" data-pane="password" hidden>
        <div class="ff-field">
          <label for="ffPwEmail">Email</label>
          <input class="ff-input" id="ffPwEmail" type="email" autocomplete="email" placeholder="you@example.com" required />
        </div>
        <div class="ff-field">
          <label for="ffPw">Password</label>
          <input class="ff-input" id="ffPw" type="password" autocomplete="current-password" placeholder="Min 8 characters" required />
        </div>
        <div class="ff-row">
          <div class="ff-field" style="margin:0"><button class="ff-btn" type="submit" data-act="login">Sign in →</button></div>
          <div class="ff-field" style="margin:0"><button class="ff-btn ff-ghost-btn" style="background:#161d2f" type="submit" data-act="register">Sign up</button></div>
        </div>
        <p class="ff-hint">🔒 PBKDF2-hashed, never stored in plain text.</p>
      </form>

      <div class="ff-or">or continue with</div>
      <button class="ff-btn ff-gh" data-act="github">
        <svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
        GitHub
      </button>

      <p class="ff-err" data-err></p>
    </div>
  </div>`;

  /* ------------------------------------------------------------- logic --- */
  const style = document.createElement("style");
  style.textContent = css;
  document.head.appendChild(style);

  const mount = () => {
    const wrap = document.createElement("div");
    wrap.innerHTML = html;
    const gate = wrap.firstElementChild;
    document.body.appendChild(gate);
    document.body.classList.add("ff-locked");

    if (location.hash === "#auth=failed") {
      gate.querySelector("[data-err]").textContent =
        "GitHub sign-in didn't complete — try again or use a code instead.";
      history.replaceState(null, "", "/");
    }

    const q = (sel) => gate.querySelector(sel);
    const errBox = q("[data-err]");
    const fail = (m) => { errBox.textContent = m; };
    const busy = (btn, on, label) => {
      btn.disabled = on;
      btn.innerHTML = on ? `<span class="ff-spin"></span>Wait…` : label;
    };

    // tabs
    gate.querySelectorAll(".ff-tab").forEach((t) =>
      t.addEventListener("click", () => {
        gate.querySelectorAll(".ff-tab").forEach((x) => x.classList.toggle("on", x === t));
        gate.querySelectorAll(".ff-pane").forEach((p) => (p.hidden = p.dataset.pane !== t.dataset.tab));
      })
    );

    // OTP boxes UX: auto-advance + paste-to-fill
    q("[data-boxes]") && gate.querySelectorAll("[data-boxes]").forEach((row) => {
      const boxes = [...row.querySelectorAll("input")];
      boxes.forEach((b, i) => {
        b.addEventListener("input", () => {
          b.value = b.value.replace(/\D/g, "").slice(-1);
          if (b.value && i < boxes.length - 1) boxes[i + 1].focus();
        });
        b.addEventListener("keydown", (e) => {
          if (e.key === "Backspace" && !b.value && i > 0) boxes[i - 1].focus();
        });
        b.addEventListener("paste", (e) => {
          e.preventDefault();
          const digits = (e.clipboardData.getData("text") || "").replace(/\D/g, "").slice(0, 6);
          digits.split("").forEach((d, j) => { if (boxes[j]) boxes[j].value = d; });
          boxes[Math.min(digits.length, 5)].focus();
        });
      });
    });
    const readCode = (pane) =>
      [...pane.querySelectorAll("[data-boxes] input")].map((b) => b.value).join("");

    // countdown helper
    const countdown = (btn, span, seconds = 40) => {
      btn.disabled = true;
      let left = seconds;
      span.textContent = left;
      const tick = setInterval(() => {
        left -= 1;
        span.textContent = left;
        if (left <= 0) { clearInterval(tick); btn.disabled = false; btn.textContent = "Resend"; }
      }, 1000);
    };

    const finish = (data) => {
      localStorage.setItem(LS_TOKEN, data.token);
      localStorage.setItem(LS_USER, JSON.stringify(data.user));
      if (data.session_id) localStorage.setItem("feefix.sid", data.session_id);
      location.reload();
    };

    const api = async (path, body) => {
      const r = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {}),
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.detail || `Error ${r.status}`);
      return d;
    };

    // ---------- OTP flows (email + phone, identical engine) ----------
    gate.querySelectorAll('form[data-pane="otp"], form[data-pane="phone"]').forEach((form) => {
      const channel = form.dataset.pane === "phone" ? "phone" : "email";
      const stepTo = form.querySelector('[data-step="to"]');
      const stepCode = form.querySelector('[data-step="code"]');

      const address = () => {
        if (channel === "email") return stepTo.querySelector("#ffEmail").value.trim().toLowerCase();
        const country = stepTo.querySelector("#ffCountry").value;
        const raw = stepTo.querySelector("#ffPhone").value.replace(/\D/g, "");
        return country ? country + raw.replace(/^0+/, "") : "+" + raw;
      };

      const send = async (btn) => {
        busy(btn, true, "Send my code →");
        fail("");
        try {
          const r = await api("/api/auth/otp/request", { channel, address: address() });
          stepTo.hidden = true;
          stepCode.hidden = false;
          stepCode.querySelector("[data-addr]").textContent = r.address;
          const msg = stepCode.querySelector("[data-msg]");
          if (r.dev_code) {
            msg.innerHTML = `⚙️ <b>Demo mode</b> — real delivery isn't configured, so your code is: <b style="font-size:1.1rem">${r.dev_code}</b>`;
          } else {
            msg.textContent = r.channel === "email" ? "📬 Check your inbox (and spam)." : "📲 Check your SMS.";
          }
          const rb = stepCode.querySelector('[data-act="resend"]');
          countdown(rb, stepCode.querySelector("[data-cd]"), r.resend_in);
          const name = channel === "email" ? stepTo.querySelector("#ffNameE").value.trim() : "";
          form._ctx = { address: r.dev_code ? address() : address(), name };
          stepCode.querySelector("[data-boxes] input").focus();
        } catch (e) { fail(e.message); }
        busy(btn, false, channel === "phone" ? "Text me a code →" : "Send my code →");
      };

      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        fail("");
        const act = e.submitter?.dataset.act;
        if (act === "send") { await send(e.submitter); return; }
        if (act === "verify") {
          const btn = e.submitter;
          busy(btn, true, "Verify & enter →");
          const nameEl = stepTo.querySelector("#ffNameE");
          try {
            const d = await api("/api/auth/otp/verify", {
              channel,
              address: address(),
              code: readCode(stepCode),
              name: channel === "email" && !form._done ? (nameEl?.value.trim() || undefined) : (nameEl?.value.trim() || undefined),
            });
            form._done = true;
            finish(d);
          } catch (err) { fail(err.message); busy(btn, false, "Verify & enter →"); }
        }
      });

      stepCode.querySelector('[data-act="resend"]').addEventListener("click", async (ev) => {
        const btn = ev.target;
        fail("");
        try {
          const r = await api("/api/auth/otp/request", { channel, address: address() });
          const msg = stepCode.querySelector("[data-msg]");
          if (r.dev_code) msg.innerHTML = `⚙️ <b>Demo mode</b> — new code: <b style="font-size:1.1rem">${r.dev_code}</b>`;
          countdown(btn, stepCode.querySelector("[data-cd]"), r.resend_in);
        } catch (e2) { fail(e2.message); }
      });
    });

    // ---------- password flow ----------
    const pwForm = gate.querySelector('form[data-pane="password"]');
    pwForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      fail("");
      const act = e.submitter?.dataset.act || "login";
      const btn = e.submitter;
      busy(btn, true, act === "register" ? "Sign up" : "Sign in →");
      try {
        const d = await api(`/api/auth/${act}`, {
          email: pwForm.querySelector("#ffPwEmail").value.trim(),
          password: pwForm.querySelector("#ffPw").value,
        });
        finish(d);
      } catch (err) { fail(err.message); busy(btn, false, act === "register" ? "Sign up" : "Sign in →"); }
    });

    // ---------- GitHub ----------
    q('[data-act="github"]').addEventListener("click", async (e) => {
      e.preventDefault();
      fail("");
      try {
        const m = await (await fetch("/api/auth/methods")).json();
        if (!m.github) { fail("GitHub sign-in isn't enabled on this deployment yet — use a code."); return; }
        location.href = "/api/auth/github";
      } catch (_) { location.href = "/api/auth/github"; }
    });

    // focus first input when shown
    setTimeout(() => q("#ffEmail")?.focus(), 150);
  };

  if (document.body) mount();
  else document.addEventListener("DOMContentLoaded", mount);
})();

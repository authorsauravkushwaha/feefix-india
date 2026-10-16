/* ==========================================================================
   FeeFix Auth Gate — blocks the app until sign-in (password · email OTP ·
   phone OTP · GitHub). Fully self-contained: injects its own DOM & CSS so
   no other source file needs to change. Loaded after app.js.

   Code sign-in is honest about delivery: the gate asks
   `GET /api/auth/methods` which gateways this deployment has, and then
     * a configured gateway → "we sent it to <masked address>, check your
       inbox / SMS",
     * the development console fallback → a loud DEMO banner and the code shown
       on screen, because nothing was actually sent,
     * no gateway and no demo (any production deploy) → the door is closed with
       an explanation instead of pretending to send a code that can never arrive.
   ========================================================================== */

(() => {
  "use strict";

  const LS_TOKEN = "feefix.token";
  const LS_USER = "feefix.user";
  const LS_SID = "feefix.sid";

  if (localStorage.getItem(LS_TOKEN)) return;      // already signed in → no gate

  /* ------------------------------------------------------------ markup -- */
  const css = `
  #ffGate{position:fixed;inset:0;z-index:9999;display:flex;align-items:center;
    justify-content:center;background:rgba(6,9,18,.86);backdrop-filter:blur(14px);
    font-family:Inter,system-ui,sans-serif;padding:16px;overflow:auto}
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
  .ff-tab.off{opacity:.4;cursor:not-allowed}
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
  .ff-banner{display:flex;gap:8px;align-items:flex-start;font-size:.74rem;line-height:1.45;
    border-radius:11px;padding:9px 11px;margin-bottom:14px;text-align:left}
  .ff-banner.demo{background:rgba(255,176,32,.12);border:1px solid rgba(255,176,32,.45);
    color:#ffd79a}
  .ff-banner.info{background:rgba(110,168,255,.1);border:1px solid rgba(110,168,255,.35);
    color:#bcd4ff}
  .ff-banner.warn{background:rgba(255,124,124,.1);border:1px solid rgba(255,124,124,.4);
    color:#ffbdbd}
  .ff-banner a{color:inherit}
  .ff-chip{display:inline-block;background:rgba(255,176,32,.18);border:1px solid rgba(255,176,32,.5);
    color:#ffd79a;font-size:.62rem;font-weight:700;letter-spacing:.8px;border-radius:6px;
    padding:1px 6px;margin-left:6px;vertical-align:middle}
  .ff-code{display:block;font-size:1.45rem;font-weight:800;letter-spacing:5px;color:#ffd79a;
    margin:6px 0 2px}
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

      <div class="ff-banner demo" data-banner="demo" hidden></div>
      <div class="ff-banner warn" data-banner="notice" hidden></div>

      <div class="ff-tabs">
        <div class="ff-tab on" data-tab="otp">Email code</div>
        <div class="ff-tab" data-tab="phone">Phone code</div>
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
          <p class="ff-hint" data-delivery-note></p>
        </div>
        <div class="ff-field" data-step="code" hidden>
          <label>Enter the 6-digit code sent to <b data-addr></b></label>
          <div class="ff-otp-row" data-boxes>
            <input maxlength="1" inputmode="numeric" /><input maxlength="1" inputmode="numeric" />
            <input maxlength="1" inputmode="numeric" /><input maxlength="1" inputmode="numeric" />
            <input maxlength="1" inputmode="numeric" /><input maxlength="1" inputmode="numeric" />
          </div>
          <p class="ff-hint" data-msg></p>
          <p class="ff-hint" data-expiry></p>
          <p class="ff-hint" data-clip-note>FeeFix never copies your session token. Clearing a code after you paste it here is convenience, not protection against malware on this device.</p>
          <button class="ff-btn" type="submit" data-act="verify">Verify & enter →</button>
          <p class="ff-hint">Didn't get it?
            <button type="button" class="ff-resend" data-act="resend" disabled>Resend code</button>
            <button type="button" class="ff-resend" data-act="dev-inbox" hidden>dev inbox</button>
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
            <input class="ff-input" id="ffCountryOther" type="tel" placeholder="+254" maxlength="5" style="max-width:78px;display:none" aria-label="Country code" />
            <input class="ff-input" id="ffPhone" type="tel" placeholder="98765 43210" style="flex:1" required />
          </div>
          <button class="ff-btn" type="submit" data-act="send">Text me a code →</button>
          <p class="ff-hint" data-delivery-note></p>
        </div>
        <div class="ff-field" data-step="code" hidden>
          <label>Enter the 6-digit code sent to <b data-addr></b></label>
          <div class="ff-otp-row" data-boxes>
            <input maxlength="1" inputmode="numeric" /><input maxlength="1" inputmode="numeric" />
            <input maxlength="1" inputmode="numeric" /><input maxlength="1" inputmode="numeric" />
            <input maxlength="1" inputmode="numeric" /><input maxlength="1" inputmode="numeric" />
          </div>
          <p class="ff-hint" data-msg></p>
          <p class="ff-hint" data-expiry></p>
          <p class="ff-hint" data-clip-note>FeeFix never copies your session token. Clearing a code after you paste it here is convenience, not protection against malware on this device.</p>
          <button class="ff-btn" type="submit" data-act="verify">Verify & enter →</button>
          <p class="ff-hint">Didn't get it?
            <button type="button" class="ff-resend" data-act="resend" disabled>Resend code</button>
            <button type="button" class="ff-resend" data-act="dev-inbox" hidden>dev inbox</button>
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
        <p class="ff-hint">🔒 Argon2id-hashed, never stored in plain text.</p>
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

  const mount = async () => {
    const wrap = document.createElement("div");
    wrap.innerHTML = html;
    const gate = wrap.firstElementChild;
    document.body.appendChild(gate);
    document.body.classList.add("ff-locked");

    const q = (sel) => gate.querySelector(sel);
    const errBox = q("[data-err]");
    const fail = (m) => { errBox.textContent = m || ""; };
    const busy = (btn, on, label) => {
      if (!btn) return;
      btn.disabled = on;
      btn.innerHTML = on ? `<span class="ff-spin"></span>Wait…` : label;
    };
    const showBanner = (kind, node) => {
      const box = q(`[data-banner="${kind}"]`);
      box.hidden = false;
      box.replaceChildren(...(Array.isArray(node) ? node : [node]));
    };

    if (location.hash === "#auth=failed") {
      fail("GitHub sign-in didn't complete — try again or use a code instead.");
      history.replaceState(null, "", "/");
    }

    /* ------------------------------------------------------ transport -- */
    const api = async (path, body) => {
      const r = await fetch(path, {
        method: body === undefined ? "GET" : "POST",
        headers: body === undefined ? {} : { "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body || {}),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        const detail = typeof data.detail === "string" ? data.detail : "";
        const err = new Error(detail || `Sign-in failed (${r.status}). Please try again.`);
        err.status = r.status;
        // The server names the honest wait, so the UI counts down the same
        // number the backend enforces instead of guessing.
        err.retryAfter = Number(r.headers.get("Retry-After") || 0) || 0;
        throw err;
      }
      return data;
    };

    const finish = (data) => {
      localStorage.setItem(LS_TOKEN, data.token);
      localStorage.setItem(LS_USER, JSON.stringify(data.user));
      if (data.session_id) localStorage.setItem(LS_SID, data.session_id);
      location.reload();
    };

    /* ------------------------------------------- delivery capabilities -- */
    let methods = { otp_email: true, otp_phone: true, github: false, delivery: null };
    let methodsLoaded = false;
    try {
      methods = await api("/api/auth/methods");
      methodsLoaded = true;
    } catch (_) {
      // The gate must never be a dead end: if capabilities cannot be read,
      // behave as before and let the API answer each attempt.
    }
    const delivery = methods.delivery || {};
    const emailInfo = delivery.email || { provider: null, demo: false, usable: true };
    const phoneInfo = delivery.phone || { provider: null, demo: false, usable: true };
    const devInboxAvailable = Boolean(delivery.dev_inbox);

    if (delivery.demo_mode) {
      showBanner("demo", [
        document.createTextNode(
          "Demo mode: this server has no email/SMS gateway, so a code appears on " +
          "this screen instead of being sent. Configure OTP_SMTP_* (email) or a " +
          "phone gateway to deliver real codes — see docs/deploy/DEPLOYMENT.md."),
      ]);
    }

    /* --------------------------------------------------------- tabs ----- */
    const selectTab = (name) => {
      gate.querySelectorAll(".ff-tab").forEach((t) =>
        t.classList.toggle("on", t.dataset.tab === name));
      gate.querySelectorAll(".ff-pane").forEach((p) => (p.hidden = p.dataset.pane !== name));
      if (name === "otp") setTimeout(() => q("#ffEmail")?.focus(), 80);
      if (name === "phone") setTimeout(() => q("#ffPhone")?.focus(), 80);
      if (name === "password") setTimeout(() => q("#ffPwEmail")?.focus(), 80);
    };

    gate.querySelectorAll(".ff-tab").forEach((tab) =>
      tab.addEventListener("click", () => {
        if (tab.classList.contains("off")) {
          fail(tab.dataset.offReason || "That sign-in option isn't available here.");
          return;
        }
        fail("");
        selectTab(tab.dataset.tab);
      })
    );

    // One door closed and another open → open the one that works, and say why.
    const closeTab = (name, reason) => {
      const tab = gate.querySelector(`.ff-tab[data-tab="${name}"]`);
      tab.classList.add("off");
      tab.dataset.offReason = reason;
      tab.title = reason;
      const pane = gate.querySelector(`.ff-pane[data-pane="${name}"]`);
      const send = pane.querySelector('[data-act="send"]');
      if (send) { send.disabled = true; send.textContent = "Not available on this server"; }
      const note = pane.querySelector("[data-delivery-note]");
      if (note) note.textContent = reason;
    };

    if (!methods.otp_email) {
      closeTab("otp", "Email codes aren't configured on this deployment yet (the operator "
        + "needs to set OTP_SMTP_HOST/USER/PASS or an email API key). Use your password or GitHub.");
    }
    if (!methods.otp_phone) {
      closeTab("phone", "SMS codes aren't configured on this deployment yet (the operator "
        + "needs to set OTP_TWILIO_* / OTP_MSG91_* / OTP_FAST2SMS_KEY / OTP_VONAGE_*). "
        + "Use email, your password or GitHub.");
    }
    if (!methods.otp_email && !methods.otp_phone) {
      fail("Code sign-in isn't configured on this server — sign in with your password or GitHub.");
      if (methods.password || methods.github) selectTab("password");
    } else if (!methods.otp_email) {
      selectTab(methods.otp_phone ? "phone" : "password");
    }

    const describeDelivery = (channel) => {
      const info = channel === "email" ? emailInfo : phoneInfo;
      const what = channel === "email" ? "email" : "SMS";
      if (info.demo) {
        return `⚠️ Demo mode — no ${what} gateway configured, so the code will be shown here.`;
      }
      if (info.provider) {
        const label = { smtp: "your email relay", brevo: "Brevo", resend: "Resend",
                        webhook: "the email webhook", twilio: "Twilio", msg91: "MSG91",
                        fast2sms: "Fast2SMS", vonage: "Vonage" }[info.provider] || info.provider;
        return `Codes are sent for real via ${label}.`;
      }
      return "";
    };
    gate.querySelectorAll(".ff-pane").forEach((pane) => {
      if (pane.dataset.pane === "password") return;
      const channel = pane.dataset.pane === "phone" ? "phone" : "email";
      const note = pane.querySelector("[data-delivery-note]");
      if (note) note.textContent = describeDelivery(channel);
      const sendBtn = pane.querySelector('[data-act="send"]');
      const info = channel === "email" ? emailInfo : phoneInfo;
      // Say what the button will do. "Text me a code" next to a demo code is a
      // small lie the student notices only after waiting for an SMS.
      if (sendBtn && info.demo) {
        sendBtn.textContent = "Show a demo code →";
      }
    });

    /* ----------------------------------------------------- OTP boxes ---- */
    gate.querySelectorAll("[data-boxes]").forEach((row) => {
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
          // Clipboard hygiene: clear a pasted one-time code so it does not sit
          // in the clipboard for a later stray paste. This is a *usability*
          // measure — it cannot stop malware that already read the value, and
          // the footer note below says so to the user in plain words.
          if (window.FeeFixClipboard) {
            window.FeeFixClipboard.clearClipboard().then((result) => {
              if (!result.ok && result.reason === "denied-or-unfocused") {
                const note = row.parentElement.querySelector("[data-clip-note]");
                if (note) note.textContent = "Clipboard could not be cleared automatically.";
              }
            });
          }
        });
      });
    });
    const readCode = (pane) =>
      [...pane.querySelectorAll("[data-boxes] input")].map((b) => b.value).join("");
    const clearCode = (pane) =>
      pane.querySelectorAll("[data-boxes] input").forEach((b) => { b.value = ""; });

    /* ------------------------------------------------------ countdowns -- */
    const timers = new WeakMap();
    const stopTimers = (el) => {
      const set = timers.get(el);
      if (set) { set.forEach(clearInterval); timers.delete(el); }
    };
    const addTimer = (el, id) => {
      const set = timers.get(el) || new Set();
      set.add(id);
      timers.set(el, set);
    };

    const startResendCountdown = (pane, seconds) => {
      const btn = pane.querySelector('[data-act="resend"]');
      if (!btn) return;
      // The server owns the cooldown, so the button counts down *its* number:
      // a hard-coded 40 next to a server-side variable is how users end up
      // watching a button that refuses to do anything.
      let left = Math.max(0, Math.round(seconds || 0));
      const render = () => {
        btn.textContent = left > 0 ? `Resend in ${left}s` : "Resend code";
        btn.disabled = left > 0;
      };
      render();
      if (!left) return;
      const tick = setInterval(() => {
        left -= 1;
        render();
        if (left <= 0) clearInterval(tick);
      }, 1000);
      addTimer(pane, tick);
    };

    const startExpiryCountdown = (pane, seconds) => {
      const note = pane.querySelector("[data-expiry]");
      if (!note || !seconds) return;
      let left = Math.max(0, Math.round(seconds || 0));
      const render = () => {
        const m = Math.floor(left / 60), s = String(left % 60).padStart(2, "0");
        note.textContent = left > 0 ? `⏳ Code expires in ${m}:${s}` : "";
      };
      render();
      const tick = setInterval(() => {
        left -= 1;
        render();
        if (left <= 0) {
          clearInterval(tick);
          backToAddress(pane, "That code expired — send yourself a new one.");
        }
      }, 1000);
      addTimer(pane, tick);
    };

    const backToAddress = (pane, message) => {
      stopTimers(pane);
      clearCode(pane);
      pane.querySelector('[data-step="code"]').hidden = true;
      pane.querySelector('[data-step="to"]').hidden = false;
      const note = pane.querySelector('[data-msg]');
      if (note) note.textContent = "";
      const expiry = pane.querySelector("[data-expiry]");
      if (expiry) expiry.textContent = "";
      if (message) fail(message);
    };

    /* ------------------------------------------------------ OTP flows --- */
    gate.querySelectorAll('form[data-pane="otp"], form[data-pane="phone"]').forEach((form) => {
      const channel = form.dataset.pane === "phone" ? "phone" : "email";
      const stepTo = form.querySelector('[data-step="to"]');
      const stepCode = form.querySelector('[data-step="code"]');
      const info = channel === "email" ? emailInfo : phoneInfo;
      const sendLabel = info.demo
        ? "Show a demo code →"
        : (channel === "phone" ? "Text me a code →" : "Send my code →");
      let lastAddress = null;

      const address = () => {
        if (channel === "email") return stepTo.querySelector("#ffEmail").value.trim().toLowerCase();
        const country = stepTo.querySelector("#ffCountry").value
          || stepTo.querySelector("#ffCountryOther").value.trim();
        const raw = stepTo.querySelector("#ffPhone").value.trim();
        const digits = raw.replace(/\D/g, "");
        if (raw.startsWith("+")) return "+" + digits;          // user typed the whole thing
        const cc = (country || "").replace(/[^\d]/g, "");
        return cc ? "+" + cc + digits.replace(/^0+/, "") : "+" + digits;
      };

      stepTo.querySelector("#ffCountry")?.addEventListener("change", (e) => {
        const other = stepTo.querySelector("#ffCountryOther");
        other.style.display = e.target.value === "" ? "" : "none";
        if (e.target.value === "") other.focus();
      });

      const showDemoCode = (pane, code) => {
        const msg = pane.querySelector("[data-msg]");
        msg.replaceChildren();
        const chip = document.createElement("span");
        chip.className = "ff-chip";
        chip.textContent = "DEMO";
        const line1 = document.createElement("span");
        line1.append("No gateway is configured, so nothing was sent. Your demo code:",
                     chip);
        const line2 = document.createElement("b");
        line2.className = "ff-code";
        line2.textContent = code;
        msg.append(line1, line2);
      };

      const enterCodeStep = (pane, r) => {
        lastAddress = address();
        stopTimers(pane);              // a resend must not stack countdowns
        stepTo.hidden = true;
        stepCode.hidden = false;
        stepCode.querySelector("[data-addr]").textContent = r.address || lastAddress;
        const msg = stepCode.querySelector("[data-msg]");
        const inbox = stepCode.querySelector('[data-act="dev-inbox"]');
        if (r.demo && r.dev_code) {
          showDemoCode(stepCode, r.dev_code);
          if (inbox) inbox.hidden = !devInboxAvailable;
        } else {
          msg.textContent = channel === "email"
            ? `📬 Code sent to ${r.address || lastAddress} — check your inbox (and spam).`
            : `📲 Code sent by SMS to ${r.address || lastAddress}.`;
          if (inbox) inbox.hidden = true;
        }
        startResendCountdown(stepCode, r.resend_in);
        startExpiryCountdown(stepCode, r.ttl_s);
        stepCode.querySelector("[data-boxes] input").focus();
      };

      const send = async (btn) => {
        busy(btn, true, sendLabel);
        fail("");
        try {
          const r = await api("/api/auth/otp/request", { channel, address: address() });
          enterCodeStep(stepCode, r);
        } catch (e) {
          if (e.status === 429 && e.retryAfter && /already sent/i.test(e.message)) {
            // A cooldown is not a wall: the previous code is still valid, so
            // drop the student on the code screen with the countdown running.
            enterCodeStep(stepCode, { address: lastAddress || address(),
                                      resend_in: e.retryAfter, ttl_s: 0 });
            const msg = stepCode.querySelector("[data-msg]");
            msg.textContent = e.message;
          } else {
            fail(e.message);
          }
        }
        busy(btn, false, sendLabel);
      };

      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        fail("");
        const act = e.submitter?.dataset.act;
        if (act === "send") { await send(e.submitter); return; }
        if (act !== "verify") return;
        const btn = e.submitter;
        const code = readCode(stepCode);
        if (code.length !== 6) { fail("Enter all 6 digits."); return; }
        busy(btn, true, "Verify & enter →");
        try {
          const nameEl = stepTo.querySelector("#ffNameE");
          const d = await api("/api/auth/otp/verify", {
            channel,
            address: lastAddress || address(),
            code,
            name: (nameEl?.value.trim() || undefined),
          });
          finish(d);
        } catch (err) {
          fail(err.message);
          busy(btn, false, "Verify & enter →");
          clearCode(stepCode);
          stepCode.querySelector("[data-boxes] input").focus();
          if (err.status === 410 || err.status === 429) {
            // Expired, or the attempts/code are burned: the challenge is gone,
            // so put the student back where a fresh code can be requested.
            backToAddress(stepCode, err.message);
          }
        }
      });

      stepCode.querySelector('[data-act="resend"]').addEventListener("click", async (ev) => {
        const btn = ev.currentTarget;
        fail("");
        busy(btn, true, "");
        try {
          const r = await api("/api/auth/otp/request", { channel, address: lastAddress || address() });
          enterCodeStep(stepCode, r);
        } catch (e) {
          fail(e.message);
          if (e.status === 429 && e.retryAfter) startResendCountdown(stepCode, e.retryAfter);
          else { btn.disabled = false; btn.textContent = "Resend code"; }
        }
      });

      stepCode.querySelector('[data-act="dev-inbox"]')?.addEventListener("click", async (ev) => {
        ev.preventDefault();
        try {
          const r = await api(`/api/auth/otp/dev-inbox?address=${encodeURIComponent(lastAddress || "")}`);
          const entry = (r.entries || [])[0];
          if (entry) showDemoCode(stepCode, entry.code);
          else fail("Dev inbox is empty — request a code first.");
        } catch (e) {
          fail(e.message);
        }
      });
    });

    /* --------------------------------------------------- password flow -- */
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

    /* --------------------------------------------------------- GitHub --- */
    q('[data-act="github"]').addEventListener("click", async (e) => {
      e.preventDefault();
      fail("");
      if (methodsLoaded && !methods.github) {
        fail("GitHub sign-in isn't enabled on this deployment yet — use a code or your password.");
        return;
      }
      location.href = "/api/auth/github";
    });

    // focus first input when shown
    setTimeout(() => q("#ffGate .ff-pane:not([hidden]) input")?.focus(), 150);
  };

  if (document.body) mount();
  else document.addEventListener("DOMContentLoaded", mount);
})();

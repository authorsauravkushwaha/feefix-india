/* ==========================================================================
   FeeFix India — web experience (vanilla SPA, hash-routed, no build step)
   One origin: every API call is relative, so it works behind any proxy.
   ========================================================================== */

"use strict";

/* ---------------------------------------------------------------- state -- */
const State = {
  sid: localStorage.getItem("feefix.sid") || crypto.randomUUID(),
  lang: localStorage.getItem("feefix.lang") || "en",
  dict: {},
  meta: null,
  stats: null,
  lastResults: null,
  board: {},
  wizard: null,
};
localStorage.setItem("feefix.sid", State.sid);

/* ------------------------------------------------------------- helpers -- */
const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));

function t(key, vars = {}) {
  let s = State.dict[key] || State.fallback?.[key] || key;
  for (const [k, v] of Object.entries(vars)) s = s.replace(`{${k}}`, v);
  return s;
}

const fmtINR = (n) => "₹" + Number(n || 0).toLocaleString("en-IN");

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  return res.json();
}

/** Minimal safe markdown: **bold**, *bold*, _em_, line breaks. */
function mdLite(text) {
  return esc(text)
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<strong>$1</strong>")
    .replace(/_([^_]+)_/g, "<em>$1</em>")
    .replace(/\n/g, "<br>");
}

let toastTimer = null;
function toast(msg) {
  const el = $("#toast");
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 2600);
}

/* ---------------------------------------------------------------- i18n -- */
async function loadLang(lang) {
  try {
    const dict = await api(`/api/i18n/${lang}`);
    State.dict = dict;
    State.lang = lang;
    localStorage.setItem("feefix.lang", lang);
    document.documentElement.lang = lang === "bn" ? "bn" : lang === "hi" ? "hi" : "en";
  } catch (e) {
    State.dict = {};
  }
}

/* ----------------------------------------------------------------- nav -- */
function renderNav() {
  const route = currentRoute();
  const links = [
    ["#/home", t("nav.home")],
    ["#/matcher", t("nav.find")],
    ["#/explore", t("nav.explore")],
    ["#/dashboard", t("nav.dashboard")],
  ];
  $("#navLinks").innerHTML =
    links
      .map(([href, label]) => {
        const active = route === href.slice(1) ? "active" : "";
        return `<a href="${href}" class="${active}">${esc(label)}</a>`;
      })
      .join("") +
    `<select class="lang-pick" id="langPick">
       <option value="en" ${State.lang === "en" ? "selected" : ""}>English</option>
       <option value="bn" ${State.lang === "bn" ? "selected" : ""}>বাংলা</option>
       <option value="hi" ${State.lang === "hi" ? "selected" : ""}>हिन्दी</option>
     </select>`;
  $("#langPick").addEventListener("change", async (e) => {
    await loadLang(e.target.value);
    renderNav();
    renderFooter();
    route();
  });
  $("#footerTagline") && ($("#footerTagline").textContent = t("footer.tagline"));
}

function renderFooter() {
  $("#footerTagline").textContent = t("footer.tagline");
  $("#footerDisclaimer").textContent = t("footer.disclaimer");
  $("#footerMade").textContent = `🇮🇳 ${t("footer.made")}`;
}

/* -------------------------------------------------------------- router -- */
function currentRoute() {
  return (location.hash || "#/home").slice(1) || "/home";
}

async function route() {
  const r = currentRoute();
  const view = $("#view");
  window.scrollTo({ top: 0 });
  renderNav();
  if (r.startsWith("/scheme/")) {
    await openScheme(r.split("/")[2], true);
    return;
  }
  switch (r) {
    case "/matcher": return MatcherView(view);
    case "/results": return ResultsView(view);
    case "/explore": return ExploreView(view);
    case "/dashboard": return DashboardView(view);
    default: return HomeView(view);
  }
}

/* ------------------------------------------------------------------ SVG -- */
function ringSVG(score) {
  const pct = Math.max(2, Math.min(100, score));
  const R = 35, C = 2 * Math.PI * R;
  const color = score >= 80 ? "#f59e0b" : score >= 65 ? "#fbbf24" : "#10b981";
  return `
    <div class="score-ring">
      <svg width="84" height="84" viewBox="0 0 84 84">
        <circle cx="42" cy="42" r="${R}" fill="none" stroke="rgba(255,255,255,0.07)" stroke-width="7"/>
        <circle cx="42" cy="42" r="${R}" fill="none" stroke="${color}" stroke-width="7"
          stroke-linecap="round" stroke-dasharray="${C}" stroke-dashoffset="${C * (1 - pct / 100)}"/>
      </svg>
      <span class="val">${Math.round(score)}</span>
    </div>`;
}

/* ------------------------------------------------------------- deadline -- */
function deadlineChip(dl) {
  if (!dl) return "";
  if (dl.expired)
    return `<span class="deadline-chip grey">${esc(t("scheme.closed"))}</span>`;
  if (dl.rolling)
    return `<span class="deadline-chip green">${esc(t("scheme.rolling"))}</span>`;
  const d = dl.days_left;
  if (d == null) return "";
  const cls = d <= 14 ? "red" : d <= 30 ? "amber" : "green";
  return `<span class="deadline-chip ${cls}">${esc(t("scheme.days_left", { n: d }))}</span>`;
}

/* --------------------------------------------------------------- badges -- */
function badgeHTML(b) {
  return `<span class="badge ${esc(b)}">${esc(t(`badge.${b}`))}</span>`;
}

/* ============================================================== HOME VIEW */
function HomeView(el) {
  const s = State.stats || {};
  el.innerHTML = `
    <section class="hero">
      <div class="hero-eyebrow"><span class="dot"></span>${esc(t("home.eyebrow"))}</div>
      <h1><span class="grad">${esc(t("home.title"))}</span></h1>
      <p>${esc(t("home.subtitle"))}</p>
      <div class="hero-actions">
        <a class="btn btn-primary" href="#/matcher">✦&nbsp; ${esc(t("home.cta"))}</a>
        <a class="btn btn-ghost" href="#/explore">${esc(t("home.cta.secondary"))}</a>
      </div>
      <div class="stats" id="statStrip">
        ${stat(t("home.stats.schemes"), s.total_schemes)}
        ${stat(t("home.stats.benefit"), s.max_annual_benefit_inr, true)}
        ${stat(t("home.stats.fee_waivers"), s.fee_waivers + " + grants")}
        ${stat(t("home.stats.verified"), `${s.verified}/${s.total_schemes}`)}
      </div>
    </section>

    <section class="section">
      <div class="section-head"><h2>${esc(t("home.how.title"))}</h2></div>
      <div class="cards3">
        ${howCard("01", t("home.how.1.title"), t("home.how.1.body"))}
        ${howCard("02", t("home.how.2.title"), t("home.how.2.body"))}
        ${howCard("03", t("home.how.3.title"), t("home.how.3.body"))}
      </div>
    </section>

    <section class="reach">
      <div class="text">
        <h2>${esc(t("home.reach.title"))}</h2>
        <p>${esc(t("home.reach.subtitle"))}</p>
      </div>
      <div class="mock">
        <button class="btn btn-primary" id="openChat">💬&nbsp; ${esc(t("home.reach.cta"))}</button>
      </div>
    </section>`;

  function stat(lbl, val, money = false) {
    return `<div class="stat"><div class="num"></div><div class="lbl">${esc(lbl)}</div></div>`;
  }
  function howCard(no, title, body) {
    return `<div class="how-card"><div class="step-no">${no}</div><h3>${esc(title)}</h3><p>${esc(body)}</p></div>`;
  }

  // Animated stat count-up.
  const defs = [
    s.total_schemes ?? 0,
    s.max_annual_benefit_inr ?? 0,
    (s.fee_waivers ?? 0) > 1 ? `${s.fee_waivers}+` : "1+",
    s.total_schemes ? `${s.verified}/${s.total_schemes}` : "–",
  ];
  $$("#statStrip .num").forEach((el, i) => {
    if (i === 1) {
      animateCount(el, 0, defs[1], (v) => "₹" + Math.round(v / 1000) + "K");
    } else if (i === 0) animateCount(el, 0, defs[0], (v) => String(Math.round(v)));
    else el.textContent = defs[i];
  });
  $("#openChat").addEventListener("click", () => Chat.open());
}

function animateCount(el, from, to, fmt) {
  const t0 = performance.now();
  const dur = 1300;
  (function frame(ts) {
    const p = Math.min(1, (ts - t0) / dur);
    const eased = 1 - Math.pow(1 - p, 3);
    el.textContent = fmt(from + (to - from) * eased);
    if (p < 1) requestAnimationFrame(frame);
  })(t0);
}

/* =========================================================== MATCHER VIEW */
const DEFAULT_PROFILE = {
  domicile_state: "West Bengal",
  category: "general",
  annual_family_income: 200000,
  course_level: "ug",
  last_exam_percentage: null,
  gender: "prefer_not_to_say",
  is_minority: false,
  minority_community: null,
  has_disability: false,
  is_single_girl_child: false,
  name: null,
};

function MatcherView(el) {
  State.wizard = { step: 0, data: { ...DEFAULT_PROFILE } };
  renderWizard(el, 1);
}

const COURSE_ICONS = {
  school: "📚", higher_secondary: "🏫", iti: "🔧", diploma: "📐",
  ug: "🎓", pg: "📖", phd: "🔬",
};

function wizardSteps() {
  return [
    { id: "domicile_state", q: t("matcher.state.q"), help: t("matcher.state.help"), render: renderStateStep },
    { id: "category", q: t("matcher.category.q"), help: t("matcher.category.help"), render: renderCategoryStep },
    { id: "annual_family_income", q: t("matcher.income.q"), help: t("matcher.income.help"), render: renderIncomeStep },
    { id: "course_level", q: t("matcher.course.q"), help: "", render: renderCourseStep },
    { id: "last_exam_percentage", q: t("matcher.marks.q"), help: t("matcher.marks.help"), render: renderMarksStep, skippable: true },
    { id: "gender", q: t("matcher.gender.q"), help: t("matcher.gender.help"), render: renderGenderStep, skippable: true },
    { id: "details", q: t("matcher.details.q"), help: "", render: renderDetailsStep, skippable: true },
  ];
}

function renderWizard(el, dir = 1) {
  const wiz = State.wizard;
  const steps = wizardSteps();
  const step = steps[wiz.step];
  const total = steps.length;

  el.innerHTML = `
    <section class="section" style="padding-top:52px">
      <div class="wizard">
        <div class="step-meta">
          <span class="step-count">${esc(t("matcher.step", { n: wiz.step + 1, total }))}</span>
          <span class="step-count">FeeFix · ${esc(t("matcher.title"))}</span>
        </div>
        <div class="progress-track"><div class="progress-fill" style="width:${((wiz.step + 1) / total) * 100}%"></div></div>
        <div class="wizard-card" key="step-${wiz.step}">
          <h2>${esc(step.q)}</h2>
          ${step.help ? `<p class="help">${esc(step.help)}</p>` : ""}
          <div id="stepBody">${step.render()}</div>
          <div class="wizard-actions">
            <button class="btn btn-ghost" id="wizBack" ${wiz.step === 0 ? "disabled" : ""}>← ${esc(t("matcher.back"))}</button>
            <div style="display:flex;gap:10px">
              ${step.skippable ? `<button class="btn btn-ghost" id="wizSkip">${esc(t("matcher.skip"))}</button>` : ""}
              <button class="btn btn-primary" id="wizNext">
                ${wiz.step === total - 1 ? "✦ " + esc(t("matcher.finish")) : esc(t("matcher.next")) + " →"}
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>`;

  attachStepHandlers(step);

  $("#wizBack").addEventListener("click", () => {
    wiz.step = Math.max(0, wiz.step - 1);
    renderWizard($("#view"), -1);
  });
  $("#wizSkip")?.addEventListener("click", advance);
  $("#wizNext").addEventListener("click", advance);

  async function advance() {
    if (wiz.step < wizardSteps().length - 1) {
      wiz.step++;
      renderWizard($("#view"), 1);
    } else {
      $("#wizNext").disabled = true;
      $("#wizNext").textContent = t("common.loading");
      try {
        const profile = { ...wiz.data };
        if (profile.last_exam_percentage === "" || profile.last_exam_percentage == null)
          profile.last_exam_percentage = null;
        // Persist profile + get matches in one call.
        const results = await api(`/api/students/${State.sid}/profile`, {
          method: "PUT",
          body: JSON.stringify({ profile, lang: State.lang }),
        });
        State.lastResults = results;
        location.hash = "#/results";
      } catch (e) {
        toast(t("common.error") + ": " + e.message);
        $("#wizNext").disabled = false;
        $("#wizNext").textContent = "✦ " + t("matcher.finish");
      }
    }
  }
}

/* --- step renderers --- */
function renderStateStep() {
  const states = State.meta?.states || [];
  const cur = State.wizard.data.domicile_state || "";
  return `
    <div class="search-select">
      <input id="stateInput" placeholder="State / राज्य / রাজ্য…" value="${esc(cur)}" autocomplete="off" />
      <div class="drop" id="stateDrop" style="display:none"></div>
    </div>`;
}

function renderCategoryStep() {
  const cur = State.wizard.data.category;
  const opts = [
    ["general", "General", "No reservation category"],
    ["sc", "SC", "Scheduled Caste"],
    ["st", "ST", "Scheduled Tribe"],
    ["obc", "OBC", "OBC-A / OBC-B · Non-creamy layer"],
  ];
  return `<div class="opt-grid">${opts
    .map(([v, l, s]) => `
      <button class="opt-card ${cur === v ? "sel" : ""}" data-k="category" data-v="${v}">
        <span class="ic">${{ general: "🪪", sc: "🏷️", st: "🏷️", obc: "🏷️" }[v]}</span>
        <span>${l}<small>${s}</small></span>
      </button>`)
    .join("")}</div>`;
}

function renderIncomeStep() {
  const v = State.wizard.data.annual_family_income ?? 200000;
  return `
    <div class="income-val" id="incomeVal">${fmtINR(v)}</div>
    <input type="range" id="incomeRange" min="0" max="1500000" step="10000" value="${v}" style="--fill:${(v / 1500000) * 100}%"/>
    <div class="range-marks"><span>₹0</span><span>₹5L</span><span>₹10L</span><span>₹15L+</span></div>`;
}

function renderCourseStep() {
  const cur = State.wizard.data.course_level;
  const labels = {
    en: { school: "School (VI–X)", higher_secondary: "Class XI–XII (HS)", iti: "ITI", diploma: "Diploma / Polytechnic", ug: "Undergraduate", pg: "Postgraduate", phd: "PhD / Research" },
    bn: { school: "স্কুল (VI–X)", higher_secondary: "XI–XII (HS)", iti: "ITI", diploma: "ডিপ্লোমা", ug: "স্নাতক (UG)", pg: "স্নাতকোত্তর (PG)", phd: "PhD" },
    hi: { school: "स्कूल (VI–X)", higher_secondary: "XI–XII (HS)", iti: "ITI", diploma: "डिप्लोमा", ug: "स्नातक (UG)", pg: "स्नातकोत्तर (PG)", phd: "PhD" },
  }[State.lang] || {};
  const subs = {
    ug: "B.Tech · MBBS · B.Sc · BA · B.Com", pg: "M.Tech · M.Sc · MBA · MA",
    school: "Class 6–10", higher_secondary: "Intermediate", iti: "Trade courses", diploma: "After class 10", phd: "Doctoral",
  };
  const order = ["school", "higher_secondary", "iti", "diploma", "ug", "pg", "phd"];
  return `<div class="opt-grid">${order
    .map((v) => `
      <button class="opt-card ${cur === v ? "sel" : ""}" data-k="course_level" data-v="${v}">
        <span class="ic">${COURSE_ICONS[v]}</span>
        <span>${labels[v] || v}<small>${subs[v] || ""}</small></span>
      </button>`)
    .join("")}</div>`;
}

function renderMarksStep() {
  const v = State.wizard.data.last_exam_percentage;
  return `
    <div class="marks-input">
      <input id="marksInput" type="number" min="0" max="100" step="0.1" placeholder="82" value="${v ?? ""}" />
      <span>%</span>
    </div>`;
}

function renderGenderStep() {
  const cur = State.wizard.data.gender;
  const opts = [["female", "👩", "Female"], ["male", "👨", "Male"], ["other", "🧑", "Other"], ["prefer_not_to_say", "🤐", "Prefer not to say"]];
  return `<div class="pill-row">${opts
    .map(([v, ic, l]) => `<button class="pill ${cur === v ? "sel" : ""}" data-k="gender" data-v="${v}">${ic} ${l}</button>`)
    .join("")}</div>`;
}

function renderDetailsStep() {
  const d = State.wizard.data;
  const communities = State.meta?.minority_communities || [];
  return `
    <div class="check-row">
      <label class="check ${d.is_minority ? "sel" : ""}" id="chkMinority">
        <input type="checkbox" ${d.is_minority ? "checked" : ""}/><span class="box">✓</span>
        ${esc(t("matcher.details.minority"))}
      </label>
      <div class="community-row ${d.is_minority ? "show" : ""}" id="communityRow">
        <select id="communitySel">
          <option value="">Select community…</option>
          ${communities.map((c) => `<option value="${c}" ${d.minority_community === c ? "selected" : ""}>${c[0].toUpperCase() + c.slice(1)}</option>`).join("")}
        </select>
      </div>
      <label class="check ${d.has_disability ? "sel" : ""}" id="chkDisability">
        <input type="checkbox" ${d.has_disability ? "checked" : ""}/><span class="box">✓</span>
        ${esc(t("matcher.details.disability"))}
      </label>
      <label class="check ${d.is_single_girl_child ? "sel" : ""}" id="chkGirl">
        <input type="checkbox" ${d.is_single_girl_child ? "checked" : ""}/><span class="box">✓</span>
        ${esc(t("matcher.details.single_girl"))}
      </label>
    </div>`;
}

function attachStepHandlers(step) {
  const wiz = State.wizard;

  // option cards & pills
  $$("#stepBody [data-k]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const k = btn.dataset.k;
      wiz.data[k] = btn.dataset.v;
      $$("#stepBody [data-k]").forEach((b) => {
        if (b.dataset.k === k) b.classList.toggle("sel", b === btn);
      });
    });
  });

  // state search
  const stateInput = $("#stateInput");
  if (stateInput) {
    const drop = $("#stateDrop");
    const states = State.meta?.states || [];
    const show = (items) => {
      if (!items.length) { drop.style.display = "none"; return; }
      drop.innerHTML = items.map((s) => `<button type="button" data-s="${esc(s)}">${esc(s)}</button>`).join("");
      drop.style.display = "block";
      $$("#stateDrop button").forEach((b) =>
        b.addEventListener("click", () => {
          wiz.data.domicile_state = b.dataset.s;
          stateInput.value = b.dataset.s;
          drop.style.display = "none";
        })
      );
    };
    stateInput.addEventListener("focus", () => show(states));
    stateInput.addEventListener("input", () => {
      const q = stateInput.value.toLowerCase();
      show(states.filter((s) => s.toLowerCase().includes(q)).slice(0, 8));
      const exact = states.find((s) => s.toLowerCase() === stateInput.value.trim().toLowerCase());
      if (exact) wiz.data.domicile_state = exact;
    });
    document.addEventListener("click", (e) => {
      if (!drop.contains(e.target) && e.target !== stateInput) drop.style.display = "none";
    });
  }

  // income slider
  const incomeRange = $("#incomeRange");
  if (incomeRange) {
    incomeRange.addEventListener("input", () => {
      const v = +incomeRange.value;
      wiz.data.annual_family_income = v;
      $("#incomeVal").textContent = fmtINR(v);
      incomeRange.style.setProperty("--fill", `${(v / 1500000) * 100}%`);
    });
  }

  // marks
  const marksInput = $("#marksInput");
  if (marksInput) {
    marksInput.addEventListener("input", () => {
      const v = marksInput.value.trim();
      wiz.data.last_exam_percentage = v === "" ? null : Math.min(100, Math.max(0, +v));
    });
  }

  // details checkboxes
  const bindCheck = (id, key, after) => {
    const el = $(id);
    if (!el) return;
    el.addEventListener("change", () => {
      wiz.data[key] = el.querySelector("input").checked;
      el.classList.toggle("sel", wiz.data[key]);
      after && after();
    });
  };
  bindCheck("#chkMinority", "is_minority", () => {
    $("#communityRow").classList.toggle("show", wiz.data.is_minority);
    wiz.data.minority_community = wiz.data.is_minority ? wiz.data.minority_community : null;
  });
  bindCheck("#chkDisability", "has_disability");
  bindCheck("#chkGirl", "is_single_girl_child");
  const sel = $("#communitySel");
  if (sel) sel.addEventListener("change", () => (wiz.data.minority_community = sel.value || null));
}

/* ========================================================== RESULTS VIEW */
function ResultsView(el) {
  const res = State.lastResults;
  if (!res) { location.hash = "#/matcher"; return; }
  const matches = res.matches || [];
  const open = matches.filter((m) => !m.deadline.expired);
  const near = res.near_misses || [];

  el.innerHTML = `
    <section class="section" style="padding-top:52px">
      <div class="section-head" style="margin-bottom:34px">
        <h2>${esc(t("results.title"))}</h2>
        <p>${esc(t("results.subtitle"))}</p>
      </div>
      <div class="results-summary">
        <div class="stat"><div class="num">${res.open_match_count}/${res.match_count}</div><div class="lbl">${esc(t("results.matches"))} · ${esc(t("results.open"))}</div></div>
        <div class="stat"><div class="num">${fmtINR(res.total_indicative_annual_benefit_inr)}</div><div class="lbl">${esc(t("results.pool"))}</div></div>
        <div class="stat"><div class="num">${res.evaluated_schemes}</div><div class="lbl">${esc(t("results.evaluated"))}</div></div>
      </div>
      <div style="display:flex;justify-content:flex-end;margin-bottom:14px">
        <button class="btn btn-ghost btn-small" id="mlToggle">⚡ ${esc(t("results.ml_preview"))}</button>
      </div>
      <div id="matchList">
        ${open.length ? "" : `<div class="empty"><div class="big">🎯</div>${esc(t("results.empty"))}</div>`}
      </div>
      ${near.length ? `
        <div class="near-block">
          <div class="section-head" style="margin-bottom:26px;text-align:left">
            <h2 style="font-size:1.4rem">${esc(t("results.near.title"))}</h2>
            <p>${esc(t("results.near.subtitle"))}</p>
          </div>
          ${near.slice(0, 6).map(nearCardHTML).join("")}
        </div>` : ""}
    </section>`;

  const list = $("#matchList");
  open.forEach((m, i) => {
    const card = document.createElement("div");
    card.innerHTML = matchCardHTML(m, i);
    list.appendChild(card.firstElementChild);
  });
  bindMatchCards(el);
  // Stagger.
  $$(".match-card", el).forEach((c, i) => (c.style.animationDelay = `${i * 70}ms`));

  // --- ML preview: rerank with the outcome model and show probabilities.
  const mlBtn = $("#mlToggle");
  let mlOn = false;
  mlBtn.addEventListener("click", async () => {
    if (mlOn) { location.reload(); return; }
    mlBtn.disabled = true;
    try {
      const data = await api(`/api/ml/rank/${State.sid}`);
      const order = new Map(data.items.map((it) => [it.scheme_id, it]));
      const list = $("#matchList");
      const cards = $$(".match-card", list);
      cards
        .sort((a, b) => (order.get(a.dataset.id)?.v2_rank ?? 999) - (order.get(b.dataset.id)?.v2_rank ?? 999))
        .forEach((c) => list.appendChild(c));
      cards.forEach((c) => {
        const it = order.get(c.dataset.id);
        if (!it) return;
        const chip = document.createElement("span");
        chip.className = "badge ml-chip";
        chip.textContent = `⚡ ML ${(it.model_probability * 100).toFixed(0)}%`;
        const badges = c.querySelector(".badge-row");
        if (badges && !badges.querySelector(".ml-chip")) badges.appendChild(chip);
      });
      const note = document.createElement("div");
      note.className = "ml-note";
      note.textContent = `V2 outcome model · trained on ${data.trained_on} samples${data.bootstrap ? " (synthetic bootstrap until real outcomes accumulate)" : ""}`;
      list.before(note);
      mlOn = true;
      mlBtn.textContent = "↩ " + t("results.ml_preview_off");
    } catch (e) {
      toast(e.message);
    }
    mlBtn.disabled = false;
  });
}

function matchCardHTML(m) {
  const why = (m.why_matched || []).slice(0, 3);
  const assumptions = m.assumptions || [];
  const isSaved = !!State.board[m.id];
  return `
    <div class="match-card" data-id="${esc(m.id)}">
      ${ringSVG(m.score)}
      <div class="match-body">
        <h3>${esc(m.name)}</h3>
        <div class="provider">${esc(m.provider)}</div>
        <div class="badge-row">${(m.badges || []).map(badgeHTML).join("")}</div>
        <div class="why-list">
          ${why.map((r) => `<div class="why-item"><span class="tick">✓</span><span>${esc(r)}</span></div>`).join("")}
          ${assumptions.slice(0, 2).map((a) => `<div class="why-item warn"><span class="tick">⚠</span><span>${esc(a.detail)}</span></div>`).join("")}
        </div>
      </div>
      <div class="match-side">
        <div style="display:flex;flex-direction:column;gap:8px;align-items:flex-end">
          ${deadlineChip(m.deadline)}
          <div class="benefit-amount">${esc(m.benefit.amount_display)}</div>
        </div>
        <div class="match-actions">
          <button class="btn btn-ghost btn-small" data-act="save">${isSaved ? "✓ " + esc(t("results.saved")) : "+ " + esc(t("results.save"))}</button>
          <button class="btn btn-primary btn-small" data-act="view">${esc(t("results.view"))}</button>
        </div>
      </div>
    </div>`;
}

function nearCardHTML(n) {
  return `
    <div class="near-card" data-id="${esc(n.id)}">
      <h4>${esc(n.name)}</h4>
      <div class="blocker">⚠ ${esc(n.failed_rule.detail)}</div>
      ${n.gap_advice ? `<div class="advice">💡 ${esc(n.gap_advice)}</div>` : ""}
      <button class="btn btn-ghost btn-small" data-act="view">${esc(t("results.view"))}</button>
    </div>`;
}

function bindMatchCards(root) {
  $$("[data-id]", root).forEach((card) => {
    const id = card.dataset.id;
    card.querySelector('[data-act="view"]')?.addEventListener("click", () => openScheme(id));
    card.querySelector('[data-act="save"]')?.addEventListener("click", async (e) => {
      try {
        const saved = !State.board[id];
        await api(`/api/tracker/${State.sid}/${id}`, {
          method: "PUT",
          body: JSON.stringify({ status: saved ? "saved" : null }),
        });
        if (saved) State.board[id] = { status: "saved" };
        else delete State.board[id];
        e.target.innerHTML = saved ? `✓ ${esc(t("results.saved"))}` : `+ ${esc(t("results.save"))}`;
        toast(saved ? t("results.saved") : t("dash.remove"));
      } catch (err) { toast(err.message); }
    });
  });
}

/* ========================================================= SCHEME DRAWER */
async function openScheme(id, viaRoute = false) {
  const scrim = $("#drawerScrim");
  const drawer = $("#drawer");
  try {
    const s = await api(`/api/schemes/${id}`);
    // Enrich with match context when available.
    let ctx = null;
    const res = State.lastResults;
    if (res) ctx = [...(res.matches || []), ...(res.near_misses || [])].find((x) => x.id === id);

    const dl = ctx?.deadline || s.deadline;
    const why = ctx?.why_matched || [];
    const assumptions = ctx?.assumptions || [];
    const saved = State.board[id]?.status;

    drawer.innerHTML = `
      <button class="drawer-close" id="drawerClose">✕</button>
      <div class="badge-row">${(ctx?.badges || []).map(badgeHTML).join("")}
        <span class="badge ${s.verification_status === "verified" ? "verified" : ""}">${esc(t(s.verification_status === "verified" ? "scheme.verified" : "scheme.pending"))}</span>
      </div>
      <h2>${esc(s.name)}</h2>
      <div class="provider">${esc(s.provider)}</div>
      ${deadlineChip(dl)}
      <div class="d-section"><div class="d-box">${esc(s.summary)}</div></div>

      ${ctx?.gap_advice ? `
        <div class="d-section"><div class="d-box" style="border-color:rgba(251,191,36,0.35);background:var(--amber-soft)">
          💡 <b style="color:var(--amber)">${esc(t("near.advice"))}</b>
          <p style="color:var(--text-soft);font-size:0.9rem;margin-top:6px">${esc(ctx.gap_advice)}</p>
        </div></div>` : ""}

      ${why.length ? `
        <div class="d-section"><h4>${esc(t("results.why"))}</h4>
          <div class="d-box"><ul class="d-list">
            ${why.map((r) => `<li><span class="tick">✓</span>${esc(r)}</li>`).join("")}
            ${assumptions.map((a) => `<li><span class="tick" style="color:var(--amber)">⚠</span>${esc(a.detail)}</li>`).join("")}
          </ul></div>
        </div>` : ""}

      <div class="d-section"><h4>${esc(t("scheme.eligibility"))}</h4>
        <div class="elig-grid">
          ${eligItem("Domicile", s.eligibility.domicile_states?.join(", ") || "All India")}
          ${eligItem("Income cap", s.eligibility.max_family_income ? fmtINR(s.eligibility.max_family_income) + "/yr" : t("common.na"))}
          ${eligItem("Category", s.eligibility.categories?.map((c) => c.toUpperCase()).join(", ") || t("common.na"))}
          ${eligItem("Course", s.eligibility.course_levels?.map((c) => c.replace("_", " ")).join(", ") || t("common.na"))}
          ${s.eligibility.min_marks_percent ? eligItem("Merit", `≥${s.eligibility.min_marks_percent}% in last exam`) : ""}
          ${s.eligibility.minority_only ? eligItem("Community", "Notified minority communities") : ""}
          ${s.eligibility.disability_required ? eligItem("Disability", "Benchmark disability (40%+)") : ""}
        </div>
        ${s.eligibility.special_conditions?.length ? `<div class="d-box" style="margin-top:10px"><ul class="d-list">${s.eligibility.special_conditions.map((c) => `<li><span class="tick" style="color:var(--amber)">▹</span>${esc(c)}</li>`).join("")}</ul></div>` : ""}
      </div>

      <div class="d-section"><h4>${esc(t("scheme.benefit"))}</h4>
        <div class="d-box">
          <div class="benefit-amount" style="text-align:left;font-size:1.1rem">${esc(s.benefit.amount_display)}</div>
          <p style="color:var(--text-soft);font-size:0.9rem;margin-top:6px">${esc(s.benefit.details)}</p>
        </div>
      </div>

      <div class="d-section"><h4>${esc(t("scheme.documents"))}</h4>
        <div class="d-box"><ul class="doc-list">${s.documents.map((d) => `<li>${esc(d)}</li>`).join("")}</ul></div>
      </div>

      <div class="d-section"><h4>${esc(t("scheme.steps"))}</h4>
        <div class="d-box"><ul class="d-list">
          ${s.application.steps.map((st, i) => `<li><span class="n">${i + 1}</span><span>${esc(st)}</span></li>`).join("")}
        </ul></div>
      </div>

      <div class="d-section"><h4>${esc(t("scheme.track"))}</h4>
        <div class="track-row" id="trackRow">
          ${(State.meta?.track_statuses || []).map((st) => `
            <button class="track-btn ${saved === st ? "on" : ""}" data-status="${st}">${esc(t("dash.status." + st))}</button>`).join("")}
        </div>
      </div>

      <div class="d-section" style="display:flex;gap:10px;flex-wrap:wrap">
        <a class="btn btn-primary" href="${esc(s.application.url)}" target="_blank" rel="noopener">↗ ${esc(t("common.apply_official"))}</a>
      </div>
      <p style="color:var(--text-dim);font-size:0.78rem;margin-top:22px">${esc(s.notes || "")}</p>`;

    scrim.classList.add("open");
    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
    if (viaRoute) $("#view").innerHTML = "";

    const close = () => {
      scrim.classList.remove("open");
      drawer.classList.remove("open");
      drawer.setAttribute("aria-hidden", "true");
    };
    $("#drawerClose").addEventListener("click", close);
    scrim.onclick = close;

    $$("#trackRow .track-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const status = btn.dataset.status;
        const current = State.board[id]?.status;
        const next = current === status ? null : status;
        await api(`/api/tracker/${State.sid}/${id}`, {
          method: "PUT", body: JSON.stringify({ status: next }),
        });
        if (next) State.board[id] = { status: next }; else delete State.board[id];
        $$("#trackRow .track-btn").forEach((b) => b.classList.toggle("on", b.dataset.status === next));
        toast(next ? t("dash.status." + next) : t("dash.remove"));
      });
    });
  } catch (e) {
    toast(e.message);
  }
}

function eligItem(k, v) {
  return `<div class="elig-item"><b>${esc(k)}</b>${esc(v)}</div>`;
}

/* ========================================================= DASHBOARD VIEW */
async function DashboardView(el) {
  el.innerHTML = `<section class="section" style="padding-top:52px"><div class="empty">${esc(t("common.loading"))}</div></section>`;
  try {
    const [matchRes, boardRes, remRes] = await Promise.all([
      api(`/api/match/${State.sid}`),
      api(`/api/tracker/${State.sid}`),
      api(`/api/students/${State.sid}/reminders`),
    ]);
    State.lastResults = State.lastResults || matchRes;
    State.board = Object.fromEntries((boardRes.items || []).map((i) => [i.id, i.track]));

    const open = matchRes.matches.filter((m) => !m.deadline.expired);
    const urgent = open.filter((m) => m.deadline.days_left != null && m.deadline.days_left <= 30);
    const board = State.board;
    const counts = (st) => Object.values(board).filter((x) => x.status === st).length;

    const groups = [
      { title: t("dash.saved"), keys: ["saved", "planning"] },
      { title: t("dash.applied"), keys: ["applied", "under_review"] },
      { title: t("dash.outcomes"), keys: ["approved", "rejected"] },
    ];

    el.innerHTML = `
      <section class="section" style="padding-top:52px">
        <div class="section-head" style="text-align:left;margin-bottom:30px">
          <h2>${esc(t("dash.title"))}</h2>
          <p>${esc(t("dash.subtitle"))}</p>
        </div>

        <div class="dash-grid">
          <div class="stat"><div class="num">${matchRes.open_match_count}</div><div class="lbl">${esc(t("dash.matches"))}</div></div>
          <div class="stat"><div class="num">${urgent.length}</div><div class="lbl">${esc(t("dash.urgent"))}</div></div>
          <div class="stat"><div class="num">${counts("saved") + counts("planning")}</div><div class="lbl">${esc(t("dash.saved"))}</div></div>
          <div class="stat"><div class="num">${counts("applied") + counts("under_review")}</div><div class="lbl">${esc(t("dash.applied"))}</div></div>
        </div>

        <div class="board-group">
          <h3>⏰ ${esc(t("dash.reminders"))} <span class="count">${remRes.count}</span></h3>
          ${remRes.reminders.length ? remRes.reminders.map(reminderHTML).join("") :
            `<div class="empty"><div class="big">🎉</div>${esc(t("dash.no_reminders"))}</div>`}
          <button class="btn btn-ghost btn-small" id="dispatchBtn" style="margin-top:8px">📲 ${esc(t("dash.dispatch"))}</button>
          <div id="dispatchNote"></div>
        </div>

        <div class="board-group">
          <h3>🎯 ${esc(t("dash.matches"))} <span class="count">${open.length}</span></h3>
          ${open.slice(0, 6).map(miniMatchHTML).join("")}
          ${open.length > 6 ? `<a href="#/results" class="btn btn-ghost btn-small" style="margin-top:8px">${esc(t("results.view"))} →</a>` : ""}
        </div>

        ${groups.map((g) => {
          const items = (boardRes.items || []).filter((i) => g.keys.includes(i.track.status));
          if (!items.length) return "";
          return `<div class="board-group"><h3>${esc(g.title)} <span class="count">${items.length}</span></h3>
            ${items.map(trackedHTML).join("")}</div>`;
        }).join("")}
      </section>`;

    bindMatchCards(el);
    $$(".match-card", el).forEach((c, i) => (c.style.animationDelay = `${i * 60}ms`));

    $("#dispatchBtn")?.addEventListener("click", async () => {
      const btn = $("#dispatchBtn");
      btn.disabled = true;
      try {
        const r = await api(`/api/students/${State.sid}/reminders/dispatch`, {
          method: "POST", body: JSON.stringify({ limit: 10 }),
        });
        $("#dispatchNote").innerHTML =
          `<div class="dispatch-note">✓ ${r.dispatched} reminder(s) queued in the WhatsApp outbox (demo).</div>`;
      } catch (e) { toast(e.message); }
      btn.disabled = false;
    });

    // tracked steppers
    $$("[data-track-item]").forEach((card) => {
      const id = card.dataset.trackItem;
      $$(".track-btn", card).forEach((btn) => {
        btn.addEventListener("click", async () => {
          const st = btn.dataset.status === "remove" ? null : btn.dataset.status;
          await api(`/api/tracker/${State.sid}/${id}`, { method: "PUT", body: JSON.stringify({ status: st }) });
          DashboardView(el);
        });
      });
      $(`[data-track-view]`, card)?.addEventListener("click", () => openScheme(id));
    });
  } catch (e) {
    el.innerHTML = `<section class="section" style="padding-top:52px"><div class="empty"><div class="big">⚠️</div>${esc(e.message)}</div></section>`;
  }
}

function reminderHTML(r) {
  const icons = { high: "🔥", medium: "⏳", low: "🗂" };
  return `
    <div class="reminder-item ${esc(r.severity)}">
      <div class="r-ic">${icons[r.severity] || "•"}</div>
      <div class="r-tx">${esc(r.message)}</div>
      ${r.days_left != null ? `<div class="r-days">${esc(t("scheme.days_left", { n: r.days_left }))}</div>` : ""}
    </div>`;
}

function miniMatchHTML(m) {
  return `
    <div class="near-card" data-id="${esc(m.id)}">
      <h4>${esc(m.name)}</h4>
      ${deadlineChip(m.deadline)}
      <button class="btn btn-ghost btn-small" data-act="view">${esc(t("results.view"))}</button>
    </div>`;
}

function trackedHTML(item) {
  const statuses = State.meta?.track_statuses || [];
  return `
    <div class="match-card" data-track-item="${esc(item.id)}" style="grid-template-columns:1fr;gap:14px">
      <div class="match-body">
        <h3>${esc(item.name)}</h3>
        <div class="provider">${esc(item.benefit.amount_display)} · ${esc(item.provider)}</div>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px">
        <div class="status-stepper">
          ${statuses.map((st) => `<button class="track-btn ${item.track.status === st ? "on" : ""}" data-status="${st}">${esc(t("dash.status." + st))}</button>`).join("")}
          <button class="track-btn" data-status="remove" style="color:var(--red)">✕</button>
        </div>
        <button class="btn btn-ghost btn-small" data-track-view>↗</button>
      </div>
    </div>`;
}

/* =========================================================== EXPLORE VIEW */
async function ExploreView(el) {
  el.innerHTML = `<section class="section" style="padding-top:52px"><div class="empty">${esc(t("common.loading"))}</div></section>`;
  let filter = { q: "", level: "", feeWaiver: false };
  let debouncer = null;

  async function load() {
    const params = new URLSearchParams();
    if (filter.q) params.set("q", filter.q);
    if (filter.level) params.set("level", filter.level);
    if (filter.feeWaiver) params.set("fee_waiver", "true");
    const data = await api(`/api/schemes?${params.toString()}`);
    renderGrid(data.schemes);
  }

  function shell() {
    el.innerHTML = `
      <section class="section" style="padding-top:52px">
        <div class="section-head" style="text-align:left;margin-bottom:26px">
          <h2>${esc(t("explore.title"))}</h2>
          <p>${esc(t("explore.subtitle"))}</p>
        </div>
        <div class="ask-box" id="askBox">
          <div class="ask-head">✦ ${esc(t("explore.ask.title"))}</div>
          <div class="ask-row">
            <input id="askInput" placeholder="${esc(t("explore.ask.placeholder"))}" />
            <button class="btn btn-primary btn-small" id="askBtn">${esc(t("explore.ask.button"))}</button>
          </div>
          <div class="ask-out" id="askOut" style="display:none"></div>
        </div>
        <div class="filter-bar">
          <input type="search" id="expSearch" placeholder="${esc(t("explore.search"))}" />
          <div class="pill-row" id="expLevel">
            <button class="pill sel" data-l="">${esc(t("explore.all"))}</button>
            <button class="pill" data-l="state">${esc(t("explore.state"))}</button>
            <button class="pill" data-l="central">${esc(t("explore.central"))}</button>
          </div>
          <div class="pill-row"><button class="pill" id="expFee">🎟 ${esc(t("explore.fee_waiver"))}</button></div>
        </div>
        <div class="explore-grid" id="expGrid"></div>
      </section>`;
  }

  function renderGrid(schemes) {
    const grid = $("#expGrid");
    if (!grid) return;
    grid.innerHTML = schemes.length
      ? schemes.map((s) => `
        <div class="explore-card" data-id="${esc(s.id)}">
          <div>
            <div class="provider">${esc(s.provider)}</div>
            <h3 style="margin-top:6px">${esc(s.name)}</h3>
          </div>
          <div class="badge-row">
            <span class="badge ${s.level === "state" ? "state_scheme" : "all_india"}">${esc(t(s.level === "state" ? "badge.state_scheme" : "badge.all_india"))}</span>
            ${s.benefit.type === "fee_waiver" ? `<span class="badge fee_waiver">${esc(t("badge.fee_waiver"))}</span>` : ""}
            ${s.verification_status === "verified" ? `<span class="badge verified">${esc(t("badge.verified"))}</span>` : ""}
          </div>
          <div class="bottom">
            <span class="amt">${esc(s.benefit.amount_display)}</span>
            <span style="color:var(--text-dim);font-size:0.8rem">${s.deadline.rolling ? "∞" : esc(s.deadline.date || "")}</span>
          </div>
        </div>`).join("")
      : `<div class="empty"><div class="big">🔎</div>${esc(t("results.empty"))}</div>`;
    $$(".explore-card", grid).forEach((c) =>
      c.addEventListener("click", () => openScheme(c.dataset.id))
    );
  }

  shell();
  await load();

  // --- Ask FeeFix (grounded AI Q&A) ---
  const askBtn = $("#askBtn");
  const askInput = $("#askInput");
  const ask = async () => {
    const q = askInput.value.trim();
    if (!q) return;
    askBtn.disabled = true;
    askBtn.textContent = t("common.loading");
    const out = $("#askOut");
    out.style.display = "block";
    out.innerHTML = `<div class="ask-loading">${esc(t("common.loading"))}</div>`;
    try {
      const r = await api("/api/ask", {
        method: "POST",
        body: JSON.stringify({ question: q, session_id: State.sid }),
      });
      out.innerHTML = `
        <div class="ask-answer">${mdLite(r.answer)}</div>
        <div class="cite-row">
          ${(r.citations || []).map((c) => `<button class="cite-chip" data-cite="${esc(c.id)}">↗ ${esc(c.name.length > 42 ? c.name.slice(0, 42) + "…" : c.name)}</button>`).join("")}
          <span class="ask-mode">FeeFix AI · ${esc(r.backend)} · ${esc(r.mode === "profile" ? t("ask.mode.profile") : t("ask.mode.search"))}</span>
        </div>`;
      $$(".cite-chip", out).forEach((c) =>
        c.addEventListener("click", () => openScheme(c.dataset.cite))
      );
    } catch (e) {
      out.innerHTML = `<div class="ask-answer">⚠ ${esc(e.message)}</div>`;
    }
    askBtn.disabled = false;
    askBtn.textContent = t("explore.ask.button");
  };
  askBtn.addEventListener("click", ask);
  askInput.addEventListener("keydown", (e) => { if (e.key === "Enter") ask(); });

  $("#expSearch").addEventListener("input", (e) => {
    filter.q = e.target.value;
    clearTimeout(debouncer);
    debouncer = setTimeout(load, 260);
  });
  $$("#expLevel .pill").forEach((p) =>
    p.addEventListener("click", () => {
      $$("#expLevel .pill").forEach((x) => x.classList.toggle("sel", x === p));
      filter.level = p.dataset.l;
      load();
    })
  );
  $("#expFee").addEventListener("click", (e) => {
    filter.feeWaiver = !filter.feeWaiver;
    e.target.classList.toggle("sel", filter.feeWaiver);
    load();
  });
}

/* ================================================================= CHAT  */
const Chat = {
  id: localStorage.getItem("feefix.chat") || null,
  opened: false,

  open() {
    const panel = $("#chatPanel");
    panel.classList.add("open");
    panel.setAttribute("aria-hidden", "false");
    if (!this.opened) {
      this.opened = true;
      panel.innerHTML = `
        <div class="chat-head">
          <div class="avatar">Fx</div>
          <div><div class="t">${esc(t("chat.title"))}</div><div class="s">● ${esc(t("chat.subtitle"))}</div></div>
        </div>
        <div class="chat-body" id="chatBody"></div>
        <div class="chat-input">
          <input id="chatInput" placeholder="${esc(t("chat.placeholder"))}" />
          <button id="chatSend">➤</button>
        </div>`;
      $("#chatSend").addEventListener("click", () => this.send());
      $("#chatInput").addEventListener("keydown", (e) => { if (e.key === "Enter") this.send(); });
      this.say("hi");
    }
  },

  close() {
    const panel = $("#chatPanel");
    panel.classList.remove("open");
    panel.setAttribute("aria-hidden", "true");
  },

  bubble(text, who) {
    const body = $("#chatBody");
    const b = document.createElement("div");
    b.className = `bub ${who}`;
    b.innerHTML = mdLite(text);
    body.appendChild(b);
    body.scrollTop = body.scrollHeight;
  },

  citations(list) {
    if (!list?.length) return;
    const body = $("#chatBody");
    const row = document.createElement("div");
    row.className = "cite-row chat-cites";
    row.innerHTML = list.map((c) =>
      `<button class="cite-chip" data-cite="${esc(c.id)}">↗ ${esc(c.name.length > 34 ? c.name.slice(0, 34) + "…" : c.name)}</button>`
    ).join("");
    body.appendChild(row);
    row.querySelectorAll(".cite-chip").forEach((c) =>
      c.addEventListener("click", () => openScheme(c.dataset.cite))
    );
    body.scrollTop = body.scrollHeight;
  },

  async say(message) {
    this.bubble(message, message === "hi" ? "bot" : "user");
    const body = $("#chatBody");
    const typing = document.createElement("div");
    typing.className = "bub bot typing";
    typing.innerHTML = "<i></i><i></i><i></i>";
    body.appendChild(typing);
    body.scrollTop = body.scrollHeight;
    try {
      const r = await api("/api/chat", {
        method: "POST",
        body: JSON.stringify({ message, chat_id: this.id }),
      });
      typing.remove();
      this.id = r.chat_id;
      localStorage.setItem("feefix.chat", r.chat_id);
      this.bubble(r.reply, "bot");
      if (r.citations) this.citations(r.citations);
      if (r.matches) this.citations(r.matches.map((m) => ({ id: m.id, name: m.name })));
    } catch (e) {
      typing.remove();
      this.bubble("⚠ " + t("common.error"), "bot");
    }
  },

  send() {
    const input = $("#chatInput");
    const msg = input.value.trim();
    if (!msg) return;
    input.value = "";
    this.say(msg);
  },
};

/* ================================================================= BOOT  */
async function boot() {
  $("#chatFab").addEventListener("click", () => {
    $("#chatPanel").classList.contains("open") ? Chat.close() : Chat.open();
  });
  await loadLang(State.lang);
  State.fallback = State.dict;
  try {
    [State.meta, State.stats] = await Promise.all([api("/api/meta"), api("/api/stats")]);
  } catch (e) {
    State.meta = { states: [], track_statuses: ["saved", "planning", "applied", "under_review", "approved", "rejected"], minority_communities: [] };
    State.stats = {};
  }
  // Restore board for save-state continuity.
  try {
    const board = await api(`/api/tracker/${State.sid}`);
    State.board = Object.fromEntries((board.items || []).map((i) => [i.id, i.track]));
  } catch (_) { State.board = {}; }

  renderNav();
  renderFooter();
  window.addEventListener("hashchange", route);
  route();
}

boot();

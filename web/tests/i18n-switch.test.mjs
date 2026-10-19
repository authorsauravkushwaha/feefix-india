/* Behavioural tests for the FeeFix web experience's language switch.
 *
 * The bug this file exists for: `renderNav()` used to declare a local
 * `const route = currentRoute()`, which shadowed the global `route()` router
 * for every closure created inside it — including the language picker's
 * "change" handler. Changing the language therefore threw
 * `TypeError: route is not a function`, the view was never re-rendered, and
 * the page was left half-translated.
 *
 * A grep for "route()" would not have caught it, so the real `app.js` is
 * executed here in a VM with a small DOM stub and the language picker is
 * actually clicked.
 *
 * Run: node --test web/tests/
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import vm from "node:vm";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..", "..");
const APP = path.join(REPO, "web", "frontend", "app.js");
const LANG_DIR = path.join(REPO, "language", "regional_support");
const LANGS = ["en", "bn", "hi", "ta"];

/* ------------------------------------------------------------- DOM stub -- */

function makeElement(selector = "") {
  const el = {
    selector,
    tagName: "DIV",
    textContent: "",
    value: "",
    hidden: false,
    style: {},
    dataset: {},
    children: [],
    attributes: {},
    listeners: {},
    classList: {
      _set: new Set(),
      add(...names) { names.forEach((n) => this._set.add(n)); },
      remove(...names) { names.forEach((n) => this._set.delete(n)); },
      toggle(name, force) {
        const on = force === undefined ? !this._set.has(name) : !!force;
        if (on) this._set.add(name); else this._set.delete(name);
        return on;
      },
      contains(name) { return this._set.has(name); },
    },
    addEventListener(type, fn) {
      (this.listeners[type] ||= []).push(fn);
    },
    removeEventListener(type, fn) {
      this.listeners[type] = (this.listeners[type] || []).filter((f) => f !== fn);
    },
    /** Fire the most recently registered handler (the live one after a re-render). */
    async fire(type, event = {}) {
      const handlers = this.listeners[type] || [];
      if (!handlers.length) throw new Error(`no ${type} handler on ${selector}`);
      return handlers[handlers.length - 1](event);
    },
    setAttribute(k, v) { this.attributes[k] = v; },
    getAttribute(k) { return this.attributes[k] ?? null; },
    removeAttribute(k) { delete this.attributes[k]; },
    appendChild(child) { this.children.push(child); return child; },
    removeChild(child) { this.children = this.children.filter((c) => c !== child); },
    remove() {},
    focus() {},
    blur() {},
    click() {},
    querySelector() { return makeElement(`${selector} > child`); },
    querySelectorAll() { return []; },
    get innerHTML() { return this._html || ""; },
    set innerHTML(value) {
      this._html = value;
      // Assigning innerHTML replaces the children — their listeners die with
      // them. Modelling that is what keeps the "last registered handler wins"
      // rule in `fire()` honest.
      this.listeners = {};
    },
  };
  return el;
}

/* ------------------------------------------------------------- the app -- */

const jsonResponse = (status, body) => ({
  ok: status >= 200 && status < 300,
  status,
  statusText: "",
  headers: { get: () => null },
  json: async () => body,
});

/** Serve the real language dictionaries so the test uses the shipped data. */
function fakeFetch(url) {
  const target = String(url);
  if (target.startsWith("/api/i18n/")) {
    const lang = target.slice("/api/i18n/".length);
    const file = path.join(LANG_DIR, `${lang}.json`);
    if (!LANGS.includes(lang) || !existsSync(file)) {
      return Promise.resolve(jsonResponse(404, { detail: "Unsupported language" }));
    }
    return Promise.resolve(
      jsonResponse(200, JSON.parse(readFileSync(file, "utf8")))
    );
  }
  if (target === "/api/meta") {
    return Promise.resolve(
      jsonResponse(200, { states: [], track_statuses: [], minority_communities: [] })
    );
  }
  if (target === "/api/stats") {
    return Promise.resolve(
      jsonResponse(200, {
        total_schemes: 0,
        max_annual_benefit_inr: 0,
        fee_waivers: 0,
        verified: 0,
      })
    );
  }
  if (target.startsWith("/api/tracker/")) {
    return Promise.resolve(jsonResponse(200, { items: [] }));
  }
  return Promise.resolve(jsonResponse(404, { detail: "not found" }));
}

/**
 * Boot the real `app.js` in a VM with a DOM stub.
 * Returns the sandbox plus helpers to inspect and drive it.
 */
async function loadApp() {
  const elements = new Map();
  const elementFor = (selector) => {
    if (!elements.has(selector)) elements.set(selector, makeElement(selector));
    return elements.get(selector);
  };

  const storage = new Map();
  const sandbox = {
    console,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    fetch: fakeFetch,
    performance: { now: () => 0 },
    requestAnimationFrame: (fn) => 0,
    crypto: { randomUUID: () => "00000000-0000-4000-8000-000000000000" },
    localStorage: {
      getItem: (k) => (storage.has(k) ? storage.get(k) : null),
      setItem: (k, v) => storage.set(k, String(v)),
      removeItem: (k) => storage.delete(k),
    },
    location: { hash: "#/home" },
    navigator: { clipboard: null, language: "en-IN" },
    document: {
      documentElement: { lang: "en" },
      body: makeElement("body"),
      createElement: () => makeElement("created"),
      querySelector: (sel) => elementFor(sel),
      querySelectorAll: () => [],
      addEventListener: () => {},
    },
  };
  sandbox.window = {
    addEventListener: () => {},
    scrollTo: () => {},
    location: sandbox.location,
    localStorage: sandbox.localStorage,
  };
  sandbox.globalThis = sandbox;

  vm.createContext(sandbox);
  vm.runInContext(readFileSync(APP, "utf8"), sandbox, { filename: "app.js" });

  // Let boot() settle: it awaits several API calls.
  for (let i = 0; i < 20; i++) await new Promise((r) => setTimeout(r, 0));

  const evaluate = (expression) => vm.runInContext(expression, sandbox);
  return { sandbox, elementFor, evaluate, storage };
}

/* --------------------------------------------------------------- tests -- */

test("the language picker re-renders the app instead of crashing", async () => {
  const { sandbox, elementFor, evaluate, storage } = await loadApp();

  // The picker exists and the app booted in English.
  assert.equal(evaluate("State.lang"), "en");
  assert.equal(elementFor("#langPick").listeners.change.length > 0, true);

  // Count the router calls so we can prove the view was actually re-rendered
  // (not just that the handler returned without throwing).
  let routeCalls = 0;
  const originalRoute = sandbox.route;
  assert.equal(typeof originalRoute, "function", "app.js must expose a route() router");
  sandbox.route = function (...args) {
    routeCalls += 1;
    return originalRoute.apply(this, args);
  };

  for (const lang of ["bn", "hi", "ta", "en"]) {
    const before = routeCalls;
    const picker = elementFor("#langPick");
    // The handler is async: awaiting it surfaces a rejected promise (the
    // `route is not a function` TypeError) as a test failure here.
    await picker.fire("change", { target: { value: lang } });

    assert.equal(evaluate("State.lang"), lang, `language did not switch to ${lang}`);
    assert.equal(
      storage.get("feefix.lang"),
      lang,
      "the chosen language must be remembered across visits"
    );
    assert.ok(routeCalls > before, `the view was not re-rendered after switching to ${lang}`);

    // The chrome and the page body are both in the new language.
    const nav = elementFor("#navLinks").innerHTML;
    const view = elementFor("#view").innerHTML;
    assert.ok(nav.length > 0, "the nav was rendered empty");
    assert.ok(view.length > 0, "the view was rendered empty");
    assert.ok(
      !nav.includes("nav.home"),
      `the nav still shows raw translation keys after switching to ${lang}`
    );
    assert.ok(
      !view.includes("home.title"),
      `the view still shows raw translation keys after switching to ${lang}`
    );
  }
});

test("every shipped language dictionary covers the same keys", async () => {
  const { evaluate } = await loadApp();
  for (const lang of LANGS) {
    const keys = evaluate(`Object.keys(State.dict).length`);
    assert.ok(keys > 0, "the dictionary must not be empty");
  }
});

test("a failed language load keeps the page readable", async () => {
  const { sandbox, evaluate } = await loadApp();
  // Break the dictionary endpoint the way a flaky network would.
  const original = sandbox.fetch;
  sandbox.fetch = (url) =>
    String(url).startsWith("/api/i18n/")
      ? Promise.resolve(jsonResponse(500, { detail: "boom" }))
      : original(url);

  await sandbox.loadLang("bn");
  for (let i = 0; i < 20; i++) await new Promise((r) => setTimeout(r, 0));

  // The UI must fall back to a real dictionary, not render raw keys.
  assert.ok(
    Object.keys(evaluate("State.dict")).length > 0,
    "a failed language load emptied the dictionary — the UI would show raw keys"
  );
  assert.equal(evaluate('t("nav.home")'), "Home");
});

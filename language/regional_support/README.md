# FeeFix Language Layer

Regional-language support is a first-class product layer, not an afterthought.

## How it works

* Dictionaries live here as flat `key → translated string` JSON files
  (`en.json`, `bn.json`, …). Keys are shared across all languages.
* The API serves a dictionary via `GET /api/i18n/{lang}` (whitelist of
  supported codes lives in `backend/api/routes.py`).
* The web app renders everything through the dictionary and re-renders on
  language switch — no page reload.
* Template variables use `{tokens}`: `"matcher.step": "Step {n} of {total}"`.

## Adding a language

1. Copy `en.json` to `<lang>.json` and translate every key.
2. Add the code to `SUPPORTED_LANGS` in `backend/api/routes.py`.
3. Add a toggle entry in the web nav language menu.

## Roadmap tie-in

* **V3 — Regional-language intelligence** (*docs/architecture*): the same
  dictionaries feed the WhatsApp reach layer, so a Bengali student gets Bengali
  questions and Bengali match explanations end to end.
* Longer term: scheme *explanations* ("why you match") become translated
  templates too — the engine already renders them from rule ids, which maps
  cleanly onto per-language templates.

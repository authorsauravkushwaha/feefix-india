<div align="center">

# 🎓 FeeFix India

### Find the funding you qualify for.

**Personalized scholarship & fee-waiver matching platform for Indian students.**

Instead of *“Where can I find scholarships?”* — FeeFix answers
**“Which schemes fit my profile, why do I qualify, and what should I do next?”**

Rule-based matching · fully explainable · multilingual UI · WhatsApp-style reach layer · application tracking · ML-ready ranking

</div>

---

FeeFix is a **decision engine, not a search engine**. A student answers a few
guided questions and gets a personalised, *ranked* set of scholarships and fee
waivers — every match explained, every deadline tracked, every application
nudged along. Phase 1 ships with a verified dataset of **9 West Bengal schemes
+ 12 national schemes**, modelled the launch roadmap.

## ✨ What's inside

| Layer | Where | What it does |
|---|---|---|
| **Web experience** | `web/frontend/` | Full product: guided Smart Matcher wizard → explainable ranked results → scheme pages → dashboard with tracker & reminders. English · বাংলা · हिन्दी. |
| **Matching engine** | `backend/matching_engine/` | Transparent rule engine: `pass / fail / unknown` semantics, **“why you match”** explanations, **near-miss detection** (one requirement away), clarity scoring. |
| **Ranking** | `backend/matching_engine/ranker.py` | `45·clarity + urgency + benefit + verified`, deadline-aware, badges. |
| **API** | `backend/api/`, `backend/main.py` | FastAPI. One origin serves the API *and* the SPA. |
| **Data & verification** | `data/` | 21 curated schemes as structured, validated records with verification manifest. |
| **Reach layer** | `backend/services/chat.py` | WhatsApp-style conversational matcher — *State → Course → Income → matches* — live in the web chat widget. |
| **Notifications** | `backend/notifications/` | Channel-agnostic reminders (console + WhatsApp outbox demo). |
| **Android** | `mobile/android/` | Kotlin/Compose reference scaffold on the same API. |
| **ML (V2)** | `ml/` | Outcome-based logistic ranker over the *same signals* + synthetic training experiment. |
| **Language layer** | `language/regional_support/` | Full dictionary-driven UI: en, বাংলা, हिन्दी. |
| **Tests** | `tests/` | 67 tests: engine, ranking, dataset integrity, API contract, chat intelligence. |

## 🚀 Quickstart

```bash
./scripts/dev.sh           # creates venv, installs deps, serves on :8000
# open http://localhost:8000
```

Run the test suite:

```bash
./scripts/dev.sh --test    # or: .venv/bin/python -m pytest
```

Try the ML experiment:

```bash
.venv/bin/python -m ml.experiments.simulate_outcomes
```

## 🧠 A match, explained

```
POST /api/match  { "profile": { "domicile_state": "West Bengal", "category": "obc",
  "annual_family_income": 95000, "course_level": "ug", "gender": "female",
  "last_exam_percentage": 71 } }

→ matches[0]: aicte-pragati  score 88
  why_matched:
    ✓ Your family income (₹95,000) is within the ₹8,00,000 limit.
    ✓ Your gender matches the scheme's requirement.
    ✓ Your course level (ug) is covered.
  badges: [top_pick, high_value, all_india, verified]   days_left: 34

→ near_misses[0]: nsp-central-sector
  single blocker: Needs ≥80% in the last exam; you reported 71.0%.
```

Unknown answers never disqualify — they lower the *clarity score* and surface
as **“verify these”** assumptions.

## 📁 Repository map

```
feefix-india/
├── backend/
│   ├── api/                 # routes + request schemas
│   ├── matching_engine/     # rules · engine · ranker  (the core)
│   ├── models/              # StudentProfile · Scheme (pydantic)
│   ├── services/            # dataset · matching · tracker · reminders · chat
│   ├── notifications/       # notifier abstraction + WhatsApp outbox
│   └── main.py              # FastAPI app (API + static SPA, one origin)
├── data/
│   ├── schemes/             # west_bengal.json · national.json  (21 schemes)
│   ├── eligibility_rules/   # the rule DSL documentation
│   └── verification/        # verification manifest
├── web/frontend/            # the FeeFix web experience (no build step)
├── mobile/android/          # Kotlin scaffold (same API contract)
├── ml/                      # V2 outcome ranker + experiments
├── language/regional_support/  # en · bn · hi dictionaries
├── docs/                    # architecture · API reference · dataset schema
├── scripts/dev.sh           # one-command dev bootstrap
└── tests/                   # 67 tests
```

## 🗺 Roadmap (matches the product phases)

- [x] **Phase 1 — West Bengal**: verified dataset, rule-based explainable matcher ✅
- [ ] Phase 2 — Multi-state expansion: new `data/schemes/<state>.json` per state; collect real application outcomes
- [ ] Phase 3 — ML ranking: swap hand weights for the trained outcome ranker (`ml/ranking`)
- [ ] Phase 4 — Regional-language depth: explanation templates per language; chat in Bengali/Hindi
- [ ] Phase 5 — Broader student network: colleges & states, same core engine

## ⚖️ Data disclaimer

Benefit amounts, cut-offs and deadlines in `data/` are indicative of recent
public cycles and marked with a curation `notes` field where they shift. Every
record carries an official source, a verification date and a status; always
verify on the official portal before applying. `data/README.md` documents the
verification workflow.

---

<div align="center"><b>Discover. Understand. Apply. Track.</b></div>

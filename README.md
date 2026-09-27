<div align="center">

# 🎓 FeeFix India

### Find the funding you qualify for.

**Personalized scholarship & fee-waiver matching platform for Indian students.**

Instead of *“Where can I find scholarships?”* — FeeFix answers
**“Which schemes fit my profile, why do I qualify, and what should I do next?”**

Rule-based matching · fully explainable · multilingual UI · WhatsApp-style reach layer · application tracking · **free local AI (no paid APIs)** · trained outcome ranking

</div>

---

FeeFix is a **decision engine, not a search engine**. A student answers a few
guided questions and gets a personalised, *ranked* set of scholarships and fee
waivers — every match explained, every deadline tracked, every application
nudged along. The dataset ships verified for **West Bengal (14) + Bihar (6) +
Odisha (6) + Uttar Pradesh (6) + national schemes (7)**, following the phased
launch roadmap.

## ✨ What's inside

| Layer | Where | What it does |
|---|---|---|
| **Web experience** | `web/frontend/` | Full product: guided Smart Matcher wizard → explainable ranked results → scheme pages → dashboard with tracker & reminders → **Ask FeeFix** AI panel. English · বাংলা · हिन्दी. |
| **AI layer (free-only)** | `ai/` | Local open-source embeddings (`fastembed`/MiniLM or built-in n-gram embedder — **never a paid API**), Hinglish/Benglish lexicon, semantic search, and **grounded Q&A** with citations — answers assembled only from verified dataset fields. |
| **Matching engine** | `backend/matching_engine/` | Transparent rule engine: `pass / fail / unknown` semantics, **“why you match”** explanations, **near-miss detection** + **gap coaching** (how to close the one blocking requirement). Every rule result carries parameter slots so explanations can be localized. |
| **Ranking** | `backend/matching_engine/ranker.py` | `45·clarity + urgency + benefit + verified`, deadline-aware, badges. |
| **V2 outcome model** | `ml/ranking/`, `POST /api/events`, `GET /api/ml/rank` | Logistic model trained on real apply/approve/reject outcome signals (synthetic bootstrap until ≥25 real events) — “⚡ ML preview” toggle re-ranks match cards with probabilities. **Same signals V1 uses; no invented facts.** |
| **API** | `backend/api/`, `backend/main.py` | FastAPI. One origin serves the API *and* the SPA. |
| **Data & verification** | `data/` | 39 curated schemes (WB · Bihar · Odisha · UP · central) as structured, validated records with verification manifest. |
| **Reach layer** | `backend/services/chat.py` + `chat_i18n.py` | WhatsApp-style conversational matcher — *State → Course → Income → matches →* **free-text Q&A** — in **English, Bengali & Hindi** (native scripts, দেশি digits `২ লাখ`, state names পশ্চিমবঙ্গ / पश्चिम बंगाल) — live in the web chat widget. |
| **Agents** | `agents/` | Dataset verification agent (data health + CI gate) and reminder scheduler agent (cron-friendly dispatcher). |
| **Notifications** | `backend/notifications/` | Channel-agnostic reminders (console + WhatsApp outbox demo). |
| **Android** | `mobile/android/` | Kotlin/Compose reference scaffold on the same API. |
| **Language layer** | `language/regional_support/` | Full dictionary-driven UI + **localized rule-explanation templates**: en, বাংলা, हिन्दी (income formatted as ₹1,00,000 / ১,০০,০০০ automatically). |
| **CI** | `.github/workflows/` | Tests + dataset agent + ML sanity + scheduler dry-run (free GitHub Actions). |
| **Tests** | `tests/` | 125 tests: engine, ranking, dataset integrity, API contract, chat intelligence, multilingual parsing, AI grounding, agents, ML endpoints. |

## 🚀 Quickstart

```bash
./scripts/dev.sh           # creates venv, installs deps, serves on :8000
# open http://localhost:8000
```

Run the test suite:

```bash
./scripts/dev.sh --test    # or: .venv/bin/python -m pytest
```

Try the agents and experiments:

```bash
.venv/bin/python -m agents.verify_dataset                  # dataset health audit
.venv/bin/python -m agents.reminder_scheduler --dry-run    # what would fire tonight
.venv/bin/python -m ml.experiments.simulate_outcomes       # V2 outcome-ranker demo
```

## 🤖 Ask FeeFix — AI that can't make things up

```bash
curl -X POST http://localhost:8000/api/ask \
  -H 'Content-Type: application/json' \
  -d '{"question": "engineering scholarship for girls"}'
```

Every answer is **grounded**: facts come only from verified dataset fields, so
a hallucinated scheme is impossible. When the question names a profile
("Muslim girl, WB, B.Tech, ₹2 lakh"), the same explaining matching engine
personalises the answer; when it points at a scheme the student misses by one
rule, the answer shows the gap and the coaching advice. All running on **free
local models only** — fastembed/MiniLM when weights are available, a built-in
n-gram embedder everywhere else. See `ai/README.md` for the free-only policy.

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
│   ├── services/            # dataset · matching · coach · tracker · chat · events · i18n
│   ├── notifications/       # notifier abstraction + WhatsApp outbox
│   └── main.py              # FastAPI app (API + static SPA, one origin)
├── ai/                      # FREE-ONLY AI: lexicon · embeddings · search · grounded Q&A
├── agents/                  # dataset verification agent · reminder scheduler agent
├── data/
│   ├── schemes/             # west_bengal · bihar · odisha · uttar_pradesh · national (39 schemes)
│   ├── eligibility_rules/   # the rule DSL documentation
│   └── verification/        # verification manifest
├── web/frontend/            # the FeeFix web experience (no build step)
├── mobile/android/          # Kotlin scaffold (same API contract)
├── ml/                      # V2 outcome ranker + experiments + events-trained service
├── language/regional_support/  # en/bn/hi dictionaries + explanations/ rule templates
├── docs/                    # architecture · API reference · dataset schema
├── .github/workflows/       # CI: tests + agents + ML sanity (free for public repos)
├── scripts/dev.sh           # one-command dev bootstrap
└── tests/                   # 91 tests
```

## 🗺 Roadmap (matches the product phases)

- [x] **Phase 1 — West Bengal**: verified dataset, rule-based explainable matcher ✅
- [x] **Phase 2 — Multi-state expansion begins**: Bihar + Odisha datasets; agent-automated verification ✅
- [x] **Phase 3 — ML ranking**: outcome-event collection + trained logistic reranker live behind the ⚡ ML preview toggle (`/api/events`, `/api/ml/rank`) ✅
- [x] **Phase 4 — Regional-language depth**: explanation templates per language; chat holds full conversations in Bengali/Hindi ✅
- [ ] Phase 5 — Broader student network: colleges & states, same core engine *(in progress — Uttar Pradesh live, tracker↔ML event loop closed)*

## ⚖️ Data disclaimer

Benefit amounts, cut-offs and deadlines in `data/` are indicative of recent
public cycles and marked with a curation `notes` field where they shift. Every
record carries an official source, a verification date and a status; always
verify on the official portal before applying. `data/README.md` documents the
verification workflow.

---

<div align="center"><b>Discover. Understand. Apply. Track.</b></div>

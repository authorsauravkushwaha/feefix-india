# FeeFix Architecture

## System map

```
                    STUDENT
                       │
        ┌──────────────┼──────────────────────┐
        │              │                      │
   WEBSITE        ANDROID APP            REACH LAYER
  web/frontend   mobile/android       (WhatsApp-style chat,
        │              │               backend/services/chat.py)
        └──────────────┼──────────────────────┘
                       │            (same REST surface, same origin)
                  FASTAPI LAYER
                backend/main.py
                backend/api/*
                       │
        ┌──────────────┼───────────────────────┐
        │              │                       │
  PROFILE/        MATCHING ENGINE         NOTIFICATIONS
  TRACKER         backend/matching_engine backend/notifications
  backend/services backend/matching_engine + reminders service
        └──────────────┼───────────────────────┘
                       │
               SCHOLARSHIP DATA LAYER
               data/schemes · data/eligibility_rules · data/verification
                       │
              ┌────────┴────────┐
              │                 │
         CURRENT V1          V2 / V3
        Rule Engine        ML ranking (ml/) + language layer (language/)
```

## The single decision: explainability over magic

V1 matching is **explicit rules**, never predictions:

```
StudentProfile  →  evaluate_rules()  →  RuleSet(pass/fail/unknown)
                                          │
                          no fails → MATCH (unknowns = assumptions)
                          1 fail   → NEAR MISS ("one requirement away")
                          2+ fails → not shown
```

Every match carries `why_matched` sentences and every unknown becomes a
visible assumption (and lowers the clarity score 45 weight in ranking).

Ranking V1: `45·clarity + urgency(0..25) + benefit_norm(0..20) + verified(0..5)`,
with expired windows pushed below open ones. **The ML layer trains on these
exact signals**, so V2 changes only the weights, never the contract.

## Request flow — "Find my matches"

```
web wizard ──PUT /api/students/{sid}/profile──▶ routes.py
      │                                          │
      │                              match_profile(profile, dataset)
      │                              EligibilityEngine.match()
      │                              RankingEngine.rank()
      │                                          │
      ◀────────── {matches[ {scheme, why, assumptions, score, badges, deadline} ],
                   near_misses[]} ───────────────┘
```

The same response object powers the results page, the dashboard, the Android
client and the WhatsApp conversation — one payload, four product surfaces.

## Service responsibilities

| Module | Responsibility |
|---|---|
| `backend/models` | Pydantic models. Data validity is a compile-time error, not a runtime surprise. |
| `backend/matching_engine/rules.py` | The rule DSL interpreter (pass/fail/unknown + human sentences). |
| `backend/matching_engine/engine.py` | Match vs near-miss classification across the catalogue. |
| `backend/matching_engine/ranker.py` | V1 transparent ranking + badges + deadline math. |
| `backend/services/dataset.py` | Loads/validates schemes from `data/`, catalog stats. |
| `backend/services/matching.py` | Orchestrates engine+ranker into API payloads. |
| `backend/services/tracker.py` | Status pipeline (`saved→planning→applied→under_review→approved/rejected`), JSON-file persistence behind an interface (swap → Postgres later). |
| `backend/services/reminders.py` | Derives *actions* from deadlines + tracker state. |
| `backend/services/chat.py` | Reach-layer conversation state machine (3 questions → matches). |
| `backend/notifications` | Channel-agnostic dispatch (console + WhatsApp outbox now; Business API later). |

## Storage today vs production

Today: scheme catalogue in versioned JSON (it *is* the database — reviewed in
git, validated by pydantic + tests), tracker in a runtime JSON file.

Production: scheme catalogue moves to Postgres tables mirroring the same
pydantic shapes (`Scheme`, `Eligibility`, …); tracker swaps `TrackerStore`
for tables keyed by user id; chat sessions move to Redis. **The API and the
engine do not change.**

## V2/V3

* **V2 — outcome ranking:** `ml/ranking/outcome_ranker.py` (logistic model,
  trained on tracker events, feature-parity with the V1 signals).
  `ml/experiments/simulate_outcomes.py` demonstrates the training loop on
  synthetic data.
* **V3 — regional-language intelligence:** dictionaries already drive the web
  UI (`language/regional_support`); the same keys render chat answers, then
  rule-explanation templates (`rules.py` already renders from rule ids — the
  seam for per-language templates).

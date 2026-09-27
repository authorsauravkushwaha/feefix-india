# FeeFix API Reference

Base URL: `/api` (same origin as the web app). All bodies are JSON.

Interactive docs (Swagger): `GET /docs` when the server is running.

## Meta

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Liveness + loaded scheme count |
| GET | `/api/meta` | Enums: states, categories, course levels, genders, minority communities, tracker statuses |
| GET | `/api/stats` | Catalogue totals (schemes, verified count, benefit pool…) |
| GET | `/api/i18n/{lang}` | UI dictionary (`en`, `bn`, `hi`) |

## Schemes

```
GET /api/schemes?q=kanyashree&level=state|central&status=verified&fee_waiver=true
GET /api/schemes/{scheme_id}
```

```bash
curl 'http://localhost:8000/api/schemes?q=nsp&fee_waiver=false'
```

## Matching (the core)

`POST /api/match` accepts an optional `"lang": "bn" | "hi"` alongside `profile` —
`why_matched` / assumption details are then localized (Phase 4). The same `lang`
parameter works on `PUT /api/students/{sid}/profile` (body) and
`GET /api/match/{sid}?lang=`.

```
POST /api/match
{
  "lang": "en",
  "profile": {
    "domicile_state": "West Bengal",
    "category": "obc",
    "annual_family_income": 95000,
    "course_level": "ug",
    "gender": "female",
    "is_minority": false,
    "minority_community": null,
    "has_disability": false,
    "last_exam_percentage": 71,
    "is_single_girl_child": false
  }
}
```

Response — every match is explainable:

```jsonc
{
  "evaluated_schemes": 21,
  "match_count": 5,
  "open_match_count": 5,
  "total_indicative_annual_benefit_inr": 128500,
  "matches": [
    {
      "id": "aicte-pragati",
      "name": "AICTE Pragati Scholarship for Girls …",
      "score": 88.0,
      "badges": ["top_pick", "high_value", "all_india", "verified"],
      "deadline": { "date": "2026-10-31", "days_left": 34, "expired": false },
      "why_matched": [
        "Your family income (₹95,000) is within the ₹8,00,000 limit.",
        "Your category (OBC) is eligible.",
        "…"
      ],
      "assumptions": [],
      "benefit": { "amount_display": "₹50,000 / year", … },
      …
    }
  ],
  "near_misses": [
    {
      "id": "nsp-central-sector",
      "failed_rule": {
        "rule": "marks",
        "requirement": "At least 80% in the last qualifying exam",
        "detail": "Needs ≥80% in the last exam; you reported 71.0%."
      }
    }
  ]
}
```

`GET /api/match/{session_id}` — re-run with the session's saved profile.

## Profiles & tracker

```
PUT /api/students/{session_id}/profile   { "profile": {…} }   → saves + returns matches
GET /api/students/{session_id}/profile

PUT /api/tracker/{session_id}/{scheme_id}   { "status": "saved" | "planning" | "applied" |
                                              "under_review" | "approved" | "rejected" | null }
GET /api/tracker/{session_id}                                   → board with scheme payloads
```

Statuses are the full journey: `saved → planning → applied → under_review → approved | rejected`.

## Reminders

```
GET  /api/students/{session_id}/reminders
POST /api/students/{session_id}/reminders/dispatch   { "limit": 10 }
```

`GET` derives severe-first actions from deadlines × tracker state.
`POST dispatch` sends them through the notification router (console +
WhatsApp outbox at `runtime/whatsapp_outbox.jsonl`) — the reach-layer demo.

## AI — semantic search & grounded Q&A (free local models)

```
GET  /api/search/semantic?q=education%20loan&k=5
```
```jsonc
{ "query": "education loan", "backend": "ngram" | "neural",
  "hits": [ { "id": "bscc-bihar", "semantic_score": 0.32, … } ] }
```

```
POST /api/ask   { "question": "engineering scholarship for girls",
                  "session_id": null }           // optional → personalises answers
```
```jsonc
{
  "question": "…",
  "answer": "Based on your profile, you qualify for these:\n1. **AICTE Pragati…**",
  "mode": "profile" | "search",
  "backend": "ngram" | "neural",
  "citations": [ { "id": "aicte-pragati", "name": "…", "score": 74.5 } ],
  "detected_profile": { "gender": "female", "course_level": "ug" }   // extracted hints
}
```

**Grounding guarantee:** answers are assembled *only* from verified dataset
fields; every `**scheme name**` in an answer appears in `citations` (enforced
by tests). Profile-aware mode reranks matches by a 50/50 blend of rule-ranker
score and semantic similarity, and surfaces *near-miss radar* entries with
gap-coaching advice.

## Outcomes & ML ranking (Phase 3)

```
POST /api/events
{ "session_id": "uuid", "scheme_id": "aicte-pragati", "type": "applied" }
```

Outcome types: `viewed | applied | under_review | approved | rejected | missed`.
Events are appended to `runtime/outcomes.jsonl` with a snapshot of the V1 signals
that were on show (`clarity`, `urgency`, `benefit_norm`, `verified`) — those rows
become the V2 ranker's training data. 404 if the scheme doesn't exist, 422 on an
unknown event type.

```
GET /api/ml/rank/{session_id}
  → {
      "trained_on": 800,                # events the model trained on
      "bootstrap": true,                # true until ≥25 real outcome events exist
      "items": [
        { "scheme_id": "aicte-pragati",
          "v1_score": 88.0, "v1_rank": 1,
          "model_probability": 0.81,    # P(positive outcome) from the logistic model
          "v2_score": 0.86,             # 50/50 blend of normalized V1 + model
          "v2_rank": 1,
          "features": { "clarity": 1.0, "urgency": 0.6, "benefit_norm": 0.3, "verified": 1.0 } },
        …
      ]
    }
```

The web results view exposes this as the **⚡ ML preview** toggle: cards re-sort by
V2 rank and gain an ML-probability chip.

## Reach layer (WhatsApp-style chat)

```
POST /api/chat   { "message": "start", "chat_id": null }
POST /api/chat   { "message": "West Bengal", "chat_id": "ab12cd34ef56" }
POST /api/chat   { "message": "B.Tech",        "chat_id": "ab12cd34ef56" }
POST /api/chat   { "message": "₹2,00,000",     "chat_id": "ab12cd34ef56" }
```

Three questions → ranked matches with the same explanations. Natural parsing:
`"2 lakh"`, `"wb"`, `"class 12"` all understood — and so are Bengali/Hindi inputs:
`পশ্চিমবঙ্গ`, `बिहार`, `২ লাখ`, `৯০ হাজার`, `১.৫ লাখ`, `বি.টেক`, `कक्षा 12`.
The session language is detected per turn and **sticks** for the rest of the
conversation; questions, summaries and follow-ups come back in that language
(Phase 4). Sessions are in-memory keyed by `chat_id` (swap `_SESSIONS` for Redis
behind a load balancer).

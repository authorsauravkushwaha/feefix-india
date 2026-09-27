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

```
POST /api/match
{
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

## Reach layer (WhatsApp-style chat)

```
POST /api/chat   { "message": "start", "chat_id": null }
POST /api/chat   { "message": "West Bengal", "chat_id": "ab12cd34ef56" }
POST /api/chat   { "message": "B.Tech",        "chat_id": "ab12cd34ef56" }
POST /api/chat   { "message": "₹2,00,000",     "chat_id": "ab12cd34ef56" }
```

Three questions → ranked matches with the same explanations. Natural parsing:
`"2 lakh"`, `"wb"`, `"class 12"` all understood. Sessions are in-memory
keyed by `chat_id` (swap `_SESSIONS` for Redis behind a load balancer).

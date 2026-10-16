# FeeFix API Reference

Base URL: `/api` (same origin as the web app). All bodies are JSON.

Interactive docs (Swagger): `GET /docs` — **enabled by default**, together with
`/redoc` and the machine-readable `/openapi.json`. They are a client/QA contract,
not an attack surface: every route answers whether or not the docs are shown, so
`FEEFIX_DISABLE_DOCS=1` is a cosmetic switch and not a control.

Request-body caps are **per endpoint** and enforced while the body is read
(chunked requests included). A rejected body gets `413` with
`X-Max-Body-Bytes` and `{"limit_bytes": …, "scope": …}`:

| Route class | Cap (default) | Env knob |
|---|---|---|
| auth | 8 KB | `FEEFIX_MAX_AUTH_BODY_BYTES` |
| Q&A (`/api/ask`) | 32 KB | `FEEFIX_MAX_ASK_BODY_BYTES` |
| chat | 64 KB | `FEEFIX_MAX_CHAT_BODY_BYTES` |
| profiles / tracker / match | 64 KB | `FEEFIX_MAX_PROFILE_BODY_BYTES` |
| other JSON API | 256 KB | `FEEFIX_MAX_BODY_BYTES` |
| documents (upload) | file budget + framing | `FEEFIX_MAX_UPLOAD_BYTES` |

`GET /api/health` returns the effective values under `limits`.

## Meta

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Liveness + **effective configuration**: password scheme, rate-limit store (and whether it is shared), secret-policy status, body/field limits, document counts. Never rate-limited, never leaks secrets. |
| GET | `/api/meta` | Enums: states, categories, course levels, genders, minority communities, tracker statuses |
| GET | `/api/stats` | Catalogue totals (schemes, verified count, benefit pool…) |
| GET | `/api/i18n/{lang}` | UI dictionary (`en`, `bn`, `hi`, `ta`) |

## Schemes

```
GET /api/schemes?q=kanyashree&level=state|central&status=verified&fee_waiver=true
GET /api/schemes/{scheme_id}
```

```bash
curl 'http://localhost:8000/api/schemes?q=nsp&fee_waiver=false'
```

## Accounts & sessions (security layer)

All authenticated calls use `Authorization: Bearer <token>` (opaque, revocable,
server-side; only its SHA-256 hash is stored).

```
POST /api/auth/register   { "email": "a@b.in", "password": "min-8-chars", "name": null }
  → { "token": "…", "expires_at": "…", "user": {…}, "session_id": null }
POST /api/auth/login      { "email": "a@b.in", "password": "…" }
  → { "token", "expires_at", "user", "session_id": "<their last session or null>" }
POST /api/auth/logout                        (Bearer) → { "revoked": true }
GET  /api/auth/me                            (Bearer) → { "user": {…} }
POST /api/auth/link-session { "session_id": "wizard-uuid" }   (Bearer)
  → binds the anonymous wizard session to the account — after this, data follows
    the login on any device, and anonymous access to that session gets HTTP 403.
GET  /api/auth/export                        (Bearer) → full account data (portability)
DELETE /api/auth/account                     (Bearer) → erase account + all owned data + uploaded files
GET  /api/auth/security-events?limit=50      (Bearer) → session-security signals
  → replay/quarantine events for this account. A single `token_replay` is usually
    a stale tab: the stale token is revoked, the session survives, and the client
    (and the user) can see it. Sustained replays escalate to family revocation.
POST /api/auth/logout-all                    (Bearer) → sign out of every session
```

Errors: wrong password and unknown email return identical `401` bodies
(no account enumeration). Auth endpoints are rate-limited
(10 attempts / 5 min per IP+account → `429` with `Retry-After` and
`X-RateLimit-Scope: auth`). If the password-hashing pool is saturated (a bounded
resource, `FEEFIX_KDF_CONCURRENCY`), auth endpoints answer **`503` +
`Retry-After: 2`** — a retryable capacity signal, identical for known, unknown
and wrong-credential requests, and never a fake "invalid password". All `/api/*` responses carry
CSP/nosniff/no-store security headers. See `docs/security/SECURITY.md`.

## Documents (uploads)

Hardened, and **actually called** — the gate in `services/upload.py` plus the
store in `services/documents.py` are what these routes use, so the control is
live rather than aspirational. Files land outside the web root under a random
name; the original filename is metadata only.

```
POST   /api/students/{sid}/documents          (multipart: file, doc_type)
  → 201 { "uploaded": true, "document": { id, doc_type, filename, media_type,
                                           size_bytes, sha256, created_at,
                                           download_url } }
  → 422 for a dangerous extension, a content/type mismatch (renamed shell.php),
    an empty file or one over the size cap — with the reason in `detail`.
GET    /api/students/{sid}/documents          → metadata list
GET    /api/students/{sid}/documents/{id}     → the file itself, always as
                                                Content-Disposition: attachment
DELETE /api/students/{sid}/documents/{id}     → remove metadata + file
```

Ownership follows every other session-scoped resource: an account-bound session
requires its owner's bearer token (403 otherwise), and a foreign session's
document id is a 404. Deletes (document, or the whole account) remove the bytes
from disk.

## Matching (the core)

`POST /api/match` accepts an optional `"lang": "bn" | "hi" | "ta"` alongside `profile` —
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
`"2 lakh"`, `"wb"`, `"class 12"` all understood — and so are Bengali/Hindi/Tamil inputs:
`পশ্চিমবঙ্গ`, `बिहार`, `தமிழ்நாடு`, `২ লাখ`, `৯০ হাজার`, `2 லட்சம்`, `বি.টেক`, `कक्षा 12`.
The session language is detected per turn and **sticks** for the rest of the
conversation; questions, summaries and follow-ups come back in that language
(Phase 4). Sessions are in-memory keyed by `chat_id` (swap `_SESSIONS` for Redis
behind a load balancer).

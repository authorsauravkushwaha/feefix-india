# FeeFix API Reference

Base URL: `/api` (same origin as the web app). All bodies are JSON.

Interactive docs (Swagger): `GET /docs` when the server is running in a
non-production environment. **They return 404 in production** — publishing the
full API surface to the internet is fingerprinting fuel, and this reference is
the contract.

## Request contract

Every client must send these, on every request:

| Header | When | Rule |
|---|---|---|
| `Content-Type: application/json` | any request with a body | — |
| `X-FeeFix-Nonce` | **every non-idempotent request** (POST/PUT/PATCH/DELETE) | ≥128 bits, base64url or hex, ≤64 chars, **single use per client IP** |
| `X-FeeFix-Ts` | same | Unix seconds, within **±300 s** of server time |
| `Authorization: Bearer <token>` | authenticated calls | 32–128 chars, `[A-Za-z0-9_-]` |

Generate a nonce with a **cryptographic** RNG. `secrets.token_urlsafe(24)` in
Python, `crypto.getRandomValues` in the browser, `SecureRandom` on Android. A
predictable nonce is one an attacker can pre-register, which inverts the control.

`GET`, `HEAD` and `OPTIONS` are exempt — replaying a read gains nothing the
capture did not already contain.

### Status codes

| Code | Meaning | Retry? |
|---|---|---|
| `200` | Success | — |
| `401` | Missing, malformed, expired or revoked token | **No.** Re-authenticate. The web SPA treats 401 as "session ended" and logs out |
| `403` | Authenticated (or anonymous) but **not permitted** — see *Authorisation* below | **No.** Retrying will not change the answer |
| `404` | Unknown id, unknown session, or a disabled feature (incl. `/docs` in production) | No |
| `405` | Method not allowed. `TRACE` is refused everywhere: it reflects headers, including `Authorization`, into the response body | No |
| `409` | **Replay rejected** — reused nonce, timestamp outside the window, or missing headers | **Yes, once**, with a *fresh* nonce and timestamp. Both first-party clients do this automatically |
| `411` | `Transfer-Encoding: chunked` on `/api/*`. A chunked body declares no length, so the 256 KB ceiling cannot be checked up front. Send `Content-Length` | No |
| `413` | Body over **256 KB** | No |
| `414` | URL path over **2048 chars** | No |
| `422` | Validation failure. The response names the field; **it never echoes the rejected value** | No |
| `429` | Rate limit. Carries a `Retry-After` header in seconds | After `Retry-After` |
| `5xx` | Generic message only. Stack traces and exception class names are never returned | Yes |

### Limits

| Limit | Value |
|---|---|
| Request body | 256 KB |
| Request headers | 16 KB |
| Query string | 8 KB |
| URL path | 2048 chars |
| Email | 254 chars (local-part 64, domain 253) |
| Password | 8–128 chars |
| Session / scheme id | 64 chars, allow-listed shapes |
| Chat message | 2000 chars |
| Question | 1000 chars |
| Search query | 200 chars |
| List fields | 64 items |

Rate limits: **600 req/min/IP** globally, **8 auth attempts / 5 min** per
(IP, bucket) plus **32 / 5 min per IP** regardless of identifier, **20 password
hashes / min / IP**, **5 OTP requests / hour / destination**.

## Authorisation

**Authentication is not authorisation.** A valid token says who you are, not what
you may do. Session-scoped endpoints therefore decide per request:

| State of `session_id` | Anonymous caller | Owner | Another account |
|---|---|---|---|
| Never written to (or written anonymously) | **allowed** — this is the product's privacy-by-design anonymous flow | — | allowed |
| Owned by an account | **403** | allowed | **403** |

Ownership is **write-once**: it is stamped when an authenticated request writes
a profile or tracker row, and `POST /api/auth/link-session` on an already-owned
session is **refused** (audited as `session.claim_refused`). This exists because
a mutable owner made rebinding an account takeover — a stranger could bind
someone else's session, read their data, and lock them out of their own account.

The anonymous→linked flow is supported and tested: use FeeFix without an account,
then sign in and call `link-session` to keep your progress.

`POST /api/chat` is the same shape one level up. `chat_id` is 128-bit and
owner-bound; a different principal presenting the same id receives a **new**
conversation rather than a 403, so the endpoint cannot be used to enumerate
which ids exist.

## Meta

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Liveness + loaded scheme count |
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
  → binds an *unowned* anonymous session to the account — after this, data
    follows the login on any device. Refused with 403 if the session is already
    owned (ownership is write-once; see *Authorisation* above).
GET  /api/auth/export                        (Bearer) → full account data (portability)
DELETE /api/auth/account                     (Bearer) → erase account + all owned data
```

Errors: wrong password and unknown email return **identical `401` bodies**, and
login always runs the password KDF even for an unknown email, so response *time*
leaks nothing either. Auth endpoints are rate-limited (see *Limits* above). All
`/api/*` responses carry CSP/nosniff/no-store/COOP/CORP headers and
`Cache-Control: no-store`.

Session tokens have both an **idle expiry (30 days, rolling)** and an
**absolute expiry (90 days)** — a rolling window alone never expires for a token
used monthly, which turns a stolen token into permanent access. Changing a
password revokes every session. With `FEEFIX_BIND_CLIENT=1` a token replayed
from a different user agent is revoked immediately, legitimate session included.

See [`docs/security/SECURITY.md`](../security/SECURITY.md) for the threat model
and [`docs/security/HARDENING.md`](../security/HARDENING.md) for what was
actually exploitable and how it was fixed.

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

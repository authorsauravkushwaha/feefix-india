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

## Request pipeline — what runs before any handler

The order matters, because each layer exists so that a later, more expensive
layer cannot be reached by traffic the earlier one should have stopped.

```
                 ┌── request_shield.py — runs on EVERY path ─────────────┐
  HTTP request   │  1. method allow-list                 → 405          │
      │          │     (TRACE refused: it reflects Authorization)       │
      ▼          │  2. total header size     ≤16 KB      → 431          │
  peer address   │  3. path length          ≤2048        → 414          │
      │          │  4. NUL / CR / LF in path               → 400        │
      │          │     (smuggling + log injection)                      │
      │          │  ── non-/api paths stop here (static files) ──       │
      │          │  5. client_ip(): X-Forwarded-For honoured only from  │
      │          │     a trusted peer, FEEFIX_PROXY_HOPS from the right │
      │          │  6. query string          ≤8 KB       → 414          │
      │          │  7. ratelimit.check_global 600/min/IP → 429          │
      │          │  8. Content-Length       ≤256 KB      → 413          │
      │          │     — checked BEFORE the body is read                │
      │          │  9. Transfer-Encoding: chunked on /api/* → 411       │
      │          │     (no declared length ⇒ no ceiling to check)       │
      │          │ 10. anti_replay.check() on mutating    → 409         │
      │          │     routes: nonce single-use + ts ±300 s             │
      │          └───────────────────────────────────────────────────────┘
      ▼          ┌── schemas.py (Pydantic) ──────────────────────────────┐
  Routing        │ 11. field length ceilings               → 422        │
      │          └───────────────────────────────────────────────────────┘
      ▼          ┌── routes.py handler ──────────────────────────────────┐
  Response       │ 12. _guard_auth() — per-route budget    → 429        │
      │          │ 13. _charge_kdf() — 20 hashes/min/IP    → 429        │
      ▼          │ 14. input_guard.* — linear-time validation → 422     │
  secure_headers │ 15. authz.authorize_* — ownership       → 403        │
      │          │ 16. the actual work (KDF, matching, storage)         │
      ▼          └───────────────────────────────────────────────────────┘
  Client

  Errors pass through a shield that returns a generic message and writes the
  exception class to the audit log only — never to the response body.
  secure_headers.py then applies CSP/COOP/CORP/nosniff/no-store to the response.
```

Four ordering decisions worth stating explicitly, because each is load-bearing:

* **Framing before parsing.** A 40 MB body must be rejected without being read
  into memory, so the ceiling is checked against `Content-Length` in middleware
  rather than against the parsed object in a handler. Chunked requests declare
  no length, which is why they are refused outright (411) instead of streamed —
  and a `Content-Length` lie is closed by the same rule, since a body longer than
  its declared length is a protocol error the server rejects.
* **Rate limit before the rate-limitable work.** The global budget is charged in
  middleware, before body parsing, so the cheapest possible rejection happens
  first. The auth and KDF budgets are charged *inside* the handler but *before*
  the KDF runs — registration is the cheapest way for an attacker to buy
  600 000 rounds of SHA-256 per request.
* **Authorisation before storage.** `authz.authorize_*` is called before any
  read or write touches the store, so a refused request performs no work on
  data it was not allowed to see.
* **Ownership is stamped on write, not only on bind.** An authenticated write
  that leaves `user_id` NULL makes that session look anonymous — and therefore
  claimable by anyone. Both paths stamp it.

## Service responsibilities

| Module | Responsibility |
|---|---|
| `backend/models` | Pydantic models. Data validity is a compile-time error, not a runtime surprise. |
| `backend/matching_engine/rules.py` | The rule DSL interpreter (pass/fail/unknown + human sentences). |
| `backend/matching_engine/engine.py` | Match vs near-miss classification across the catalogue. |
| `backend/matching_engine/ranker.py` | V1 transparent ranking + badges + deadline math. |
| `backend/services/dataset.py` | Loads/validates schemes from `data/`, catalog stats. |
| `backend/services/matching.py` | Orchestrates engine+ranker into API payloads. |
| `backend/services/tracker.py` + `sqlite_store.py` | Status pipeline (`saved→planning→applied→under_review→approved/rejected`). Default store is **SQLite (WAL)** with **write-once** session↔account ownership binding; `FEEFIX_STORE=json` keeps the legacy JSON store. |
| `backend/services/db.py` | Database engine + versioned migrations + audit log (WAL, FK on, busy-timeout; parameterized only). |
| `backend/services/auth.py` | Accounts: PBKDF2-SHA256 (600k) password hashing, opaque hashed session tokens with idle **and** absolute expiry, optional client binding, register/login/link/erase. |
| **`backend/services/security.py`** | The security kernel: environment inference (**unset ⇒ production**), all hard ceilings in one `LIMITS` object, trusted-network parsing and `client_ip()`, secret loading (0600, length-checked), audit writing, and the text helpers that strip control/bidi characters and scrub credentials. Everything else imports from here. |
| **`backend/services/input_guard.py`** | Linear-time validation and normalisation — email, phone, ids, filenames, bearer tokens, nonces. Length is rejected before pattern matching, because length is the cheapest possible rejection and the shipped email regex was quadratic. |
| **`backend/services/authz.py`** | Authorisation as a separate question from authentication: `owner_of`, `authorize_session`, `authorize_bind`, `authorize_chat`. Ownership is **write-once**; a refusal is audited. Every session-scoped handler calls this. |
| **`backend/services/anti_replay.py`** | Nonce + timestamp verification on mutations, per-IP bounded nonce store, `enforce`/`optional`/`off` modes with `off` refused in production. |
| **`backend/services/request_shield.py`** | The middleware that enforces request framing: body/header/query/path ceilings, `411` on chunked, and the global per-IP budget — before any handler runs. |
| **`backend/services/uploads.py`** | Upload verification ahead of the feature: magic-byte sniffing, MIME-mismatch and forbidden-content rejection, dimension caps, digest-named storage, path-escape proof. |
| `backend/services/ratelimit.py` + `secure_headers.py` | Sliding-window rate limits (global, auth, per-IP, **KDF**, OTP-destination) with an insertion-path bound on the bucket map, and CSP/HSTS/nosniff/no-store/COOP/CORP transport hardening. |
| `backend/services/reminders.py` | Derives *actions* from deadlines + tracker state. |
| `backend/services/chat.py` + `chat_i18n.py` | Reach-layer conversation state machine (3 questions → matches → free-text Q&A), multilingual: Bengali/Hindi script detection, native-digit/state/course parsing, localized conversation strings that stick per session. |
| `backend/services/i18n_rules.py` + `language/regional_support/explanations/` | Rule-explanation renderer: every rule result carries `{rule, status, params}`; templates per language produce localized `why_matched` / assumption / blocker sentences. |
| `backend/services/events.py` | Outcome-event collector (`runtime/outcomes.jsonl`) — the V2 ranker's training feed. |
| `ml/ranking/service.py` | V1↔V2 compare service: trains the logistic model on recorded events (synthetic bootstrap < 25 real events) and re-ranks a session's matches with probabilities + V1/V2 rank deltas. |
| `backend/notifications` | Channel-agnostic dispatch (console + WhatsApp outbox now; Business API later). |
| `ai/` | Free-local AI: lexical layer, two embedding backends (neural `fastembed` or built-in n-gram), semantic search, grounded Q&A + near-miss radar. **No paid APIs, ever.** |
| `agents/` | Deterministic automations: dataset verification (CI gate) + reminder scheduler (cron). |

## Storage today vs production

Today: scheme catalogue in versioned JSON (it *is* the product database —
reviewed in git, validated by pydantic + tests). Runtime state (accounts,
sessions, profiles, tracker, outcome events, audit log) lives in **SQLite WAL**
(`runtime/feefix.db`), behind the same store contract as the legacy JSON files
(auto-imported on first boot).

Production: scheme catalogue moves to Postgres tables mirroring the same
pydantic shapes (`Scheme`, `Eligibility`, …); runtime stores swap their
connection target (same SQL-shaped contract — see
`docs/deploy/DEPLOYMENT.md`); chat sessions move to Redis. **The API and the
engine do not change.**

## V2/V3 — shipped

* **V2 — outcome ranking (shipped):** `ml/ranking/` trains the logistic model on
  recorded outcome events (`POST /api/events` → `runtime/outcomes.jsonl`;
  synthetic bootstrap while < 25 real events) and serves the live comparison at
  `GET /api/ml/rank/{session_id}` — V1 score/rank vs model probability and the
  blended V2 rank. Feature-parity with the V1 signals; no invented facts.
  `ml/experiments/simulate_outcomes.py` demonstrates the loop offline.
* **V3 — regional-language intelligence (shipped):** UI dictionaries already
  drive the web UI; `chat_i18n.py` gives the reach layer full Bengali/Hindi
  conversations with native-script parsing, and `i18n_rules.py` + the
  `language/regional_support/explanations/` templates localize every match
  explanation (`match_profile(..., lang=)` → `POST /api/match` `lang`).
* **V4 — state expansion (shipped):** seven states roll on the same engine —
  West Bengal, Bihar, Odisha, Uttar Pradesh, Maharashtra, Jharkhand,
  Tamil Nadu (55 schemes). Chat parses every state's Bengali/Hindi name.
* **Next:** richer regional language coverage (te/ta/mr) is a matter of adding
  template files, no engine changes; more states follow the same dataset shape.

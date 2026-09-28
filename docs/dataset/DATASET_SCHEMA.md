# FeeFix Dataset Schema

One record per scheme, validated by `backend/models/scheme.py` (pydantic) and
enforced in CI by `tests/test_dataset.py`.

## Top-level fields

| Field | Type | Notes |
|---|---|---|
| `id` | slug | Unique across files. `^[a-z0-9][a-z0-9-]*$` |
| `name` | string | Official scheme name (short alias in parentheses) |
| `provider` | string | Ministry / department / corporation |
| `level` | `state` \| `central` | `state` ⇒ usually has `domicile_states` |
| `summary` | string | 1–2 sentences, student-first |
| `benefit` | object | see below |
| `deadline` | object | `date` XOR `rolling` required |
| `eligibility` | object | **machine-evaluable rules** (see DSL doc) |
| `documents` | list[string] | Required documents |
| `application` | object | `mode`, `portal`, `url`, ordered `steps` |
| `official_url` | url | Canonical official source |
| `last_verified` | date | When a curator last checked |
| `verification_status` | `verified` \| `pending_review` \| `stale` | See manifest policy |
| `tags` | list[string] | Search aids |
| `notes` | string | Curation caveats (indicative amounts, shifting deadlines…) |

### `benefit`

```jsonc
{
  "type": "scholarship" | "fee_waiver" | "grant",
  "amount_annual_inr": 50000,            // representative annual value
  "amount_display": "₹12,000 – ₹60,000 / year",  // shown to students
  "details": "How the money is paid"
}
```

`amount_annual_inr` feeds ranking and the "indicative pool" totals; the
manifest disclaimer states all amounts are indicative.

### `deadline`

```jsonc
{ "date": "2026-11-30", "rolling": false, "label": "2026–27 cycle" }
{ "date": null, "rolling": true, "label": "Rolling — apply any time" }
```

The engine computes `days_left` per student per day; rolling schemes get a
flat urgency and never expire.

### `eligibility` (rule DSL → `matching_engine/rules.py`)

See `data/eligibility_rules/README.md` for per-field semantics: domicile,
category, income cap, gender, minority, disability, course level, marks
cut-off, single-girl-child. `special_conditions` is the escape hatch for
conditions no machine can check — displayed, never scored.

## Verification workflow

1. Curator updates/adds a record against the official portal.
2. `last_verified` is set to today; `verification_status` to `verified`.
3. Entry logged in `data/verification/manifest.json` (id + source + date).
4. `pytest tests/test_dataset.py` must pass: ids unique, URLs https,
   documents & steps present, manifest covers every scheme.
5. The `stale` status is assigned when the record surpasses the review cycle
   (30 days) without a re-check.

## Phase 1 scope

* **21 schemes**: 9 West Bengal (SVMCM, Kanyashree, Aikyashree, OASIS ×3,
  Nabanna, WB Freeship, Hindi Scholarship) + 12 central (NSP family, UGC,
  AICTE, DST INSPIRE, NMMS).
* Expansion to new states = a new `data/schemes/<state>.json` following this
  schema — the engine needs no code changes.

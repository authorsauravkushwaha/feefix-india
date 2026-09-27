# FeeFix Eligibility Rules DSL

Eligibility is never free text. Each scheme in `data/schemes/*.json` carries a
machine-evaluable `eligibility` block interpreted by the engine
(`backend/matching_engine/rules.py`). The engine compiles it into **rules**,
each producing `pass` / `fail` / `unknown`.

| Field | Type | Rule behaviour |
|-------|------|----------------|
| `domicile_states` | `list[str] \| null` | `null` → open to all India. Otherwise the student's `domicile_state` must be in the list. |
| `categories` | `list[category] \| null` | Student's reservation category must be listed (`general`, `sc`, `st`, `obc`; `obc-a`/`obc-b` normalise to `obc`). |
| `max_family_income` | `int(INR) \| null` | Student's `annual_family_income` must be ≤ cap. `null` profile income ⇒ `unknown`. |
| `genders` | `list[gender] \| null` | Restrictive only when not all genders are listed. `prefer_not_to_say` ⇒ `unknown` on restricted schemes. |
| `minority_only` | `bool` | When `true`, `is_minority` must be true; if `minority_communities` is set and a community is named, it must be in the list. |
| `disability_required` | `bool` | When `true`, `has_disability` must be true (benchmark disability ≥40%). |
| `course_levels` | `list[level] \| null` | `school`, `higher_secondary`, `iti`, `diploma`, `ug`, `pg`, `phd`. Student's level must be listed. |
| `min_marks_percent` | `float \| null` | Student's `last_exam_percentage` ≥ cut-off. Unknown marks ⇒ `unknown` (assumption flagged). |
| `single_girl_child_required` | `bool` | Requires `is_single_girl_child && gender == female`. |
| `special_conditions` | `list[str]` | **Informational only** — displayed to the student, never machine-checked. Use for conditions the DSL can't express (e.g. "institution must be on the notified list"). |

## Verdict semantics

* A scheme is a **match** when *no rule fails*.
* `unknown` rules do not block a match — they become **assumptions** and
  lower the *clarity score* (share of confirmed rules).
* Exactly **one failing rule** ⇒ **near miss**, surfaced as
  "you are one requirement away from this scheme".

## Adding a scheme

1. Add a record to `data/schemes/west_bengal.json` (or `national.json`).
2. Run `pytest tests/test_dataset.py` — it validates ids, enums, dates,
   URLs and verification metadata for every record.
3. Log the verification in `data/verification/manifest.json`.

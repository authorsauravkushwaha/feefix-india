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
2. `last_verified` is set to today; `verification_status` reflects what the
   source actually established (see *Confidence* below — it is **not**
   automatically `verified`).
3. Entry logged in `data/verification/manifest.json` (id + source + date).
4. `pytest tests/test_dataset.py` must pass: ids unique, URLs https,
   documents & steps present, manifest covers every scheme, and every scheme
   has either a `deadline.date` or `rolling: true`.
5. `python -m agents.verify_dataset` must run clean of **errors**. It prints the
   verified/pending split and every finding; the full list lands in
   `runtime/verification_report.json`.
6. The `stale` status is assigned when a `verified` record surpasses the review
   cycle (30 days) without a re-check.

### Confidence — what each status actually claims

A status is a promise to the student, so it is defined narrowly:

| Status | The claim | When to use it |
|---|---|---|
| `verified` | A **recent, scheme-specific official source** confirms the current deadline, portal and eligibility | You opened the department's own page or notification, or a same-week report quoting it |
| `pending_review` | The record exists but is **not currently confirmed** | Sources conflict; the department has published nothing for the current cycle; the date is carried forward from last year; the portal could not be reached |
| `stale` | It *was* verified and has **aged out** of the 30-day cycle | Assigned by the agent, not by hand |

**Never upgrade a record to `verified` on the strength of an aggregator
repeating another aggregator.** Scholarship aggregator sites copy each other
extensively, and three sites agreeing on a date is frequently one source counted
three times. During the 2026-10-15 audit this was the difference between
"confirmed" and "carried forward" on roughly a third of the state records.

### Deadline policy — a past date is recorded, not guessed

When an annual window has already closed, the dataset records the **real, past
date** rather than inventing the next cycle's:

```jsonc
{ "date": "2026-09-30", "rolling": false,
  "label": "MahaDBT 2026–27 CLOSED on 30 Sep 2026 (window was 1 Jun – 30 Sep)" }
```

`agents/verify_dataset.py` then reports it as `window_closed` (within the
120-day grace period) or `deadline_stale` (beyond it). That is the system
working as designed: the record surfaces for re-verification when the next cycle
opens.

The reasoning is about harm, not tidiness. An honest past date tells a student
*"this closed, prepare for next June"*. An invented future date sends them to a
form that does not exist, after they have paid for an income certificate and a
caste validity certificate and waited three weeks for a bank to seed their
Aadhaar. **A confident wrong date is worse than an honest "we don't know"** —
which is why `pending_review` exists and why the agent counts it out loud.

### Portals move — re-check the URL, not just the date

Four state portals changed domain between the previous audit and this one. A
record can be `verified` on its deadline and still send a student to a dead URL,
so both are checked together:

| Scheme group | Was | Now |
|---|---|---|
| Maharashtra (MahaDBT, 6 records) | `mahadbt.maharashtra.gov.in` | `mahadbt2.maharashtra.gov.in` (MahaDBT 2.0) |
| West Bengal OASIS (3 records) | `oasis.gov.in` | `oasis.wb.gov.in` |
| West Bengal Aikyashree | `wbmdfcscholarship.gov.in` | `nspwb.wbmdfc.org` |
| West Bengal SVMCM | `svmcm.wb.gov.in` | `svmcm.wbhed.gov.in` |
| West Bengal Nabanna | `wbcmo.gov.in` | `cmrf.wb.gov.in` |
| Tamil Nadu (5 records) | `tnscholarships.tn.gov.in` | `umis.tn.gov.in` (Unified State Scholarship Portal) |
| Bihar SC/ST | `pmsonline.bih.nic.in` | `scstpmsonline.bihar.gov.in` |
| Bihar BC/EBC | `pmsonline.bih.nic.in` | `pmsonline.bihar.gov.in` |
| Ishan Uday | `www.ugc.gov.in` | `scholarships.gov.in` (UGC does not take the application) |

When a portal moves, record the **old URL in `notes`** — students arrive with
bookmarks and search results, and "that address is not the portal any more" is
itself useful information.

## Manifest

`data/verification/manifest.json` is the audit trail. `tests/test_dataset.py`
asserts its `records[]` set is **exactly** the set of scheme ids — a record
without a manifest entry, or a manifest entry without a record, fails CI.

```jsonc
{
  "dataset_version": "1.1.0",        // semver: minor = records added/removed/corrected
  "generated_at": "2026-10-15",
  "policy": {
    "review_cycle_days": 30,
    "statuses": { /* human-readable meaning of each status */ },
    "amounts_disclaimer": "…",
    "source_ledger": {               // WHERE each file's facts came from, per state
      "national": "Official NSP portal announcements + official UGC NSPGS FAQ PDF …",
      "maharashtra": "careers360.com (2026-10-01) + buddy4study.com (2026-06-23): …"
    },
    "deadline_policy": "…",          // past dates are recorded, not guessed
    "confidence_policy": "…"         // what may be called `verified`
  },
  "records": [
    { "scheme_id": "…", "verified_by": "curator",
      "verified_on": "2026-10-15", "source": "https://…" }
  ],
  "retired": [                       // removed records and WHY
    { "scheme_id": "ugc-pg-single-girl-child", "retired_on": "2026-10-15",
      "reason": "Merged into NSPGS per UGC's own FAQ …",
      "superseded_by": "ugc-nspgs", "source": "https://scholarships.gov.in/public/FAQ/FAQ_NSPG.pdf" }
  ]
}
```

The `source_ledger` exists so a reviewer can check any single claim without
re-reading a script or a pull-request description. The `retired` list exists so
that deleting a scheme is a **recorded decision with a reason**, not a silent
disappearance — six months later, "why isn't the single-girl-child scholarship
in here?" should be answerable from the file.

## Retirement

A record is removed when the scheme has genuinely ended or been merged, and the
removal is written to `retired[]` with a reason, a source, and — where one
exists — `superseded_by`. Removing a record requires three coordinated edits, or
CI fails:

1. delete it from `data/schemes/<file>.json`;
2. remove its `records[]` entry and add a `retired[]` entry in the manifest;
3. check nothing else references the id (`grep -rn "<id>" tests/ docs/ data/`).

**Do not retire a scheme merely because its window closed.** Annual cycles are
not closures; that is what `window_closed` and the next-cycle note are for.

## Current scope

**75 records** across 11 files — 10 state files (West Bengal 9, Bihar 6,
Maharashtra 6, Odisha 6, Uttar Pradesh 6, Assam 5, Jharkhand 5, Karnataka 5,
Kerala 5, Tamil Nadu 5) plus `national.json` (17 central schemes including
NER-wide Ishan Uday).

Expansion to a new state = a new `data/schemes/<state>.json` following this
schema — the engine needs no code changes.

## Audit 2026-10-15

Full re-verification of all 75 records against official sources. Reproduced by
`scripts/refresh_national_2026.py` and `scripts/refresh_states_2026.py`, which
are kept in the tree because the sourcing rationale in their headers is part of
the record.

**Central (17 records).** Verified directly against `scholarships.gov.in`,
including its Announcements page and the official UGC NSPGS FAQ PDF.

* **3 removed**: `ugc-pg-single-girl-child` and `ugc-pg-merit-rank-holders` were
  **merged** into the National Scholarship for Post Graduate Studies — UGC's own
  FAQ on the NSP portal names all four predecessor schemes. `inspire-she` was
  removed because no application window has been open since October 2024 and DST
  told the Rajya Sabha on 13 August 2026 that the scheme is under *redesign*;
  the dataset had been showing a deadline of **2026-10-15**, i.e. telling
  students to apply today for a scheme with no form.
* **7 added**: `ugc-nspgs`, `pm-yasasvi-top-class-college`, `aicte-swanath`,
  `pm-usp-special-scholarship-jkl`, `nfshe-st`, `free-coaching-sc-obc`,
  `top-class-education-disabilities`.
* **`nmms-central` corrected from 2026-12-15 to 2026-10-31.** The old date
  conflated the state NMMS *selection exam* (Class VIII, held Nov–Dec by each
  SCERT) with the *scholarship application* window on NSP. The Ministry extended
  the application twice — 31 Aug → 30 Sep → 31 Oct 2026.
* **Two AY 2026–27 rule changes** applied across the catalogue, both from the
  official NSP Announcements page:
  * a student may now hold **one merit-based + one or more welfare-based**
    schemes, replacing the old "one scholarship only" restriction. Records still
    carrying the old text were actively costing students a second award they are
    entitled to;
  * **UDID portal registration and consent is mandatory** for every
    disability-linked NSP scheme — without it the application cannot be
    submitted at all.
* **`nsp-central-sector` (PM-USP CSSS) and `pm-usp-special-scholarship-jkl`
  are RENEWAL ONLY** for 2026–27 — the NSP announcement names both
  explicitly. A first-year student reading "open" here would have prepared
  a full application for a window that does not exist for them.

**States (58 records, 51 changed).**

* **6 windows found already closed** that the dataset showed as open:
  Maharashtra (30 Sep), Assam SC/OBC (30 Sep), Bihar (30 Sep), Odisha
  post-matric (29 Sep), Karnataka Backward Classes (30 Sep), Uttar Pradesh
  pre-matric (21 Sep).
* **Uttar Pradesh** runs two different post-matric windows in the same year —
  Class 11–12 closed 21 Sep, while Dashmottar (UG/PG/Diploma/ITI) runs to
  31 Oct 2026. One date for both was wrong for one of them.
* **Karnataka** likewise: Social Welfare (SC/ST) runs to 31 Jan 2027 while
  Backward Classes/Tribal/Minorities closed 30 Sep 2026.
* **Jharkhand** e-Kalyan confirmed at 20 Nov 2026, with a new NSP OTR
  prerequisite and an institute-registration deadline (25 Sep) that silently
  blocks any student whose college missed it.
* **Bihar** split into two portals by category, with new prerequisites: NSP OTR,
  income certificate dated on/after 1 Apr 2026, mandatory Aadhaar-bank seeding,
  and a maximum of three defect corrections at 15 days each.
* **Kerala** `kerala-egrantz-scst` and **Odisha** `banishree-od` were recorded as
  `rolling`; both are annual windows (30 Nov 2026). "Rolling" told a student
  there was no deadline when there was one.
* **West Bengal** `kanyashree-k2` was likewise `rolling` but closes 31 Dec 2026
  and does not accept late submissions. `nabanna-wb` is genuinely rolling —
  `cmrf.wb.gov.in` publishes no fixed date and gives 90 days from registration.
* **25 records downgraded to `pending_review`** rather than given a confident
  date: sources conflicted (Tamil Nadu's 30 Nov vs "not yet notified"), the
  department published nothing for 2026–27 (e-Medhabruti, KMDC Arivu, Karnataka
  prize money and labour welfare), or the portal itself could not be confirmed
  (`kswcfc.org` resolves but renders placeholder content).

**Agent fix.** `verify_dataset.py` previously raised `review_due` only when
`verification_status == "verified"`, so `pending_review` and `stale` records —
the ones that most need attention — were invisible, and a run could print
"✓ dataset healthy" with a third of the catalogue unconfirmed. It now flags
both, reports `window_closed` for recently-passed deadlines, and prints the
status breakdown on every run.

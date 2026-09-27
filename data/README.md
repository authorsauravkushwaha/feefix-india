# FeeFix Data Layer

Scholarship information is treated as **structured, versioned, verified data** —
never as copied prose or PDFs. This directory is the single source of truth for
the matching engine, the API, the website, the app and the reach layer.

```
data/
├── schemes/            # Scheme records (one JSON array per coverage area)
│   ├── west_bengal.json   # Phase 1 focus: verified WB dataset
│   └── national.json      # Central / All-India schemes (NSP, UGC, AICTE, DST…)
├── eligibility_rules/  # The rule DSL documentation (README)
└── verification/       # Verification manifest — who checked what, when, where
```

## Guarantees the dataset must keep

* Every scheme validates against `backend/models/scheme.py` (`pydantic`).
* Every scheme has an official source URL, a verification date and a
  verification status (`verified` | `pending_review` | `stale`).
* Eligibility is expressed in the rule DSL only — see
  `data/eligibility_rules/README.md`.
* Amounts are indicative and carry the disclaimer in
  `data/verification/manifest.json`.

`tests/test_dataset.py` enforces all of the above in CI.

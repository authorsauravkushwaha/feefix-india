# Contributing to FeeFix India

Thanks for helping students find funding. This project intentionally stays
**simple to contribute to and free to run** — no paid APIs, no build steps,
no cloud accounts.

## The highest-value contribution: a new state dataset

Adding a state is a **data contribution**, not a code one — the engine,
ranker, chat and AI pick it up automatically.

1. Create `data/schemes/<state>.json` — copy the shape of any existing file.
2. Fill every field honestly; **include `official_url`, `last_verified`,
   `verification_status` and `notes`** for anything that shifts between cycles.
3. Add each scheme to `data/verification/manifest.json`.
4. Add the state to the assertion in `tests/test_dataset.py
   ::test_phase_states_present` and (ideally) one profile scenario test.
5. Run the gates:

```bash
./scripts/dev.sh --test
.venv/bin/python -m agents.verify_dataset   # must print ✓ dataset healthy
```

### Data rules (these are enforced in CI)

* HTTPS official URLs only.
* `deadline` is a concrete date **or** `rolling: true` — never both ambiguous.
* Benefit needs a numeric `amount_annual_inr` (indicative is fine; say so in
  `notes`) plus a human `amount_display`.
* Machine-checkable rules go in `eligibility`; real-world nuance goes in
  `special_conditions` (the AI cites these in answers).
* When in doubt, mark `"verification_status": "pending_review"` — accuracy
  beats confidence.

## Code contributions

* Python 3.11+, FastAPI, pydantic; the engine stays dependency-light.
* **The AI policy (`ai/README.md`) is non-negotiable**: free, local,
  open-weight/zero-dependency models only — never a paid API.
* Security: constant-time comparisons, parameterized SQL only, no secrets in
  code. Read `docs/security/SECURITY.md` first for auth-layer changes.
* Add/adjust tests for anything you change (`./scripts/dev.sh --test`).

## Workflow

1. Fork / branch from `main`.
2. Keep PRs focused (one state, one feature, one fix).
3. CI must be green: the Python suite (incl. property-based and a multi-process
   rate-limiter run), the API fuzz job, the dependency audit, the clipboard
   behaviour tests, the secret scan (working tree **and** history, with a wiring
   self-check), the dataset agent, ML sanity and the scheduler dry-run.
4. If your change alters behaviour that a document describes, update that
   document in the same PR — `tests/test_wiring_and_claims.py` fails when
   documentation and code drift apart (they have drifted before, which is why
   the check exists).
5. Screenshots in the PR for UI changes.

## Useful commands

```bash
./scripts/dev.sh                                 # run the app on :8000
./scripts/dev.sh --test                          # the full Python suite
node --test "web/tests/*.test.mjs"                # frontend behaviour tests
.venv/bin/python -m scripts.fuzz_api --requests 500 --seed 1   # randomised API probing
.venv/bin/python -m agents.secret_scan --history --check-ci    # secrets + CI wiring
.venv/bin/python -m agents.verify_dataset        # data audit
.venv/bin/python -m agents.reminder_scheduler --dry-run
.venv/bin/python -m ml.experiments.simulate_outcomes
```

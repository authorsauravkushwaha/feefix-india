# ML Ranking Experiments

Phase 3 of the FeeFix roadmap: rank with learned evidence, not hand-tuned rules.

## The transition contract

| V1 (today) | V2 (this module) |
|---|---|
| Fixed weights: `45·clarity + urgency + benefit + verified` | Logistic model learns weights from real outcomes |
| Deterministic order | Probability-trained order, over identical signals |
| Explainable by construction | Still explainable — the inputs never change |

`matching_engine/ranker.py` defines the four signals (+ interaction terms).
`ml/ranking/outcome_ranker.py` trains on labelled events streamed from the
application tracker:

```
applied → approved        +1.00
applied → (submitted)     +0.65
matched → window closed   +0.15   (decayed)
applied → rejected        +0.00
```

## Running the synthetic experiment

```bash
.venv/bin/python -m ml.experiments.simulate_outcomes
```

It synthesises 2,000 outcomes, trains the ranker, and verifies that
approvals score higher than misses. When production outcome data exists,
exchange ``synthesize()`` for the tracker export — the rest is identical.

## What's deliberately NOT here

* No opaque embeddings / two-tower models — until far more data exists, a
  transparent logistic model over explainable signals out-performs in trust,
  debuggability and (at this volume) accuracy.
* No scraping or demographic inference beyond what students themselves tell us.

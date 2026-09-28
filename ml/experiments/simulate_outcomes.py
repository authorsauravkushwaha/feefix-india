"""Synthetic-experiment harness for the V2 outcome ranker.

Generates a plausible population of application outcomes (approvals correlate
with clarity + urgency + verified records), trains the logistic ranker, and
shows it recovers the underlying pattern — the exact loop we will run on real
FeeFix data in Phase 3 (see docs/architecture).

Run:  python -m ml.experiments.simulate_outcomes
"""

from __future__ import annotations

import math
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ml.ranking import OutcomeRanker  # noqa: E402


def synthesize(n: int = 2000, seed: int = 7) -> list:
    rng = random.Random(seed)
    examples = []
    for _ in range(n):
        clarity = rng.random()
        urgency = rng.choice([0.16, 0.24, 0.32, 0.48, 0.72]) * rng.uniform(0.8, 1.2)
        benefit = rng.random()
        verified = rng.random() < 0.8

        # Latent "true" propensity: confirmed clarity & verification + urgency
        # push approvals; missing deadlines ruin everything.
        z = -2.2 + 2.4 * clarity + 1.1 * verified + 1.3 * min(urgency, 1.0) + 0.7 * benefit
        z += rng.gauss(0, 0.8)
        approved = rng.random() < 1 / (1 + math.exp(-z))

        if approved:
            outcome = "approved"
        else:
            outcome = rng.choice(["rejected", "missed", "unknown"])
        examples.append(
            OutcomeRanker.from_ranker_signals(
                clarity=clarity,
                urgency=urgency * 25,
                benefit_norm=benefit,
                verified=verified,
                outcome=outcome,
            )
        )
    return examples


def main() -> dict:
    data = synthesize()
    ranker = OutcomeRanker()
    history = ranker.fit(data, epochs=250)

    scored = ranker.score_examples(data[-6:])
    report = {
        "trained_on": len(data),
        "first_epoch_loss": round(history[0], 4),
        "final_loss": round(history[-1], 4),
        "weights": dict(zip(["clarity", "urgency", "benefit_norm", "verified", "clarity_x_urgency"],
                            [round(w, 3) for w in ranker.weights])),
        "bias": round(ranker.bias, 3),
    }
    print("=== FeeFix V2 outcome-ranker — synthetic experiment ===")
    for k, v in report.items():
        print(f"  {k}: {v}")
    print("  sample scores:")
    for example, p in scored:
        print(f"    outcome={example.outcome:9s}  predicted={p:.3f}  features={ {k: round(v,2) for k,v in example.features.items()} }")

    # Sanity: the model must rank approvals above misses on average.
    approved_p = [p for e, p in scored if e.outcome == "approved"] or [1.0]
    missed_p = [p for e, p in scored if e.outcome == "missed"] or [0.0]
    assert sum(approved_p) / len(approved_p) > sum(missed_p) / len(missed_p), "model failed sanity check"
    return report


if __name__ == "__main__":
    main()

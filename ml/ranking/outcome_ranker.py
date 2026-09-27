"""V2 — outcome-based ranking (the future ML layer of FeeFix).

V1 ranks rules with hand-tuned weights. Once real application outcomes
accumulate, *the same signals* become features of a logistic model trained on::

    applied → approved      (positive)
    applied → rejected      (negative)
    saved → window closed   (negative, "decayed")
    matched → applied       (soft positive)

This keeps the product contract identical — transparent signals, never a
black box — but lets evidence, not intuition, set the weights. The scorer in
``matching_engine/ranker.py`` documents the exact signal set; this module
learns over it.

No external ML dependencies: gradient descent in pure Python keeps the V2
prototype runnable anywhere (decision documented in docs/architecture).
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

FEATURES = [
    "clarity",          # share of confirmed rules (0..1)
    "urgency",          # deadline pressure score (0..25, scaled /25)
    "benefit_norm",     # benefit relative to catalogue max (0..1)
    "verified",         # 1.0 when the record is verified
    "clarity_x_urgency" # interaction: confirmed AND urgent matters most
]

LABELS = {"approved": 1.0, "applied": 0.65, "unknown": 0.5, "missed": 0.15, "rejected": 0.0}


@dataclass
class TrainingExample:
    features: dict[str, float]
    outcome: str  # key of LABELS


@dataclass
class OutcomeRanker:
    """Logistic model over the V1 ranker signals."""

    weights: list[float] = field(default_factory=lambda: [0.0] * len(FEATURES))
    bias: float = 0.0
    trained: bool = False

    # -- featurisation -----------------------------------------------------
    @staticmethod
    def vectorise(features: dict[str, float]) -> list[float]:
        return [features.get(f, 0.0) for f in FEATURES]

    @classmethod
    def from_ranker_signals(
        cls, clarity: float, urgency: float, benefit_norm: float, verified: bool, outcome: str
    ) -> "TrainingExample":
        u = urgency / 25.0
        return TrainingExample(
            features={
                "clarity": clarity,
                "urgency": u,
                "benefit_norm": benefit_norm,
                "verified": 1.0 if verified else 0.0,
                "clarity_x_urgency": clarity * u,
            },
            outcome=outcome,
        )

    # -- model --------------------------------------------------------------
    def _probability(self, x: list[float]) -> float:
        z = self.bias + sum(w * v for w, v in zip(self.weights, x))
        z = max(-30.0, min(30.0, z))
        return 1.0 / (1.0 + math.exp(-z))

    # -- training -----------------------------------------------------------
    def fit(
        self, examples: list[TrainingExample], epochs: int = 400, lr: float = 0.6
    ) -> list[float]:
        data = [(self.vectorise(e.features), LABELS.get(e.outcome, 0.5)) for e in examples]
        history = []
        rng = random.Random(42)
        for _ in range(epochs):
            rng.shuffle(data)
            grad_w = [0.0] * len(self.weights)
            grad_b = 0.0
            loss = 0.0
            for x, y in data:
                p = self._probability(x)
                err = p - y
                loss += -(y * math.log(max(p, 1e-9)) + (1 - y) * math.log(max(1 - p, 1e-9)))
                for i in range(len(self.weights)):
                    grad_w[i] += err * x[i]
                grad_b += err
            n = max(len(data), 1)
            for i in range(len(self.weights)):
                self.weights[i] -= lr * grad_w[i] / n
            self.bias -= lr * grad_b / n
            history.append(loss / n)
        self.trained = True
        return history

    def predict_success(self, features: dict[str, float]) -> float:
        """Estimated probability the student *acts successfully* on the match."""
        return round(self._probability(self.vectorise(features)), 4)

    def score_examples(self, examples: list[TrainingExample]) -> list[tuple[TrainingExample, float]]:
        return [(e, self.predict_success(e.features)) for e in examples]

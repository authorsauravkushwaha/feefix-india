"""V2 rank comparison — puts the outcome-trained model beside V1, live.

Flow:
  1. Collect all recorded outcome events (``backend/services/events``).
  2. If there are enough real outcomes (≥ 25), train on them. Otherwise
     bootstrap with the synthetic population from ``ml/experiments`` — the
     *shape* of the model is the same; the demo flag tells the UI.
  3. For every currently ranked match, compute the V1 signal vector
     (identical features to V1), the model probability, and a 50/50 blended
     V2 score — then emit the new ordering side by side with the V1 one.

Transparent-by-design: the model never invents a signal, it only re-weights
the ones V1 already shows students.
"""

from __future__ import annotations

from backend.matching_engine.engine import EligibilityEngine
from backend.matching_engine.ranker import RankedMatch, RankingEngine
from backend.services.dataset import DatasetService
from backend.services import events as events_svc
from ml.ranking import OutcomeRanker

MIN_REAL_EVENTS = 25
BOOTSTRAP_SIZE = 800


def _features(r: RankedMatch, max_amount: int, ranker: RankingEngine) -> dict:
    urgency = ranker._urgency(r.days_left)  # same computation V1 uses
    return {
        "clarity": r.evaluation.clarity,
        "urgency": round(urgency / 25.0, 4),
        "benefit_norm": round(r.scheme.benefit.amount_annual_inr / max_amount, 4)
        if max_amount else 0.0,
        "verified": 1.0 if r.scheme.verification_status == "verified" else 0.0,
    }


def train_ranker(events: list[dict] | None = None) -> tuple[OutcomeRanker, int, bool]:
    """Returns (ranker, samples_used, used_synthetic_bootstrap)."""
    events = events if events is not None else events_svc.load()
    trainable = [
        e for e in events
        if e.get("type") in {"applied", "approved", "rejected", "missed", "under_review"}
        and e.get("context", {}).get("clarity") is not None
    ]
    ranker = OutcomeRanker()
    if len(trainable) >= MIN_REAL_EVENTS:
        examples = []
        label_map = {"applied": "applied", "approved": "approved",
                     "rejected": "rejected", "missed": "missed", "under_review": "applied"}
        for e in trainable:
            c = e["context"]
            examples.append(OutcomeRanker.from_ranker_signals(
                clarity=c.get("clarity", 0.5),
                urgency=c.get("urgency", 0.2) * 25,
                benefit_norm=c.get("benefit_norm", 0.0),
                verified=bool(c.get("verified", 0.0)),
                outcome=label_map.get(e["type"], "unknown"),
            ))
        ranker.fit(examples, epochs=250)
        return ranker, len(examples), False

    from ml.experiments.simulate_outcomes import synthesize

    examples = synthesize(BOOTSTRAP_SIZE)
    ranker.fit(examples +  # sprinkle any real events on top of the bootstrap
               [OutcomeRanker.from_ranker_signals(
                   clarity=e["context"].get("clarity", 0.5),
                   urgency=e["context"].get("urgency", 0.2) * 25,
                   benefit_norm=e["context"].get("benefit_norm", 0.0),
                   verified=bool(e["context"].get("verified", 0.0)),
                   outcome="applied",
               ) for e in trainable],
               epochs=250)
    return ranker, len(examples) + len(trainable), True


def compare(session_profile, dataset: DatasetService, events: list[dict] | None = None) -> dict:
    """V1 ordering vs outcome-model ordering, for one student's matches."""
    engine = EligibilityEngine(dataset.schemes)
    report = engine.match(session_profile)
    v1_ranker = RankingEngine()
    ranked = v1_ranker.rank(report.matches)
    open_ranked = [r for r in ranked if not r.expired]

    model, samples, bootstrap = train_ranker(events)
    amounts = [r.scheme.benefit.amount_annual_inr for r in open_ranked] or [1]
    max_amount = max(amounts) or 1
    max_v1 = max((r.score for r in open_ranked), default=1) or 1

    items = []
    for idx, r in enumerate(open_ranked):
        feats = _features(r, max_amount, v1_ranker)
        prob = model.predict_success(feats)
        v1_norm = r.score / max_v1
        v2 = round(0.5 * v1_norm + 0.5 * prob, 4)
        items.append({
            "scheme_id": r.scheme.id,
            "v1_score": r.score,
            "v1_rank": idx + 1,
            "model_probability": prob,
            "v2_score": v2,
            "features": feats,
        })
    order = sorted(items, key=lambda x: -x["v2_score"])
    for i, item in enumerate(order):
        item["v2_rank"] = i + 1
    return {
        "trained_on": samples,
        "bootstrap": bootstrap,
        "items": order,
    }

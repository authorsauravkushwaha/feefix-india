"""Ranking engine — orders eligible schemes by *actionable value* now.

V1 ranking is a transparent additive score over four examinable signals:

    score = 45 × clarity            (how confirmed the match is)
          + urgency                 (deadline pressure, 0..25)
          + benefit_norm            (money at stake, 0..20, normalised)
          + verification bonus      (5 when the record is freshly verified)

The V2 ML layer (``ml/ranking``) reuses exactly these signals as features,
so the transition from rules to learned ranking does not change the product
contract — it only re-weights the same, explainable evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from backend.matching_engine.engine import SchemeEvaluation


@dataclass
class RankedMatch:
    evaluation: SchemeEvaluation
    score: float
    days_left: int | None
    expired: bool
    badges: list[str] = field(default_factory=list)

    @property
    def scheme(self):
        return self.evaluation.scheme


class RankingEngine:
    def __init__(self, today: date | None = None):
        self.today = today or date.today()

    # -- signal helpers ------------------------------------------------------
    def days_until(self, evaluation: SchemeEvaluation) -> int | None:
        deadline = evaluation.scheme.deadline
        if deadline.rolling or not deadline.date:
            return None
        return (deadline.date - self.today).days

    def _urgency(self, days: int | None) -> float:
        if days is None:  # rolling intake
            return 6.0
        if days < 0:
            return 0.0  # window closed
        if days <= 30:
            return 25.0
        if days <= 60:
            return 18.0
        if days <= 90:
            return 12.0
        if days <= 180:
            return 8.0
        return 4.0

    @staticmethod
    def _badges(days: int | None, evaluation: SchemeEvaluation, rank: int) -> list[str]:
        badges: list[str] = []
        scheme = evaluation.scheme
        if rank == 0:
            badges.append("top_pick")
        if days is not None and 0 <= days <= 30:
            badges.append("closing_soon")
        if days is not None and days < 0:
            badges.append("window_closed")
        if scheme.benefit.type == "fee_waiver":
            badges.append("fee_waiver")
        elif scheme.benefit.amount_annual_inr >= 50000:
            badges.append("high_value")
        if scheme.level == "state":
            badges.append("state_scheme")
        else:
            badges.append("all_india")
        if scheme.verification_status == "verified":
            badges.append("verified")
        return badges

    # -- public API -----------------------------------------------------------
    def rank(self, matches: list[SchemeEvaluation]) -> list[RankedMatch]:
        amounts = [m.scheme.benefit.amount_annual_inr for m in matches] or [0]
        max_amount = max(amounts) or 1

        ranked: list[RankedMatch] = []
        for m in matches:
            days = self.days_until(m)
            benefit = m.scheme.benefit.amount_annual_inr / max_amount * 20.0
            verified = 5.0 if m.scheme.verification_status == "verified" else 1.0
            score = (45.0 * m.clarity) + self._urgency(days) + benefit + verified
            ranked.append(
                RankedMatch(evaluation=m, score=round(score, 2),
                            days_left=days, expired=days is not None and days < 0)
            )

        ranked.sort(key=lambda r: (r.expired, -r.score, r.scheme.name))
        for i, r in enumerate(ranked):
            r.badges = self._badges(r.days_left, r.evaluation, i)
        return ranked

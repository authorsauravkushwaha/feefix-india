"""FeeFix matching engine — transparent, rule-based eligibility evaluation.

V1 philosophy: a match is never a black-box prediction. It is a set of
explicit rules a student satisfies, each with a human-readable explanation.
"""

from backend.matching_engine.engine import EligibilityEngine, SchemeEvaluation  # noqa: F401
from backend.matching_engine.ranker import RankingEngine, RankedMatch  # noqa: F401

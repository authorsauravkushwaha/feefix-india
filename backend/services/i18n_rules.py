"""Regional-language explanation renderer (Phase 4 language layer).

The engine stays language-neutral: rules produce English details *plus* the
slot values (``RuleResult.params``). This module re-renders those details in
any supported language from template dictionaries at
``language/regional_support/explanations/{lang}.json``.

Contract: template key = ``"{rule}.{status}"``, slots = ``RuleResult.params``.
Missing key/language → English detail preserved (never a broken sentence).
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from backend.matching_engine.engine import MatchReport
from backend.matching_engine.rules import RuleResult

EXPL_DIR = (
    Path(__file__).resolve().parents[2] / "language" / "regional_support" / "explanations"
)
SUPPORTED = {"en", "bn", "hi"}


class _SafeParams(dict):
    def __missing__(self, key):  # never explode on a typo'd slot name
        return "{" + key + "}"


@lru_cache(maxsize=8)
def _templates(lang: str) -> dict:
    if lang not in SUPPORTED:
        return {}
    path = EXPL_DIR / f"{lang}.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def render_rule(result: RuleResult, lang: str) -> str:
    """Localized detail for one rule result (falls back to its English text)."""
    if lang == "en":
        return result.detail
    tpl = _templates(lang).get(f"{result.rule}.{result.status}")
    if not tpl:
        return result.detail
    params = _SafeParams({k: str(v) for k, v in result.params.items()})
    try:
        return tpl.format_map(params)
    except Exception:
        return result.detail


def localize_report(report: MatchReport, lang: str) -> MatchReport:
    """Rewrite every explanation in a match report to the target language."""
    if lang == "en":
        return report
    for evaluation in report.matches + report.near_misses:
        for result in evaluation.rules.results:
            result.detail = render_rule(result, lang)
    return report

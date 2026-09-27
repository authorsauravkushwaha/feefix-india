"""Gap coach — converts a near-miss blocker into actionable advice.

A near miss is not a rejection; it is a *margin*. The coach turns the single
failing rule into the exact next thing to check, gather or verify.
"""

from __future__ import annotations

from backend.matching_engine.rules import RuleResult
from backend.models.scheme import Scheme


def gap_advice_for(blocker: RuleResult, scheme: Scheme) -> str:
    """Human next-best-action for one blocking rule."""
    r = blocker.rule
    if r == "income":
        return (
            "Income margin is close. Recheck the figure on a fresh, certified income "
            "certificate — scheme income is computed for the *entire* family per its own "
            "definition (some schemes exclude education income or count parents only)."
        )
    if r == "marks":
        return (
            "Check the official portal for category-wise and renewal cut-offs — they are "
            "often 5–10 points lower than the fresh-application cut-off. If your board "
            "percentile differs from aggregate %, ask if top-percentile rules help."
        )
    if r == "minority":
        return (
            "This scheme is limited to notified minority communities. If you hold a "
            "minority community certificate, update your profile; otherwise ignore this one."
        )
    if r == "category":
        return (
            "This scheme is category-restricted. Make sure your caste certificate is issued "
            "by the competent state authority — a central-format certificate often fails "
            "state validation. If you have one, update the category in your profile."
        )
    if r == "state":
        return (
            "Domicile-restricted scheme. Compare with the all-India (central) matches in "
            "your list — most portals accept any Indian domicile."
        )
    if r == "course":
        return (
            "This scheme covers a different academic stage. It may still help a sibling, "
            "or you in the next academic year — save it and FeeFix will remind you."
        )
    if r == "gender":
        return "This scheme is gender-restricted by design; no workaround applies."
    if r == "disability":
        return (
            "Reserved for benchmark disability (40%+). If you have a UDID/disability "
            "certificate, update your profile to unlock this match."
        )
    if r == "single_girl_child":
        return "Requires an attested single-girl-child affidavit — verify your status."
    return "Review the scheme's eligibility section to close this gap."

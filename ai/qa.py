"""FeeFix Q&A — grounded, citation-backed answers about scholarships.

**Grounding rule:** an answer may only contain facts present in structured
dataset fields (name, benefit, deadline, eligibility, URLs). The engine never
generates free-world knowledge — it *retrieves and assembles*. Users can
therefore never be hallucinated an invented scheme.

Answer builder strategy:
  1. Extract profile hints from the question (gender, community, category,
     disability, state, course, income) via the lexicon + reach-layer parsers.
  2. If hints (or a session profile) exist → run the real matching engine and
     answer from the top matches, including why-you-match reasons.
  3. Otherwise → answer from semantic search hits (scheme Q&A mode).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ai.lexicon import HINTS, MINORITY_COMMUNITIES
from ai.search import SemanticSearch, SearchHit
from backend.models.student import Gender, StudentProfile
from backend.services.chat import parse_course, parse_income, parse_state
from backend.services.dataset import DatasetService
from backend.services.matching import match_profile

FOCUS_WORDS = ("deadline", "last date", "lastdate", "kab tak", "apply by", "benefit", "amount",
               "kitna", "how much", "documents", "papers", "eligibility", "who can", "criteria")


@dataclass
class QaAnswer:
    question: str
    answer: str
    mode: str                     # "profile" | "search"
    citations: list[dict] = field(default_factory=list)   # [{id, name, score}]
    detected_profile: dict = field(default_factory=dict)
    backend: str = "unknown"


class QaEngine:
    def __init__(self, dataset: DatasetService, search: SemanticSearch | None = None):
        self.dataset = dataset
        self.search = search or SemanticSearch(dataset.schemes)
        self.backend = self.search.backend_name

    # ------------------------------------------------------------ hints --
    @staticmethod
    def _detect_profile(question: str, base: StudentProfile | None) -> tuple[dict, bool]:
        """Extract profile hints from free text. Returns (overrides, found?)."""
        q = question.lower()
        hints: dict = {}
        if state := parse_state(question):
            hints["domicile_state"] = state
        if course := parse_course(question):
            # parse_course is keyword-based; avoid false trigger from generic text
            if re.search(r"\b(class|b\.?tech|btech|mtech|m\.?tech|mbbs|bsc|b\.?sc|msc|m\.?sc|iti|diploma|polytechnic|phd|mba|ug|pg|inter|hs|school|college|engineering|medical|nursing|degree)\b", q):
                hints["course_level"] = course.value
        if re.search(r"(income|earn|salary|lakh|lac|₹|\brs\.?\b|rupee|how much do)", q):
            if income := parse_income(question):
                hints["annual_family_income"] = income
        if HINTS["female"].search(question):
            hints["gender"] = Gender.female.value
        elif HINTS["male"].search(question):
            hints["gender"] = Gender.male.value
        if HINTS["minority"].search(question):
            hints["is_minority"] = True
            community = next((c for c in MINORITY_COMMUNITIES if c in q), None)
            if community:
                hints["minority_community"] = community
        if HINTS["disabled"].search(question):
            hints["has_disability"] = True
        if HINTS["obc"].search(question):
            hints["category"] = "obc"
        elif HINTS["sc"].search(question):
            hints["category"] = "sc"
        elif HINTS["st"].search(question):
            hints["category"] = "st"
        if m := re.search(r"(\d{2}(?:\.\d+)?)\s?%", q):
            hints["last_exam_percentage"] = float(m.group(1))
        return hints, bool(hints)

    # ------------------------------------------------------------ answer --
    def answer(
        self, question: str, session_profile: StudentProfile | None = None, k: int = 4
    ) -> QaAnswer:
        hints, found = self._detect_profile(question, session_profile)

        base = session_profile.model_dump(mode="json") if session_profile else {}
        merged = {**base, **hints}
        profile = StudentProfile(**merged)

        if found or session_profile:
            return self._answer_from_profile(question, profile, hints, found, k)
        return self._answer_from_search(question, k)

    # ---------------------------------------------------------- builders --
    def _rerank_by_semantics(self, question: str, matches: list[dict]) -> list[dict]:
        """50/50 blend of rule-ranker score and semantic similarity to the query."""
        if not matches:
            return matches
        sem = self.search.scores_for(question, {m["id"] for m in matches})
        if not sem:
            return matches
        max_score = max((m["score"] for m in matches), default=1) or 1
        max_sem = max(sem.values(), default=1) or 1

        def blended(m: dict) -> float:
            s_norm = m["score"] / max_score
            q_norm = sem.get(m["id"], 0.0) / max_sem
            return round(0.5 * s_norm + 0.5 * q_norm, 4)

        return sorted(matches, key=lambda m: (-blended(m), m["id"]))

    def _answer_from_profile(
        self, question: str, profile: StudentProfile, hints: dict, found: bool, k: int
    ) -> QaAnswer:
        result = match_profile(profile, self.dataset)
        open_matches = [m for m in result["matches"] if not m["deadline"]["expired"]]
        # Blend rule-ranker score with semantic relevance to the question, so
        # "engineering scholarship for girls" puts AICTE Pragati above INSPIRE.
        open_matches = self._rerank_by_semantics(question, open_matches)
        top = open_matches[:k]

        if not top:
            answer = (
                "From the verified FeeFix catalogue I don't see an open scheme that fits "
                "this profile today. Two suggestions: (1) re-check assumptions like marks "
                "and income certificates, (2) watch the rolling schemes — several reopen "
                "every cycle. Always verify on the official portal."
            )
            return QaAnswer(question, answer, "profile", [], hints, self.backend)

        intro = (
            "Based on your profile, you qualify for these:"
            if found else "Using your saved profile, your strongest fits:"
        )
        blocks = []
        citations = []
        for i, m in enumerate(top, 1):
            dl = m["deadline"]
            when = "rolling intake (apply any time)" if dl["rolling"] else (
                f"deadline {dl['date']} ({dl['days_left']} days left)" if dl["days_left"] is not None
                else "deadline announced each cycle"
            )
            reason = f"\n   ✓ {m['why_matched'][0]}" if m["why_matched"] else ""
            blocks.append(
                f"{i}. **{m['name']}** — {m['benefit']['amount_display']} · {when}{reason}"
            )
            citations.append({"id": m["id"], "name": m["name"], "score": m["score"]})
        assume = ""
        if top and top[0]["assumptions"]:
            assume = "\n\n⚠ Verify: " + top[0]["assumptions"][0]["detail"]

        # Radar: a scheme the question is *about* that you miss by one rule.
        radar = ""
        near = result.get("near_misses", [])
        if near:
            near_sem = self.search.scores_for(question, {n["id"] for n in near})
            cited_ids = {c["id"] for c in citations}
            candidates = [
                (sid, s) for sid, s in near_sem.items()
                if sid not in cited_ids and s >= 0.28
            ]
            candidates.sort(key=lambda x: -x[1])
            if candidates:
                nid = candidates[0][0]
                n = next(x for x in near if x["id"] == nid)
                radar = (
                    f"\n\n📡 Worth watching: **{n['name']}** — you're one requirement "
                    f"away ({n['failed_rule']['detail']}). {n['gap_advice']}"
                )
                citations.append({"id": n["id"], "name": n["name"], "score": round(candidates[0][1], 4)})

        answer = f"{intro}\n" + "\n".join(blocks) + assume + radar + (
            "\n\n_Curated from FeeFix's verified dataset — re-confirm on the official portal before applying._"
        )
        return QaAnswer(question, answer, "profile", citations, hints, self.backend)

    def _answer_from_search(self, question: str, k: int) -> QaAnswer:
        hits: list[SearchHit] = self.search.search(question, k=k)
        hits = [h for h in hits if h.score > 0] or hits[:k]

        blocks, citations = [], []
        focus_docs = re.search(r"document|paper|certificate|kagoj|kagaz", question, re.I)
        focus_dl = re.search(r"deadline|last date|kab tak|closing|till when", question, re.I)
        for i, hit in enumerate(hits, 1):
            s = hit.scheme
            dl = s.deadline
            when = "rolling intake" if dl.rolling else f"deadline {dl.date}" if dl.date else "cycle-based"
            extra = ""
            if focus_docs:
                extra = "\n   documents: " + "; ".join(s.documents[:4])
            elif focus_dl:
                extra = f"\n   status: {s.deadline.label}"
            blocks.append(
                f"{i}. **{s.name}** — {s.benefit.amount_display} · {when}{extra}"
            )
            citations.append({"id": s.id, "name": s.name, "score": round(hit.score, 4)})
        lead = "Here's what I found in the verified FeeFix catalogue:"
        hint_tail = (
            "\n\nTip: tell me your state, course and family income (or complete the Smart "
            "Matcher) and I'll rank these for *your* profile."
        )
        answer = f"{lead}\n" + "\n".join(blocks) + hint_tail + (
            "\n\n_Curated from FeeFix's verified dataset — re-confirm on the official portal._"
        )
        return QaAnswer(question, answer, "search", citations, {}, self.backend)

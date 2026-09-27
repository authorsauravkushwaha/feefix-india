"""FeeFix Reach Layer — a WhatsApp-style conversational matcher.

The same eligibility engine, spoken through three questions. The state
machine is deliberately tiny (state → course → income → matches) so it can
run on any chat transport — the web demo, WhatsApp Business API, or SMS.

Sessions are held in memory keyed by ``chat_id``; swap ``ChatSessionStore``
for Redis to run many workers.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field

from backend.models.student import (
    CourseLevel,
    INDIAN_STATES,
    StudentProfile,
)
from backend.services.dataset import DatasetService
from backend.services.matching import match_profile, strip_internal

ASK_STATE = "ask_state"
ASK_COURSE = "ask_course"
ASK_INCOME = "ask_income"
DONE = "done"

_COURSE_KEYWORDS: list[tuple[tuple[str, ...], CourseLevel]] = [
    (("phd", "ph.d", "doctorate", "research"), CourseLevel.phd),
    (("m.tech", "mtech", "m.sc", "msc", "mba", "ma ", "postgraduate", "pg", "master"), CourseLevel.pg),
    (("b.tech", "btech", "b.e", "engineering", "mbbs", "b.sc", "bsc", "ba", "b.com", "undergraduate", "ug", "degree", "college"), CourseLevel.ug),
    (("iti",), CourseLevel.iti),
    (("diploma", "polytechnic"), CourseLevel.diploma),
    (("11", "12", "xi", "xii", "hs", "higher secondary", "+2", "intermediate"), CourseLevel.higher_secondary),
    (("school", "class 8", "class 9", "class 10", "8", "9", "10", "madhyamik"), CourseLevel.school),
]

_STATE_LOOKUP = {s.lower(): s for s in INDIAN_STATES}
_STATE_LOOKUP.update({
    "wb": "West Bengal",
    "bengal": "West Bengal",
    "delhi ncr": "Delhi",
    "orissa": "Odisha",
    "pondicherry": "Puducherry",
    "up": "Uttar Pradesh",
    "mp": "Madhya Pradesh",
    "ap": "Andhra Pradesh",
    "tn": "Tamil Nadu",
    "j&k": "Jammu and Kashmir",
})


def parse_income(text: str) -> int | None:
    """Parse '₹2,00,000', '2 lakh', '1.5 lakhs', '200000' → INR int."""
    t = text.lower().replace("₹", "").replace(",", "").strip()
    m = re.search(r"(\d+(?:\.\d+)?)\s*(lakh|lac|l)(?:s|hs)?\b", t)
    if m:
        return int(float(m.group(1)) * 100000)
    m = re.search(r"(\d+(?:\.\d+)?)\s*(thousand|k)\b", t)
    if m:
        return int(float(m.group(1)) * 1000)
    m = re.search(r"(\d{4,9})", t)
    if m:
        return int(m.group(1))
    return None


def parse_state(text: str) -> str | None:
    t = text.strip().lower()
    if t in _STATE_LOOKUP:
        return _STATE_LOOKUP[t]
    for key, name in _STATE_LOOKUP.items():
        if key in t:
            return name
    return None


_WORD_CACHE: dict[str, re.Pattern] = {}


def _word_regex(keyword: str) -> re.Pattern:
    pattern = _WORD_CACHE.get(keyword)
    if pattern is None:
        pattern = re.compile(
            rf"(?<![a-z0-9]){re.escape(keyword.strip())}(?![a-z0-9])"
        )
        _WORD_CACHE[keyword] = pattern
    return pattern


def parse_course(text: str) -> CourseLevel | None:
    """Keyword match on whole words only — 'diploma' must not hit PG's 'ma'."""
    t = text.strip().lower()
    for keywords, level in _COURSE_KEYWORDS:
        if any(_word_regex(kw).search(t) for kw in keywords):
            return level
    return None


@dataclass
class ChatSession:
    chat_id: str
    step: str = ASK_STATE
    answers: dict = field(default_factory=dict)


_SESSIONS: dict[str, ChatSession] = {}

WELCOME = (
    "👋 Welcome to *FeeFix* — I find scholarships and fee waivers you qualify for, "
    "in 3 questions.\n\n*Question 1 of 3:* Which state do you live in (domicile)?"
)


def handle_message(
    message: str,
    dataset: DatasetService,
    chat_id: str | None = None,
) -> dict:
    """Process one chat turn and return the reply (+ matches when ready)."""
    session = _SESSIONS.get(chat_id or "")
    if session is None:
        session = ChatSession(chat_id=chat_id or uuid.uuid4().hex[:12])
        _SESSIONS[session.chat_id] = session

    text = (message or "").strip()
    if text.lower() in ("/start", "start", "hi", "hello", "restart"):
        session.step, session.answers = ASK_STATE, {}
        return {"chat_id": session.chat_id, "step": session.step, "reply": WELCOME}

    if session.step == ASK_STATE:
        state = parse_state(text)
        if not state:
            return {
                "chat_id": session.chat_id,
                "step": session.step,
                "reply": "I couldn't recognise that state. Try e.g. *West Bengal* or *Bihar*.",
            }
        session.answers["domicile"] = state
        session.step = ASK_COURSE
        return {
            "chat_id": session.chat_id,
            "step": session.step,
            "reply": (
                f"✅ Noted: *{state}*.\n\n*Question 2 of 3:* What are you studying? "
                "(e.g. Class 10, HS, ITI, Diploma, B.Tech/UG, M.Sc/PG, PhD)"
            ),
        }

    if session.step == ASK_COURSE:
        course = parse_course(text)
        if not course:
            return {
                "chat_id": session.chat_id,
                "step": session.step,
                "reply": "Hmm — say something like *B.Tech*, *Class 12*, *ITI*, *Diploma*, or *MSc*.",
            }
        session.answers["course"] = course
        session.step = ASK_INCOME
        return {
            "chat_id": session.chat_id,
            "step": session.step,
            "reply": (
                f"✅ Got it: *{course.value.replace('_', ' ')}*.\n\n"
                "*Question 3 of 3:* What is your approximate annual family income? "
                "(e.g. ₹2,00,000 or '2 lakh')"
            ),
        }

    if session.step == ASK_INCOME:
        income = parse_income(text)
        if income is None:
            return {
                "chat_id": session.chat_id,
                "step": session.step,
                "reply": "Please give a number — like *₹1,50,000* or *2.5 lakh*.",
            }
        session.answers["income"] = income
        session.step = DONE

        profile = StudentProfile(
            domicile_state=session.answers["domicile"],
            course_level=session.answers["course"],
            annual_family_income=session.answers["income"],
        )
        result = match_profile(profile, dataset)
        open_matches = [m for m in result["matches"] if not m["deadline"]["expired"]]
        top = [
            {
                "id": m["id"],
                "name": m["name"],
                "benefit": m["benefit"]["amount_display"],
                "deadline": m["deadline"],
                "score": m["score"],
                "why_matched": m["why_matched"][:3],
            }
            for m in open_matches[:5]
        ]
        lines = [f"🎯 *{result['match_count']} schemes match your profile.*"]
        for i, m in enumerate(top, 1):
            dl = m["deadline"]
            when = "rolling" if dl["rolling"] else (
                f"{dl['days_left']} days left" if dl["days_left"] is not None else "—"
            )
            lines.append(f"{i}. *{m['name']}* — {m['benefit']} · {when}")
        lines.append(
            "\nOn the FeeFix site you can add category, marks, gender and minority "
            "details to refine these results — and track every application."
        )
        return {
            "chat_id": session.chat_id,
            "step": session.step,
            "reply": "\n".join(lines),
            "matches": top,
            "assumptions": "Category 'General', no minority/disability flags, no marks — refine on the full matcher.",
            "full_result": strip_internal(result),
        }

    # DONE — any further message restarts.
    session.step, session.answers = ASK_STATE, {}
    return {
        "chat_id": session.chat_id,
        "step": session.step,
        "reply": "Let's start fresh! " + WELCOME,
    }

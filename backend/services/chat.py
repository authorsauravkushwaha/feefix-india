"""FeeFix Reach Layer — a WhatsApp-style conversational matcher.

The same eligibility engine, spoken through three questions. The state
machine is deliberately tiny (state → course → income → matches → free-text
Q&A) so it can run on any chat transport — the web demo, WhatsApp Business
API, or SMS.

V3 language layer: the conversation *follows the student's script*. Type in
Bengali (বাংলা) or Hindi (हिन्दी) and every question, prompt and summary
comes back in that language; native digits (১২ লাখ / २ लाख) are understood.

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
from backend.services.chat_i18n import detect_lang, normalize_digits, tr
from backend.services.dataset import DatasetService
from backend.services.matching import match_profile, strip_internal

ASK_STATE = "ask_state"
ASK_COURSE = "ask_course"
ASK_INCOME = "ask_income"
DONE = "done"

_COURSE_KEYWORDS: list[tuple[tuple[str, ...], CourseLevel]] = [
    (("phd", "ph.d", "doctorate", "research", "পিএইচডি", "पीएचडी"), CourseLevel.phd),
    (("m.tech", "mtech", "m.sc", "msc", "mba", "ma ", "postgraduate", "pg", "master",
      "স্নাতকোত্তর", "এমএসসি", "এমএ", "एमएससी", "स्नातकोत्तर"), CourseLevel.pg),
    (("b.tech", "btech", "b.e", "engineering", "mbbs", "b.sc", "bsc", "ba", "b.com",
      "undergraduate", "ug", "degree", "college", "বি.টেক", "বি টেক",
      "ইঞ্জিনিয়ারিং", "इंजीनियरिंग", "बी.टेक", "बी टेक", "স্নাতক", "स्नातक",
      "কলেজ", "कॉलेज"), CourseLevel.ug),
    (("iti", "আইটিআই", "आईटीआई"), CourseLevel.iti),
    (("diploma", "polytechnic", "ডিপ্লোমা", "डिप्लोमा", "পলিটেকনিক"), CourseLevel.diploma),
    (("11", "12", "xi", "xii", "hs", "higher secondary", "+2", "intermediate", "inter",
      "plus two", "১১", "১২", "१२", "ইন্টার", "इंटर", "উচ্চ মাধ্যমিক",
      "कक्षा 12", "कक्षा १२", "कक्षा 11"), CourseLevel.higher_secondary),
    (("school", "class 8", "class 9", "class 10", "8", "9", "10", "madhyamik",
      "স্কুল", "स्कूल", "মাধ্যমিক", "ক্লাস", "कक्षा"), CourseLevel.school),
]

_STATE_LOOKUP = {s.lower(): s for s in INDIAN_STATES}
_STATE_LOOKUP.update({
    # English aliases
    "wb": "West Bengal", "bengal": "West Bengal", "delhi ncr": "Delhi",
    "orissa": "Odisha", "pondicherry": "Puducherry", "up": "Uttar Pradesh",
    "mp": "Madhya Pradesh", "ap": "Andhra Pradesh", "tn": "Tamil Nadu",
    "j&k": "Jammu and Kashmir", "odisha": "Odisha",
    # Bengali
    "পশ্চিমবঙ্গ": "West Bengal", "বাংলা": "West Bengal", "পশ্চিম বাংলা": "West Bengal",
    "বিহার": "Bihar", "আসাম": "Assam", "ওড়িশা": "Odisha", "ওডিশা": "Odisha",
    "ত্রিপুরা": "Tripura", "ঝাড়খণ্ড": "Jharkhand", "দিল্লি": "Delhi",
    "মেঘালয়": "Meghalaya", "মণিপুর": "Manipur", "তামিলনাড়ু": "Tamil Nadu",
    "কেরালা": "Kerala", "কর্ণাটক": "Karnataka", "গুজরাট": "Gujarat",
    "মহারাষ্ট্র": "Maharashtra", "পাঞ্জাব": "Punjab", "রাজস্থান": "Rajasthan",
    "উত্তর প্রদেশ": "Uttar Pradesh", "মধ্য প্রদেশ": "Madhya Pradesh",
    # Hindi
    "पश्चिम बंगाल": "West Bengal", "बंगाल": "West Bengal", "बिहार": "Bihar",
    "असम": "Assam", "असमिया": "Assam", "ओडिशा": "Odisha", "ओड़िसा": "Odisha",
    "उत्तर प्रदेश": "Uttar Pradesh", "यूपी": "Uttar Pradesh",
    "मध्य प्रदेश": "Madhya Pradesh", "महाराष्ट्र": "Maharashtra",
    "राजस्थान": "Rajasthan", "गुजरात": "Gujarat", "पंजाब": "Punjab",
    "तमिलनाडु": "Tamil Nadu", "केरल": "Kerala", "कर्नाटक": "Karnataka",
    "दिल्ली": "Delhi", "झारखंड": "Jharkhand", "तेलंगाना": "Telangana",
    "हरियाणा": "Haryana", "छत्तीसगढ़": "Chhattisgarh", "त्रिपुरा": "Tripura",
})


def parse_income(text: str) -> int | None:
    """Parse '₹2,00,000', '2 lakh', '১২ লাখ', '2 लाख', '1.5 lakhs', '200000'."""
    t = normalize_digits(text.lower()).replace("₹", "").replace(",", "").strip()
    m = re.search(r"(\d+(?:\.\d+)?)\s*(lakh|lac|লাখ|लाख|l)(?:s|hs)?\b", t)
    if m:
        return int(float(m.group(1)) * 100000)
    m = re.search(r"(\d+(?:\.\d+)?)\s*(thousand|k|হাজার|हज़ार|हजार)\b", t)
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
        # Latin tokens get word boundaries; Indic-script keywords use plain
        # containment (ASCII boundary classes don't apply around native text).
        if re.search(r"[^a-z0-9+\s]", keyword):
            pattern = re.compile(re.escape(keyword.strip()))
        else:
            pattern = re.compile(
                rf"(?<![a-z0-9]){re.escape(keyword.strip())}(?![a-z0-9])"
            )
        _WORD_CACHE[keyword] = pattern
    return pattern


def parse_course(text: str) -> CourseLevel | None:
    """Keyword match; 'diploma' must not hit PG's 'ma', 'internship' must not hit 'inter'."""
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
    lang: str = "en"


_SESSIONS: dict[str, ChatSession] = {}


def _answers_profile(session: ChatSession) -> StudentProfile:
    return StudentProfile(
        domicile_state=session.answers.get("domicile", "West Bengal"),
        course_level=session.answers.get("course", CourseLevel.ug),
        annual_family_income=session.answers.get("income"),
    )


def handle_message(
    message: str,
    dataset: DatasetService,
    chat_id: str | None = None,
    qa=None,
) -> dict:
    """Process one chat turn and return the reply (+ matches when ready).

    ``qa`` (optional): an ``ai.qa.QaEngine`` — enables grounded free-text
    follow-ups after the 3-question flow.
    """
    session = _SESSIONS.get(chat_id or "")
    if session is None:
        session = ChatSession(chat_id=chat_id or uuid.uuid4().hex[:12])
        _SESSIONS[session.chat_id] = session

    text = (message or "").strip()

    # Language follows the student's script.
    detected = detect_lang(text)
    if detected != "en" or not session.answers:
        session.lang = detected if detected != "en" else session.lang
    lang = session.lang or "en"

    def say(key: str, **slots) -> str:
        return tr(lang, key, **slots)

    if text.lower() in ("/start", "start", "hi", "hello", "restart", "শুরু", "रिस्टार्ट"):
        session.lang = detected
        session.step, session.answers = ASK_STATE, {}
        return {"chat_id": session.chat_id, "step": session.step,
                "reply": say("welcome")}

    if session.step == ASK_STATE:
        state = parse_state(text)
        if not state:
            return {"chat_id": session.chat_id, "step": session.step,
                    "reply": say("state_retry")}
        session.answers["domicile"] = state
        session.step = ASK_COURSE
        return {"chat_id": session.chat_id, "step": session.step,
                "reply": say("q2", state=state)}

    if session.step == ASK_COURSE:
        course = parse_course(text)
        if not course:
            return {"chat_id": session.chat_id, "step": session.step,
                    "reply": say("course_retry")}
        session.answers["course"] = course
        session.step = ASK_INCOME
        return {
            "chat_id": session.chat_id,
            "step": session.step,
            "reply": say("q3", course=course.value.replace("_", " ")),
        }

    if session.step == ASK_INCOME:
        income = parse_income(text)
        if income is None:
            return {"chat_id": session.chat_id, "step": session.step,
                    "reply": say("income_retry")}
        session.answers["income"] = income
        session.step = DONE

        profile = _answers_profile(session)
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
        lines = [say("header", n=result["match_count"])]
        for i, m in enumerate(top, 1):
            dl = m["deadline"]
            when = (
                say("rolling") if dl["rolling"] else
                (say("days_left", n=dl["days_left"]) if dl["days_left"] is not None else "—")
            )
            lines.append(f"{i}. *{m['name']}* — {m['benefit']} · {when}")
        lines.append(say("tail"))
        return {
            "chat_id": session.chat_id,
            "step": session.step,
            "reply": "\n".join(lines),
            "matches": top,
            "assumptions": "Category 'General', no minority/disability flags, no marks — refine on the full matcher.",
            "full_result": strip_internal(result),
        }

    # DONE — free-text follow-ups become grounded Q&A (if an AI engine is
    # wired in); the word "restart" starts over.
    if session.step == DONE and qa is not None:
        profile = _answers_profile(session)
        result = qa.answer(text, session_profile=profile)
        return {
            "chat_id": session.chat_id,
            "step": session.step,
            "reply": result.answer,
            "citations": result.citations,
            "mode": result.mode,
        }

    # Otherwise: restart the 3-question flow.
    session.step, session.answers = ASK_STATE, {}
    return {
        "chat_id": session.chat_id,
        "step": session.step,
        "reply": say("fresh") + say("welcome"),
    }

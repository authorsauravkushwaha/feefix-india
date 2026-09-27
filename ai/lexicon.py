"""Domain lexicon for Indian scholarship language.

Queries arrive in Hinglish, Benglish, abbreviations and government jargon.
The lexicon expands tokens to canonical equivalents *for the embedding
corpus only* — the student always sees their original words.
"""

from __future__ import annotations

import re

# canonical → aliases the corpus should also mean
ALIASES: dict[str, list[str]] = {
    "scholarship": ["chhatravritti", "chhatrabritti", "chhatrvitti", "britti", "brithi", "scholership", "skolarship", "upakar"],
    "girl": ["girl", "girls", "female", "daughter", "daughters", "lady", "ladies", "kanya", "balika", "meye", "meyehora", "ladki", "beti", "pragati", "kanyashree"],
    "boy": ["boy", "boys", "male", "son", "sons", "balak", "chhele", "ladka", "beta"],
    "engineering": ["engineering", "engineer", "btech", "b.tech", "b.e", "mtech", "m.tech", "technical", "polytechnic", "diploma"],
    "medical": ["medical", "mbbs", "nursing", "bds", "doctor", "ayush", "bams"],
    "science": ["science", "bsc", "b.sc", "msc", "m.sc", "physics", "chemistry", "maths", "mathematics", "biology", "inspire"],
    "minority": ["minority", "minorities", "muslim", "islam", "christian", "sikh", "buddhist", "jain", "parsee", "parsi", "aikyashree"],
    "loan": ["loan", "credit", "bscc", "student credit", "credit card", "finance"],
    "fee_waiver": ["fee waiver", "feeship", "freeship", "tuition waiver", "fee concession", "waiver", "muft", "free education"],
    "disabled": ["disabled", "disability", "divyang", "handicapped", "pwd", "specially abled", "udid"],
    "hostel": ["hostel", "hosteller", "mess", "accommodation", "residential"],
    "merit": ["merit", "toppers", "rank", "first division", "talent", "medhavi", "bright"],
    "post_matric": ["post matric", "after matric", "after 10th", "post-matric", "pms"],
    "pre_matric": ["pre matric", "before matric", "pre-matric", "class 9", "class 10", "school students"],
    "income": ["income", "salary", "earning", "poor", "bpl", "economically weak", "ews"],
    "deadline": ["deadline", "last date", "apply by", "closing", "urgent", "till when", "kab tak", "shobo shesh"],
    "documents": ["documents", "papers", "certificate", "kagoj", "kagaz", "kagojpotro", "proof"],
    "exam": ["exam", "test", "entrance", "jee", "neet", "wbjee", "board"],
    "sc": ["sc", "scheduled caste", "dalit"],
    "st": ["st", "scheduled tribe", "tribal", "adivasi"],
    "obc": ["obc", "obc-a", "obc-b", "backward", "ebc", "bc", "most backward"],
    "renewal": ["renewal", "renew", "2nd year", "second year", "continue"],
}

# Build alias → canonical lookup (bi-directional expansion)
_LOOKUP: dict[str, list[str]] = {}
for canon, words in ALIASES.items():
    for w in words + [canon]:
        _LOOKUP.setdefault(w.lower(), [])
        if canon not in _LOOKUP[w.lower()]:
            _LOOKUP[w.lower()].append(canon)

_TOKEN_RE = re.compile(r"[a-z0-9.\-+]+")


def expand_query(text: str) -> str:
    """Append canonical tokens after a query's tokens.

    "kanya k liye engineering scholarship" →
    "kanya girl k liye engineering scholarship"
    """
    tokens = _TOKEN_RE.findall(text.lower())
    expanded: list[str] = list(tokens)
    appended: set[str] = set(tokens)          # dedup canonical additions
    for tok in tokens:
        for canon in _LOOKUP.get(tok, []):
            if canon not in appended:
                appended.add(canon)
                expanded.append(canon)
    return " ".join(expanded)


# --- profile-hint extraction (for grounded Q&A) ----------------------------- #
HINTS = {
    "female": re.compile(r"\b(girl|female|daughter|lady|kanya|ladki|beti|meye)\b", re.I),
    "male": re.compile(r"\b(boy|male|son|ladka|beta|chhele)\b", re.I),
    "minority": re.compile(r"\b(muslim|islam|christian|sikh|buddhist|jain|parsee|parsi|minority)\b", re.I),
    "disabled": re.compile(r"\b(disabl|divyang|handicap|udid|pwd)\b", re.I),
    "sc": re.compile(r"\b(s\.?c\.?\b|scheduled caste|dalit)", re.I),
    "st": re.compile(r"\b(s\.?t\.?\b|scheduled tribe|adivasi|tribal)", re.I),
    "obc": re.compile(r"\b(o\.?b\.?c\.?\b|backward|ebc|obc-[ab])", re.I),
}

MINORITY_COMMUNITIES = ["muslim", "christian", "sikh", "buddhist", "jain", "parsee"]

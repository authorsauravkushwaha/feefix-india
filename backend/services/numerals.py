"""Locale-aware number text → integer, driven by data instead of escapes.

What was wrong before
---------------------
The income parser carried hand-written ``\\uXXXX`` escapes inside regex
alternations, one per language per scale:

* adding a language meant editing raw escape soup (nobody can review that);
* the escapes were invisible to grep, so a Devanagari character typed into the
  Bengali entry mis-parsed silently — the failure the project already hit once;
* coverage was partial (no crore, no other Indic scripts, no locale digit sets
  beyond Bengali/Devanagari, no currency markers beyond ``₹``).

How it works now
----------------
* The lexicon lives in ``language/regional_support/numerals.json`` in **real
  Unicode**, split by language and scale (crore / lakh / thousand), plus the
  digit sets and currency markers.
* :func:`build_patterns` compiles the lexicon into regexes *programmatically*
  with :func:`re.escape`, so a new language is a data edit — no code change, no
  escapes, no chance of a typo'd codepoint in a Python string literal.
* :func:`validate_lexicon` checks every word's script against the language's
  declared scripts (and that every scale is reachable), which is the automated
  version of "someone typed the wrong script's letter". It runs at import time
  in a test and can be run in CI standalone.
* Digit translation covers every Indic/Arabic-Indic digit set listed in the data
  file, so "२.५ लाख", "২.৫ লাখ", "2.5 கோடி" and "2,50,000" all parse.
* Indian grouping ("1,50,000"), decimals, ranges ("1.5-2 lakh" → 1.5 lakh) and
  currency markers ("Rs.", "INR", "रुपये") are handled.
* ReDoS safety is unchanged and enforced structurally: digit runs are bounded
  and the scale patterns are built from escaped literals inside one pass — the
  timing tests in the security suite keep holding.
"""

from __future__ import annotations

import json
import re
import unicodedata
from functools import lru_cache
from pathlib import Path

LEXICON_PATH = (
    Path(__file__).resolve().parents[2] / "language" / "regional_support" / "numerals.json"
)

#: An annual family income beyond this is not a real figure — reject rather than
#: risk float overflow / absurd downstream arithmetic (availability guard).
MAX_INCOME = 10 ** 13

#: Bound on a digit run; keeps every regex linear (ReDoS guard).
_DIGITS = r"\d{1,12}(?:\.\d{1,6})?"
_ONE_NUMBER = r"(\d{1,12}(?:\.\d{1,6})?)"
#: Range separator so "1.5–2 lakh" and "2 से 3 लाख" are read as a range.
_RANGE_SEP = r"(?:\s*(?:-|–|—|\bto\b|से|থেকে)\s*)?"

#: Zero-width joiners and the nukta can differ between a keyboard, a lexicon and
#: a copy-paste; folding them away makes "हज़रा"/"हजार" and "লক্ষ"/"লক্\u200dষ" the
#: same string before matching (a real-world Apple/Android IME difference).
_INVISIBLE = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u093c"), None)


def fold(text: str) -> str:
    """Canonical, IME-tolerant form used for every comparison."""
    return unicodedata.normalize("NFKC", text).translate(_INVISIBLE)


@lru_cache(maxsize=1)
def lexicon() -> dict:
    return json.loads(LEXICON_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def digit_translation() -> dict[int, str]:
    """str.translate table mapping every configured digit set to ASCII digits."""
    table: dict[int, str] = {}
    for block in lexicon().get("digit_sets", {}).values():
        for offset, glyph in enumerate(block):
            table[ord(glyph)] = str(offset)
    return table


def normalize_digits(text: str) -> str:
    return text.translate(digit_translation())


# -- lexicon validation ------------------------------------------------------- #
# Unicode block ranges are enough to catch "wrong script" typos, which is the
# failure mode that matters here (a Bengali word typed with Devanagari letters).
_SCRIPT_RANGES: dict[str, tuple[tuple[int, int], ...]] = {
    "Latin": ((0x0041, 0x024F),),
    "Devanagari": ((0x0900, 0x097F), (0xA8E0, 0xA8FF)),
    "Bengali": ((0x0980, 0x09FF),),
    "Gurmukhi": ((0x0A00, 0x0A7F),),
    "Gujarati": ((0x0A80, 0x0AFF),),
    "Odia": ((0x0B00, 0x0B7F),),
    "Tamil": ((0x0B80, 0x0BFF),),
    "Telugu": ((0x0C00, 0x0C7F),),
    "Kannada": ((0x0C80, 0x0CFF),),
    "Malayalam": ((0x0D00, 0x0D7F),),
}


def _in_any_script(word: str, scripts: tuple[str, ...]) -> bool:
    for char in word:
        code = ord(char)
        if char in ". -()kK":
            continue
        if not any(
            low <= code <= high for script in scripts for low, high in _SCRIPT_RANGES.get(script, ())
        ):
            return False
    return True


def validate_lexicon(data: dict | None = None) -> list[str]:
    """Return a list of lexicon defects (empty == healthy).

    Catches exactly the class of bug that shipped before: a word whose glyphs do
    not belong to the language it is filed under.
    """
    data = data or lexicon()
    problems: list[str] = []
    scales = set(data.get("scales", {}))
    for lang, spec in data.get("languages", {}).items():
        scripts = tuple(spec.get("scripts", ()))
        words = spec.get("words", {})
        if not scripts:
            problems.append(f"{lang}: no scripts declared")
        for scale in scales:
            if not words.get(scale):
                problems.append(f"{lang}: no word for scale '{scale}'")
            for word in words.get(scale, []):
                if len(word) < 1:
                    problems.append(f"{lang}.{scale}: empty word")
                elif not _in_any_script(word, scripts):
                    problems.append(
                        f"{lang}.{scale}: '{word}' uses characters outside {scripts}"
                    )
    if not scales:
        problems.append("no scales defined")
    return problems


# -- pattern construction ----------------------------------------------------- #
def _alternation(words: list[str]) -> str:
    """One escaped alternation, longest first so 'लाखों' is not eaten by 'लाख'."""
    ordered = sorted({fold(w) for w in words if w}, key=len, reverse=True)
    return "|".join(re.escape(w) for w in ordered)


@lru_cache(maxsize=1)
def build_patterns() -> dict[str, re.Pattern]:
    """Compile the data into regexes: one per scale, plus thousands-of separator."""
    data = lexicon()
    patterns: dict[str, re.Pattern] = {}
    for scale, words in _words_by_scale(data).items():
        if not words:
            continue
        # Latin words need a boundary so "2 l" doesn't match "2 litres" and "2 k"
        # isn't read out of "2 kg"; Indic words are matched by containment.
        body = _alternation(words)
        latin = all(ord(w[0]) < 0x0250 for w in words if w)
        if latin:
            body = body + r"(?![a-z])"
        # (lower)(separator?)(upper)? <scale word>  — the optional second number
        # is what makes "1.5-2 lakh" a range instead of a wrong "2 lakh".
        patterns[scale] = re.compile(
            rf"{_ONE_NUMBER}(?:{_RANGE_SEP}{_ONE_NUMBER})?\s*(?:{body})", re.IGNORECASE
        )
    return patterns


def _words_by_scale(data: dict) -> dict[str, list[str]]:
    by_scale: dict[str, list[str]] = {scale: [] for scale in data.get("scales", {})}
    for spec in data.get("languages", {}).values():
        for scale, words in spec.get("words", {}).items():
            by_scale.setdefault(scale, []).extend(words)
    return by_scale


@lru_cache(maxsize=1)
def currency_pattern() -> re.Pattern:
    markers = lexicon().get("currency_markers", [])
    return re.compile(_alternation(markers) + r"\.?", re.IGNORECASE) if markers else re.compile(r"(?!x)x")


def strip_currency(text: str) -> str:
    return currency_pattern().sub(" ", text)


# -- the parser ---------------------------------------------------------------- #
def _safe_money(numstr: str, multiplier: int) -> int | None:
    try:
        value = float(numstr) * multiplier
    except (ValueError, OverflowError):
        return None
    if value != value or value in (float("inf"), float("-inf")):  # NaN / inf
        return None
    as_int = int(value)
    return as_int if 0 <= as_int <= MAX_INCOME else None


def parse_income(text: str) -> int | None:
    """Parse an income figure in any supported language/script/format.

    ``₹1,50,000`` · ``Rs 2.5 lakh`` · ``2 lakh`` · ``१.५ लाख`` · ``২.৫ লাখ`` ·
    ``2 கோடி`` · ``90 हजार`` · ``1.5 crore`` · ``250000`` — all → an int (INR).
    Returns ``None`` when no plausible figure is present.
    """
    if not text or not isinstance(text, str):
        return None
    # NFKC folds compatibility forms (Devanagari "ऱ", full-width digits) so one
    # comparison table is enough; lower() only affects Latin markers.
    normalized = fold(strip_currency(normalize_digits(text.lower()))).replace(",", "").strip()
    if not normalized:
        return None
    # A digit run longer than the bounded quantifier is not an income figure —
    # refuse rather than silently reading the first 12 digits of a 40-digit mess.
    if re.search(r"\d{13,}", normalized):
        return None

    scales = lexicon().get("scales", {})
    patterns = build_patterns()
    # Largest scale first: "2 crore" must not be read as "2 … k" style noise.
    for scale in sorted(scales, key=lambda s: scales[s], reverse=True):
        pattern = patterns.get(scale)
        if pattern is None:
            continue
        match = pattern.search(normalized)
        if match:
            # A range ("1.5–2 lakh") is read at its *lower* bound: for income,
            # under-claiming keeps a student eligible for more schemes, while a
            # mis-parsed upper bound silently disqualifies them.
            candidates = [
                _safe_money(value, scales[scale])
                for value in (match.group(1), match.group(2))
                if value
            ]
            candidates = [c for c in candidates if c is not None]
            if candidates:
                return min(candidates)
            # A scale word was present but the magnitude is absurd. Returning
            # None (→ "please give a number") is correct; falling through would
            # silently read "9999999999 lakh" as 9,999,999,999 — off by 10^5.
            return None

    match = re.search(r"(\d{1,12}(?:\.\d{1,6})?)", normalized)
    if match:
        return _safe_money(match.group(1), 1)
    return None


def supported_scales() -> dict[str, int]:
    return dict(lexicon().get("scales", {}))


def supported_languages() -> dict[str, list[str]]:
    return {
        lang: list(spec.get("words", {}))
        for lang, spec in lexicon().get("languages", {}).items()
    }

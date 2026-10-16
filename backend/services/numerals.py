"""Amount / numeral understanding — table-driven, script-agnostic.

The previous income parser hard-coded ``\\uXXXX`` escapes for each script inside
a Python regex. That is brittle by construction: adding a language means typing
raw code points (which is exactly how a Devanagari AA once ended up in the
Bengali table), and every new locale is a code change.

This module inverts that. The vocabulary lives in
``language/regional_support/numerals.json``:

* **digit sets** for 14 Indic/right-to-left scripts (Devanagari, Bengali, Tamil,
  Gujarati, Kannada, Telugu, Malayalam, Odia, Gurmukhi, Arabic-Indic …),
* **multiplier words** for crore / lakh / thousand in every language the product
  ships (English, Hindi, Bengali, Tamil), including plural and oblique forms,
* **currency tokens** (₹, ৳, ரூ, रुपये, টাকা, Rs, INR …),

and the parser is built from that table at import time — longest-first so that
``लाखों`` wins over ``लाख``, with Unicode ``\\w`` boundaries so an Indic word
never matches as a prefix of a longer word. Adding a language is a JSON block,
and ``assert_coverage()`` (asserted in the test suite) fails loudly if a
supported language is missing a multiplier — the table cannot silently rot.

Formats understood:

============  ===============================================
Input         Parsed as
============  ===============================================
``₹2,00,000``  200000 (Indian digit grouping)
``2.5 lakh``   250000
``1.5cr``      15000000
``६५ हजार``    65000
``৯০ হাজার``   90000
``2 லட்சம்``   200000
``60k``        60000
``2,50,000``   250000
============  ===============================================

Out of scope by design (documented in the JSON): number words spelled out in
the language itself (Hindi दो = 2) — that needs a per-language number grammar.
"""

from __future__ import annotations

import json
import re
import unicodedata
from functools import lru_cache
from pathlib import Path

NUMERALS_PATH = (
    Path(__file__).resolve().parents[2]
    / "language" / "regional_support" / "numerals.json"
)

#: Amounts above this are not real family incomes — reject rather than let an
#: absurd figure reach downstream arithmetic (availability guard).
MAX_AMOUNT = 10 ** 13

# Bounded digit run *with* boundaries: without them a 40-digit string would
# match its first 12 digits and silently return a truncated number.
_DIGIT_RUN = r"(?<![\d.])\d{1,12}(?:\.\d{1,6})?(?![\d.])"


def _load() -> dict:
    return json.loads(NUMERALS_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def table() -> dict:
    return _load()


@lru_cache(maxsize=1)
def _digit_translation() -> dict[int, str]:
    """Translation map for every supported script's digits → ASCII."""
    mapping: dict[int, str] = {}
    for digits in table()["digit_sets"].values():
        if len(digits) != 10:
            raise ValueError(f"digit set must have 10 glyphs, got {len(digits)!r}")
        for index, glyph in enumerate(digits):
            mapping[ord(glyph)] = str(index)
    return mapping


def normalize_digits(text: str) -> str:
    """Any supported script's digits → ASCII digits."""
    return (text or "").translate(_digit_translation())


def normalize(text: str) -> str:
    """Canonicalise input: NFC, digits → ASCII, currency/strip noise removed.

    NFC matters because Indic text may arrive decomposed (``ा`` + nukta forms),
    which would otherwise defeat plain substring matching — the bug class that
    produced the corrupted escape sequence in the first place.
    """
    text = unicodedata.normalize("NFC", text or "")
    text = normalize_digits(text.lower())
    for token in table()["currency_tokens"]:
        token = unicodedata.normalize("NFC", token.lower())
        if token in text:
            text = text.replace(token, " ")
    for junk in (",", "\u00a0", "_", "'"):
        text = text.replace(junk, "")
    return text.strip()


@lru_cache(maxsize=1)
def multiplier_patterns() -> tuple[tuple[int, re.Pattern[str]], ...]:
    """``(multiplier, compiled pattern)`` pairs, richest multiplier first."""
    entries: list[tuple[int, re.Pattern[str]]] = []
    for entry in sorted(table()["multipliers"], key=lambda e: -int(e["value"])):
        words: set[str] = set()
        for words_for_lang in entry["words"].values():
            words.update(w.lower() for w in words_for_lang)
        # Longest-first alternation so "लाखों" is preferred over "लाख".
        alternatives = "|".join(
            re.escape(w) for w in sorted(words, key=len, reverse=True) if w
        )
        if not alternatives:
            continue
        pattern = re.compile(rf"(?<!\w)({_DIGIT_RUN})\s*(?:{alternatives})(?!\w)")
        entries.append((int(entry["value"]), pattern))
    return tuple(entries)


@lru_cache(maxsize=1)
def _bare_amount_pattern() -> re.Pattern[str]:
    return re.compile(_DIGIT_RUN)


def parse_amount(text: str) -> int | None:
    """Parse a money-ish phrase into an integer amount, or ``None``.

    Digit runs are bounded (``\\d{1,12}``) so a long digit run cannot trigger
    super-linear backtracking; absurd magnitudes are rejected by
    :func:`_bounded` instead of overflowing.
    """
    cleaned = normalize(text)
    if not cleaned:
        return None
    for multiplier, pattern in multiplier_patterns():
        match = pattern.search(cleaned)
        if match:
            return _bounded(match.group(1), multiplier)
    match = _bare_amount_pattern().search(cleaned)
    if match:
        return _bounded(match.group(0), 1)
    return None


def _bounded(numstr: str, multiplier: int) -> int | None:
    try:
        value = float(numstr) * multiplier
    except (ValueError, OverflowError):
        return None
    if value != value or value in (float("inf"), float("-inf")):  # NaN / inf
        return None
    as_int = int(value)
    return as_int if 0 <= as_int <= MAX_AMOUNT else None


def supported_languages() -> set[str]:
    """Languages that have at least one multiplier word in the table."""
    langs: set[str] = set()
    for entry in table()["multipliers"]:
        langs.update(entry["words"].keys())
    return langs


def assert_coverage(required: set[str]) -> list[str]:
    """Return the missing (multiplier, language) pairs for ``required`` locales.

    Used by the test suite: adding a language to the product without adding its
    crore/lakh/thousand vocabulary fails the build instead of silently falling
    back to English.
    """
    missing: list[str] = []
    langs = supported_languages()
    for lang in sorted(required):
        for entry in table()["multipliers"]:
            words = entry["words"].get(lang) or []
            if not [w for w in words if w.strip()]:
                missing.append(f"{entry['label']}:{lang}")
        if lang not in langs:
            missing.append(f"language:{lang}")
    return missing


def describe_table() -> dict:
    """Non-secret summary of the numeral vocabulary (docs / ``/api/meta``)."""
    return {
        "scripts": len(table()["digit_sets"]),
        "languages": sorted(supported_languages()),
        "multipliers": [
            {"value": e["value"], "label": e["label"],
             "languages": sorted(e["words"].keys())}
            for e in table()["multipliers"]
        ],
        "max_amount": MAX_AMOUNT,
    }


def reset_cache() -> None:  # tests
    table.cache_clear()
    _digit_translation.cache_clear()
    multiplier_patterns.cache_clear()
    _bare_amount_pattern.cache_clear()

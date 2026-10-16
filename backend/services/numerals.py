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


# Expected Unicode block for each digit set. A Devanagari glyph pasted into the
# Bengali row (the original corruption) fails this check instead of parsing as
# the wrong script's zero.
_DIGIT_BLOCKS: dict[str, tuple[int, int]] = {
    "hi": (0x0966, 0x096F),
    "mr": (0x0966, 0x096F),
    "ne": (0x0966, 0x096F),
    "bn": (0x09E6, 0x09EF),
    "as": (0x09E6, 0x09EF),
    "ta": (0x0BE6, 0x0BEF),
    "gu": (0x0AE6, 0x0AEF),
    "kn": (0x0CE6, 0x0CEF),
    "te": (0x0C66, 0x0C6F),
    "ml": (0x0D66, 0x0D6F),
    "or": (0x0B66, 0x0B6F),
    "pa": (0x0A66, 0x0A6F),
    "ur": (0x06F0, 0x06F9),
    "ar": (0x0660, 0x0669),
}

# Multiplier words must actually be in that language's script. English
# abbreviations live only under "en".
_WORD_SCRIPT: dict[str, tuple[int, int]] = {
    "hi": (0x0900, 0x097F),
    "mr": (0x0900, 0x097F),
    "bn": (0x0980, 0x09FF),
    "as": (0x0980, 0x09FF),
    "ta": (0x0B80, 0x0BFF),
    "gu": (0x0A80, 0x0AFF),
    "kn": (0x0C80, 0x0CFF),
    "te": (0x0C00, 0x0C7F),
    "ml": (0x0D00, 0x0D7F),
    "or": (0x0B00, 0x0B7F),
    "pa": (0x0A00, 0x0A7F),
    "ur": (0x0600, 0x06FF),
}

_GROUPED_NUMBER = re.compile(
    r"(?<!\d)(?:"
    r"\d{1,3}(?:\.\d{3})+(?:,\d+)?"          # 1.234.567,89  (European)
    r"|\d{1,3}(?:,\d{2,3})+(?:\.\d+)?"       # 2,00,000 / 1,234,567.89
    r"|\d{1,3}(?:[ \u00a0\u202f\u2009]\d{2,3})+(?:[.,]\d+)?"
    r")(?!\d)"
)


def _fold_grouped_number(token: str) -> str:
    """Turn a grouped numeral into a plain ASCII number, keeping the decimal."""
    if re.fullmatch(r"\d{1,3}(?:\.\d{3})+(?:,\d+)?", token):
        return token.replace(".", "").replace(",", ".")
    decimal = ""
    body = token
    tail = re.search(r"([.,])(\d+)$", token)
    if tail and tail.group(1) == "." and not re.fullmatch(r"\d{1,3}(?:\.\d{3})+", token):
        decimal = "." + tail.group(2)
        body = token[: tail.start()]
    elif tail and tail.group(1) == "," and re.fullmatch(r"\d{1,3}(?:\.\d{3})+(?:,\d+)?", token):
        decimal = "." + tail.group(2)
        body = token[: tail.start()]
    body = re.sub(r"[ ,\u00a0\u202f\u2009']", "", body)
    return body + decimal


def _fold_grouped_numbers(text: str) -> str:
    return _GROUPED_NUMBER.sub(lambda match: _fold_grouped_number(match.group(0)), text)


def normalize(text: str) -> str:
    """Canonicalise input: NFC, digits → ASCII, grouping folded, noise removed.

    NFC matters because Indic text may arrive decomposed, which would otherwise
    defeat plain substring matching — the bug class that produced the corrupted
    escape sequence in the first place. Grouping is folded *before* commas are
    stripped, so ``1.234,56`` (European) is not silently read as ``1.23456``.
    """
    text = unicodedata.normalize("NFC", text or "")
    text = normalize_digits(text.lower())
    # Arabic thousands / decimal separators → the forms the folder understands.
    text = text.replace("\u066c", ",").replace("\u066b", ".")
    for token in table()["currency_tokens"]:
        token = unicodedata.normalize("NFC", token.lower())
        if token in text:
            text = text.replace(token, " ")
    text = _fold_grouped_numbers(text)
    for junk in (",", "\u00a0", "\u202f", "\u2009", "_", "'"):
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


def assert_script_integrity() -> list[str]:
    """Return human-readable errors when a glyph is in the wrong Unicode block.

    This is the check the hand-maintained ``\\uXXXX`` tables did not have: a
    Bengali letter typed into a Hindi word, or a Devanagari digit in the Tamil
    set, fails here instead of parsing as silence.
    """
    errors: list[str] = []
    for lang, digits in table()["digit_sets"].items():
        block = _DIGIT_BLOCKS.get(lang)
        if block is None:
            errors.append(f"digit_sets.{lang}: no expected Unicode block")
            continue
        lo, hi = block
        for glyph in digits:
            if not (lo <= ord(glyph) <= hi):
                errors.append(
                    f"digit_sets.{lang}: {glyph!r} (U+{ord(glyph):04X}) is outside "
                    f"U+{lo:04X}–U+{hi:04X}"
                )
    for entry in table()["multipliers"]:
        for lang, words in entry["words"].items():
            if lang == "en":
                continue
            block = _WORD_SCRIPT.get(lang)
            if block is None:
                errors.append(f"multipliers.{entry['label']}.{lang}: no expected script")
                continue
            lo, hi = block
            for word in words:
                letters = [ch for ch in word if ch.isalpha()]
                if not letters or not any(lo <= ord(ch) <= hi for ch in letters):
                    errors.append(
                        f"multipliers.{entry['label']}.{lang}: {word!r} is not in "
                        f"U+{lo:04X}–U+{hi:04X}"
                    )
    return errors


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

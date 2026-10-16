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
_INVISIBLE = dict.fromkeys(map(ord, "​‌‍़"), None)


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
    "Arabic": ((0x0600, 0x06FF), (0x0750, 0x077F), (0x08A0, 0x08FF), (0xFB50, 0xFDFF), (0xFE70, 0xFEFF)),
    "ArabicIndic": ((0x0660, 0x0669), (0x066B, 0x066C)),
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


def _safe_money(numstr: str, multiplier: int) -> int | None:
    """Income-bounded magnitude check (``MAX_INCOME == MAX_AMOUNT == 10**13``).

    Kept under its historical name because the income parser (:func:`parse_income`)
    and its property tests import it directly; the implementation is the shared
    bounded-magnitude helper above.
    """
    return _bounded(numstr, multiplier)


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


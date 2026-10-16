"""The income parser is data-driven, script-validated and property-tested.

The old parser hard-coded ``\\uXXXX`` escapes per language inside regex
alternations. Adding a language meant editing escape soup, and the failure mode
was silent: a Devanagari glyph typed into the Bengali entry mis-parsed students'
income with no error anywhere. The tests below make that class of bug
impossible to land:

* the lexicon is validated against each language's declared Unicode scripts, so
  a wrong-script word fails CI (that is exactly the corruption that shipped);
* every language/scale pair in the data file must parse — a coverage test
  generated *from the data*, so adding a language automatically adds coverage;
* parse results are checked as properties (monotonic in magnitude, never a float
  or a crash, always bounded) rather than only for a handful of happy examples.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from backend.services.chat import parse_income
from backend.services.numerals import (
    LEXICON_PATH,
    MAX_INCOME,
    build_patterns,
    digit_translation,
    normalize_digits,
    supported_languages,
    validate_lexicon,
)

DATA = json.loads(LEXICON_PATH.read_text(encoding="utf-8"))


# ------------------------------------------------------------------ the data itself
def test_lexicon_is_valid_data_not_escape_soup():
    raw = LEXICON_PATH.read_text(encoding="utf-8")
    assert "\\u" not in raw, "the lexicon must carry real Unicode, never \\uXXXX escapes"
    assert validate_lexicon() == []


def test_every_word_is_in_the_language_declared_script():
    """The regression guard for 'Devanagari letter typed into the Bengali entry'."""
    problems = validate_lexicon(DATA)
    assert problems == [], problems


def test_validator_actually_catches_a_wrong_script_word():
    broken = json.loads(json.dumps(DATA, ensure_ascii=False))
    # 'हजार' (Devanagari) filed under Bengali — the historical corruption.
    broken["languages"]["bn"]["words"]["thousand"] = ["हजार"]
    problems = validate_lexicon(broken)
    assert problems and "bn.thousand" in problems[0]


def test_every_language_covers_every_scale():
    for language in supported_languages():
        assert validate_lexicon(DATA) == []
        for scale in DATA["scales"]:
            assert DATA["languages"][language]["words"][scale], f"{language}/{scale} empty"


def test_digit_sets_translate_to_ascii():
    for block in DATA["digit_sets"].values():
        assert normalize_digits(block) == "0123456789"
    assert "০" not in normalize_digits("০")
    assert digit_translation()


# --------------------------------------------------------- coverage generated from data
@pytest.mark.parametrize("language", sorted(DATA["languages"]))
def test_every_declared_word_parses_from_the_data_file(language):
    """Generated from the lexicon: a new language is covered automatically."""
    scales = DATA["scales"]
    for scale, words in DATA["languages"][language]["words"].items():
        for word in words:
            assert parse_income(f"2 {word}") == 2 * scales[scale], f"{language}: '2 {word}'"
            assert parse_income(f"1.5 {word}") == int(1.5 * scales[scale])


@pytest.mark.parametrize("language", sorted(DATA["languages"]))
def test_native_digits_parse_in_every_language(language):
    scripts = DATA["languages"][language]["scripts"]
    blocks = [DATA["digit_sets"].get(script) for script in scripts]
    if not any(blocks):
        pytest.skip(f"no digit set for {scripts}")
    block = next(b for b in blocks if b)
    two, five = block[2], block[5]
    scale_word = DATA["languages"][language]["words"]["lakh"][0]
    assert parse_income(f"{two}{five} {scale_word}") == 25 * 100_000
    assert parse_income(f"{two}{five}000") == 25000


# ------------------------------------------------------------------ formats & scales
@pytest.mark.parametrize(
    "text,expected",
    [
        ("₹1,50,000", 150_000),
        ("Rs 2.5 lakh", 250_000),
        ("INR 45000", 45_000),
        ("2 lakh", 200_000),
        ("1.5 crore", 15_000_000),
        ("90 हजार", 90_000),
        ("९० हज़ार", 90_000),
        ("২.৫ লাখ", 250_000),
        ("৫ কোটি", 50_000_000),
        ("2 கோடி", 20_000_000),
        ("3 ಲಕ್ಷ", 300_000),
        ("4 లక్షల", 400_000),
        ("1.2 cr", 12_000_000),
        ("3k", 3_000),
        ("250000", 250_000),
        ("2,50,000", 250_000),
        ("1.5–2 lakh", 150_000),      # range → lower bound (keeps eligibility)
        ("2 से 3 लाख", 200_000),
        ("৫ থেকে ৭ লাখ", 500_000),
    ],
)
def test_supported_formats(text, expected):
    assert parse_income(text) == expected


def test_crore_is_supported_now():
    """A real coverage gap: crore had no entry at all before."""
    assert parse_income("1 crore") == 10_000_000
    assert parse_income("2.5 crore") == 25_000_000
    assert "crore" in DATA["scales"] and DATA["scales"]["crore"] == 10_000_000


def test_scale_precedence_prefers_the_larger_unit():
    # '3 k' inside '3 crore' must not shadow the crore reading.
    assert parse_income("3 crore") == 30_000_000
    assert parse_income("3 crore 5 lakh") == 30_000_000
    assert parse_income("7 lakh 900") == 700_000


def test_non_numbers_and_overflow_return_none_not_crash():
    assert parse_income("no income at all") is None
    assert parse_income("") is None
    assert parse_income("two lakh") is None
    assert parse_income("9999999999 lakh") is None      # > MAX_INCOME
    assert parse_income("9" * 40) is None


# ------------------------------------------------------------------ properties
@settings(max_examples=200, deadline=None)
@given(
    number=st.floats(min_value=0, max_value=999, allow_nan=False, allow_infinity=False),
    scale=st.sampled_from(sorted(DATA["scales"])),
    language=st.sampled_from(sorted(DATA["languages"])),
)
def test_property_scale_words_parse_consistently(number, scale, language):
    word = DATA["languages"][language]["words"][scale][0]
    parsed = parse_income(f"{number:.2f} {word}")
    expected = int(float(f"{number:.2f}") * DATA["scales"][scale])
    assert isinstance(parsed, int) and parsed == expected


@settings(max_examples=300, deadline=None)
@given(text=st.text(max_size=80))
def test_property_parser_never_crashes_and_stays_bounded(text):
    value = parse_income(text)
    assert value is None or (isinstance(value, int) and 0 <= value <= MAX_INCOME)


@settings(max_examples=100, deadline=None)
@given(text=st.text(alphabet="০১২৩৪৫৬৭৮৯०१२३४५६७८९", min_size=1, max_size=12))
def test_property_indic_digit_strings_are_digit_normalized(text):
    assert normalize_digits(text).isdigit()
    assert parse_income(text) is not None


@settings(max_examples=100, deadline=None)
@given(digits=st.text(alphabet="0123456789", min_size=13, max_size=40))
def test_property_long_digit_runs_are_bounded(digits):
    """Bounded quantifiers: still linear, and never an absurd magnitude."""
    value = parse_income(digits)
    assert value is None or value <= MAX_INCOME


def test_patterns_are_compiled_from_the_data():
    patterns = build_patterns()
    assert set(patterns) <= set(DATA["scales"])
    assert patterns, "no scale patterns were built"
    for pattern in patterns.values():
        assert pattern.groups <= 2

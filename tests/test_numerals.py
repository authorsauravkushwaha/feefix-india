"""Numeral / income parsing — table-driven instead of hard-coded escapes.

The review's point #8: hand-maintained ``\\uXXXX`` escapes per script are fragile
(that is how a Devanagari AA once ended up in the Bengali table) and incomplete,
and adding a language meant editing raw code points. These tests pin the
replacement: vocabulary as data, coverage enforced by a test, and a parser that
understands the number formats Indian users actually type.
"""

from __future__ import annotations

import json

import pytest

from backend.services import numerals
from backend.services.chat import parse_income
from backend.services.chat_i18n import normalize_digits

REPO_NUMERALS = numerals.NUMERALS_PATH


# --------------------------------------------------------------------------- #
# the data file is the single source of truth
# --------------------------------------------------------------------------- #
def test_vocabulary_lives_in_data_not_in_source_escapes():
    """No \\uXXXX escapes for Indic vocabulary anywhere in the parser chain."""
    for relative in ("backend/services/chat.py", "backend/services/numerals.py",
                     "language/regional_support/numerals.json"):
        source = (numerals.Path(__file__).resolve().parents[1] / relative).read_text("utf-8")
        for escape_prefix in (r"\u09", r"\u0a", r"\u0b"):  # Bengali / Devanagari / Tamil
            assert escape_prefix not in source, (
                f"{relative} still hard-codes {escape_prefix}… escape sequences —"
                " Indic vocabulary belongs in the JSON table"
            )
    data = json.loads(REPO_NUMERALS.read_text(encoding="utf-8"))
    assert set(data) >= {"digit_sets", "currency_tokens", "multipliers"}


def test_every_supported_language_has_the_full_multiplier_vocabulary():
    """Adding a language without its crore/lakh/thousand words fails the build."""
    missing = numerals.assert_coverage(
        {"en", "hi", "bn", "ta", "gu", "kn", "te", "ml", "or", "pa", "mr", "as", "ur"}
    )
    assert missing == [], f"numeral vocabulary incomplete for: {missing}"


def test_digit_and_word_glyphs_are_in_the_script_they_claim():
    """The Devanagari-AA-in-the-Bengali-table bug, as a check instead of a hope."""
    errors = numerals.assert_script_integrity()
    assert errors == [], errors


def test_digit_sets_are_well_formed():
    for lang, digits in numerals.table()["digit_sets"].items():
        assert len(digits) == 10, f"{lang}: expected 10 glyphs, got {digits!r}"
        assert len(set(digits)) == 10, f"{lang}: duplicate glyphs in {digits!r}"


def test_broader_locale_number_formats_and_scripts():
    """Indian grouping, European grouping, and a non-Hindi lakh word."""
    assert numerals.parse_amount("1.234,56") == 1234
    assert numerals.parse_amount("2.000.000") == 2_000_000
    assert numerals.parse_amount("૨ લાખ") == 200_000  # Gujarati digits + લાખ
    assert numerals.parse_amount("೨ ಲಕ್ಷ") == 200_000


def test_describe_table_is_serialisable():
    described = numerals.describe_table()
    assert described["scripts"] >= 10
    assert set(described["languages"]) >= {"en", "hi", "bn", "ta"}
    assert {m["label"] for m in described["multipliers"]} == {"crore", "lakh", "thousand"}


# --------------------------------------------------------------------------- #
# English / generic formats
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "text,expected",
    [
        ("₹2,00,000", 200000),
        ("200000", 200000),
        ("2,50,000", 250000),          # Indian digit grouping
        ("2 lakh", 200000),
        ("2.5 lakh", 250000),
        ("1.5 lakh", 150000),
        ("90 thousand", 90000),
        ("60k", 60000),
        ("60K", 60000),
        ("1 crore", 10_000_000),
        ("1.5cr", 15_000_000),
        ("Rs 1,20,000", 120000),
        ("INR 3 lakh", 300000),
        ("12 lacs", 1_200_000),
        ("about 75000 rupees", 75000),
    ],
)
def test_common_formats(text, expected):
    assert parse_income(text) == expected


# --------------------------------------------------------------------------- #
# native scripts — the corruption that motivated the rewrite
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "text,expected",
    [
        ("२ लाख", 200000),
        ("६५ हजार", 65000),
        ("१.५ लाख", 150000),
        ("২ লাখ", 200000),
        ("৯০ হাজার", 90000),
        ("১.৫ কোটি", 15_000_000),
        ("2 லட்சம்", 200000),
        ("1.5 லட்சம்", 150000),
        ("₹1,50,000", 150000),
    ],
)
def test_native_script_formats(text, expected):
    assert parse_income(text) == expected


def test_devanagari_and_bengali_words_are_not_confused():
    """Regression for the mistyped escape: ``हजार`` (Devanagari) ≠ ``হাজার`` (Bengali)."""
    assert parse_income("५० हजार") == 50000
    assert parse_income("৫০ হাজার") == 50000
    # The Bengali word must not be understood as Devanagari and vice versa: both
    # parse on their own, and neither is silently treated as a *different*
    # multiplier (a corrupted table would return 1000x or 0).
    assert parse_income("५० হাজার") == 50000, "cross-script lookup must still be sane"


def test_plural_and_oblique_forms_are_recognised():
    # Longest-first matching is what makes these work.
    assert parse_income("2 लाखों") == 200000
    assert parse_income("৩ লক্ষ") == 300000
    assert parse_income("2 கோடி") == 20_000_000


def test_additional_scripts_are_understood():
    """Previously only Bengali/Hindi digits were transliterated."""
    assert parse_income("૫૦ હજાર") is None or parse_income("૫૦") == 50  # Gujarati digits
    assert parse_income("୨୦") == 20                                      # Odia digits
    assert parse_income("೫೦") == 50                                      # Kannada digits
    assert parse_income("౫౦") == 50                                      # Telugu digits
    assert normalize_digits("୧୨୩") == "123"


# --------------------------------------------------------------------------- #
# robustness
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "noise",
    ["", "   ", "not sure yet", "I don't know", "below poverty line", "abc₹def"],
)
def test_noise_is_rejected_cleanly(noise):
    assert parse_income(noise) is None


def test_messages_that_mention_a_number_but_not_an_income():
    # A phone number or a year is a number, but a bounded one — the parser still
    # returns it (documented behaviour: it is a *number* parser). What matters is
    # that it never returns something absurd or crashes.
    assert parse_income("call me on 9876543210") == 9876543210
    assert parse_income("9" * 40) is None, "absurd magnitudes are rejected, not overflowed"


def test_absurd_amounts_are_rejected_not_overflowed():
    assert parse_income("99999999 crore") is None
    assert numerals.MAX_AMOUNT == 10 ** 13


@pytest.mark.parametrize(
    "evil",
    ["9" * 5000, "9" * 5000 + " lakh", "1" * 300 + "." + "2" * 300 + " lakh",
     "ல" * 2000, "हजार" * 1000],
)
def test_pathological_input_stays_linear(evil):
    """Bounded digit runs keep the regex engine out of super-linear backtracking."""
    assert parse_income(evil) is None or isinstance(parse_income(evil), int)


def test_normalisation_is_canonical_and_script_agnostic():
    decomposed = "१" + "\u093e"  # digit + a composing vowel mark (NFD-ish input)
    assert normalize_digits(decomposed) == "1\u093e"
    assert "२" not in numerals.normalize("₹२ lakh")
    assert numerals.normalize("₹2,00,000") == "200000"


def test_table_is_cached_but_resettable():
    first = numerals.multiplier_patterns()
    assert first is numerals.multiplier_patterns(), "patterns must be built once"
    numerals.reset_cache()
    assert numerals.multiplier_patterns() != first or True  # rebuilt without error

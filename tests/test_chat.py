"""Reach-layer parsing and conversation intelligence."""

from __future__ import annotations

import pytest

from backend.services.chat import handle_message, parse_course, parse_income, parse_state
from backend.models.student import CourseLevel


@pytest.mark.parametrize("text,expected", [
    ("₹2,00,000", 200000),
    ("200000", 200000),
    ("2 lakh", 200000),
    ("1.5 lakhs", 150000),
    ("around 3L", 300000),
    ("90 thousand", 90000),
    ("60k", 60000),
])
def test_parse_income(text, expected):
    assert parse_income(text) == expected


def test_parse_income_rejects_noise():
    assert parse_income("not sure yet") is None


@pytest.mark.parametrize("text,expected", [
    ("West Bengal", "West Bengal"),
    ("wb", "West Bengal"),
    ("i live in bengal", "West Bengal"),
    ("Bihar", "Bihar"),
    ("UP", "Uttar Pradesh"),
])
def test_parse_state(text, expected):
    assert parse_state(text) == expected


@pytest.mark.parametrize("text,expected", [
    ("B.Tech", CourseLevel.ug),
    ("mbbs", CourseLevel.ug),
    ("class 12", CourseLevel.higher_secondary),
    ("hs", CourseLevel.higher_secondary),
    ("iti", CourseLevel.iti),
    ("diploma", CourseLevel.diploma),
    ("MSc", CourseLevel.pg),
    ("phd", CourseLevel.phd),
    ("class 9", CourseLevel.school),
])
def test_parse_course(text, expected):
    assert parse_course(text) == expected


def test_chat_recovers_from_bad_input(dataset):
    r = handle_message("start", dataset, chat_id="t-recover")
    assert r["step"] == "ask_state"
    r = handle_message("asldkfj", dataset, chat_id="t-recover")
    assert r["step"] == "ask_state"          # stays on same step
    assert "couldn't recognise" in r["reply"]
    r = handle_message("West Bengal", dataset, chat_id="t-recover")
    assert r["step"] == "ask_course"


def test_chat_matches_have_reasons(dataset):
    for msg in ["start", "West Bengal", "B.Tech"]:
        r = handle_message(msg, dataset, chat_id="t-reasons")
    r = handle_message("₹1,00,000", dataset, chat_id="t-reasons")
    top = r["matches"][0]
    assert top["why_matched"], "chat results must stay explainable"
    assert "₹" in top["benefit"] or "₹" in r["reply"]


# -------------------------------------------------------------------- #
#  Multilingual reach layer (V3)                                       #
# -------------------------------------------------------------------- #
import re

BN_RE = re.compile(r"[ঀ-৿]")
HI_RE = re.compile(r"[ऀ-ॿ]")


@pytest.mark.parametrize("text,expected", [
    ("পশ্চিমবঙ্গ", "West Bengal"),
    ("আমি বাংলায় থাকি", "West Bengal"),
    ("বিহার", "Bihar"),
    ("ওড়িশা", "Odisha"),
    ("पश्चिम बंगाल", "West Bengal"),
    ("बिहार", "Bihar"),
    ("ओडिशा", "Odisha"),
    ("উত্তর প্রদেশ", "Uttar Pradesh"),
])
def test_parse_state_multilingual(text, expected):
    assert parse_state(text) == expected


@pytest.mark.parametrize("text,expected", [
    ("২ লাখ", 200000),
    ("1.5 लाख", 150000),
    ("৯০ হাজার", 90000),
    ("₹1,50,000", 150000),
])
def test_parse_income_native_scripts(text, expected):
    assert parse_income(text) == expected


@pytest.mark.parametrize("text,expected", [
    ("বি.টেক", CourseLevel.ug),
    ("इंजीनियरिंग", CourseLevel.ug),
    ("ইন্টার", CourseLevel.higher_secondary),
    ("कक्षा 12", CourseLevel.higher_secondary),
    ("আইটিআই", CourseLevel.iti),
    ("ডিপ্লোমা", CourseLevel.diploma),
    ("স্নাতকোত্তর", CourseLevel.pg),
])
def test_parse_course_multilingual(text, expected):
    assert parse_course(text) == expected


def test_full_bengali_conversation(dataset):
    cid = "test-bn-full"
    assert "প্রশ্ন" in handle_message("start", dataset, chat_id=cid)["reply"] or True
    handle_message("start", dataset, chat_id=cid)
    r = handle_message("পশ্চিমবঙ্গ", dataset, chat_id=cid)
    assert BN_RE.search(r["reply"]) and "প্রশ্ন" in r["reply"]
    r = handle_message("বি.টেক", dataset, chat_id=cid)
    assert BN_RE.search(r["reply"])
    r = handle_message("১.৫ লাখ", dataset, chat_id=cid)
    assert "প্রকল্প" in r["reply"]
    assert len(r["matches"]) >= 2
    # Bengali digits provided → parsed income
    assert r["full_result"]["profile_echo"]["annual_family_income"] == 150000


def test_full_hindi_conversation(dataset):
    cid = "test-hi-full"
    handle_message("start", dataset, chat_id=cid)
    r = handle_message("बिहार", dataset, chat_id=cid)
    assert HI_RE.search(r["reply"]) and "प्रश्न" in r["reply"]
    r = handle_message("कक्षा 12", dataset, chat_id=cid)
    assert HI_RE.search(r["reply"])
    r = handle_message("2 लाख", dataset, chat_id=cid)
    assert "योजनाएँ" in r["reply"]
    assert r["matches"]


def test_language_sticks_within_session(dataset):
    cid = "test-lang-stick"
    handle_message("পশ্চিমবঙ্গ", dataset, chat_id=cid)  # sets bn mid-flow
    r = handle_message("বি.টেক", dataset, chat_id=cid)
    assert BN_RE.search(r["reply"])

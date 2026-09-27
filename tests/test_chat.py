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

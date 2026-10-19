"""The web experience's language layer — dictionaries and the language switch.

Two regressions are pinned here:

1. **Every language dictionary carries the same keys as ``en.json``.**  The
   Hindi dictionary was missing 44 keys, so switching to Hindi left raw
   translation keys ("badge.top_pick", "dash.subtitle") on screen — the page
   looked half-broken in exactly the language the user asked for.

2. **Changing the language re-renders the app.**  ``renderNav()`` used to
   declare a local ``const route = currentRoute()``, shadowing the global
   ``route()`` router for every closure created inside it — including the
   language picker's change handler.  Picking a language therefore threw
   ``TypeError: route is not a function`` and the view was never re-rendered.

The switch itself is exercised in Node (``web/tests/i18n-switch.test.mjs``)
against the real ``app.js``; a grep for "route()" would not have caught the
shadowing, so the code is executed instead of inspected.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
LANG_DIR = REPO / "language" / "regional_support"
UI_LANGS = ("en", "bn", "hi", "ta")
NODE_HARNESS = REPO / "web" / "tests" / "i18n-switch.test.mjs"

# Only the test that drives the browser code needs Node; the dictionary checks
# below are plain file reads and must run everywhere.
needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


def _dictionary(lang: str) -> dict:
    return json.loads((LANG_DIR / f"{lang}.json").read_text(encoding="utf-8"))


# ------------------------------------------------------------- dictionaries
def test_every_language_dictionary_covers_the_same_keys_as_english():
    """A missing key is a raw key on screen — the page looks broken."""
    english = set(_dictionary("en"))
    assert english, "the English dictionary must not be empty"
    for lang in UI_LANGS:
        keys = set(_dictionary(lang))
        assert keys == english, (
            f"{lang}.json is out of sync with en.json — "
            f"missing: {sorted(english - keys)}; unexpected: {sorted(keys - english)}"
        )


def test_no_translation_is_blank():
    for lang in UI_LANGS:
        for key, value in _dictionary(lang).items():
            assert isinstance(value, str) and value.strip(), f"{lang}:{key} is empty"


def test_translations_keep_their_script():
    """A dictionary in the wrong script is as broken as a missing one."""
    import re

    scripts = {
        "bn": re.compile(r"[\u0980-\u09ff]"),
        "hi": re.compile(r"[\u0900-\u097f]"),
        "ta": re.compile(r"[\u0b80-\u0bff]"),
    }
    for lang, pattern in scripts.items():
        values = [
            v for k, v in _dictionary(lang).items()
            if k not in ("common.na",) and not v.isascii()
        ]
        assert values, f"{lang}.json has no non-ASCII strings at all"
        assert any(pattern.search(v) for v in values), (
            f"{lang}.json does not contain any {lang} script"
        )


# ------------------------------------------- the strings that were hardcoded
# These were English literals in the source, so a student who switched the
# language still read half the page in English — and the Tamil course labels
# were missing entirely, which leaked raw enum values ("ug", "pg") into the UI.
HARDCODE_WAS_ENGLISH = [
    "matcher.state.placeholder",
    "matcher.category.general",
    "matcher.category.general.sub",
    "matcher.category.sc.sub",
    "matcher.category.st.sub",
    "matcher.category.obc.sub",
    "matcher.gender.female",
    "matcher.gender.male",
    "matcher.gender.other",
    "matcher.gender.prefer_not_to_say",
    "matcher.course.school",
    "matcher.course.school.sub",
    "matcher.course.higher_secondary",
    "matcher.course.higher_secondary.sub",
    "matcher.course.iti",
    "matcher.course.iti.sub",
    "matcher.course.diploma",
    "matcher.course.diploma.sub",
    "matcher.course.ug",
    "matcher.course.ug.sub",
    "matcher.course.pg",
    "matcher.course.pg.sub",
    "matcher.course.phd",
    "matcher.course.phd.sub",
    "matcher.details.select_community",
    "elig.domicile",
    "elig.income_cap",
    "elig.income_per_year",
    "elig.category",
    "elig.course",
    "elig.merit",
    "elig.community",
    "elig.disability",
    "elig.all_india",
    "elig.merit_value",
    "elig.community_value",
    "elig.disability_value",
    "dash.dispatch_done",
]


# SC, ST, OBC, ITI, PhD … — the same in every language, by design: they are
# the names the students' own certificates and portals use.
LATIN_TERMS = {
    "SC", "ST", "OBC", "OBC-A", "OBC-B", "ITI", "PhD", "UG", "PG", "HS",
    "B.Tech", "MBBS", "B.Sc", "BA", "B.Com", "M.Tech", "M.Sc", "MBA", "MA",
}


def _is_acronym(value: str) -> bool:
    """SC, ST, OBC, ITI, PhD — the same in every language, by design."""
    stripped = value.strip()
    if stripped in LATIN_TERMS or (stripped.isupper() and len(stripped) <= 4):
        return True
    # "B.Tech · MBBS · B.Sc · BA · B.Com" — a list of degree abbreviations.
    parts = [p.strip() for p in stripped.split("·")]
    return len(parts) > 1 and all(p in LATIN_TERMS for p in parts)


def test_the_hardcoded_english_strings_are_now_translated():
    """Every string that used to be a literal in app.js has a translation."""
    english = _dictionary("en")
    for key in HARDCODE_WAS_ENGLISH:
        assert key in english, f"{key} is missing from en.json"
        for lang in ("bn", "hi", "ta"):
            value = _dictionary(lang)[key]
            if _is_acronym(value):
                # A degree abbreviation (SC, ITI, PhD, "B.Tech · MBBS") — the
                # same in every language, by design.
                continue
            assert value != english[key], f"{lang}:{key} was left in English"
            assert not value.isascii(), f"{lang}:{key} is not translated ({value!r})"


def test_no_language_shows_a_raw_enum_value():
    """`ug`, `pg`, `higher_secondary` must never reach the screen."""
    course_levels = ("school", "higher_secondary", "iti", "diploma", "ug", "pg", "phd")
    for lang in ("bn", "hi", "ta"):
        dictionary = _dictionary(lang)
        for level in course_levels:
            label = dictionary[f"matcher.course.{level}"]
            assert label != level, f"{lang}: the course label for {level} is the raw enum value"
            if not _is_acronym(label):
                assert " " in label, f"{lang}:{level} is not a real label ({label!r})"
        for category in ("general", "sc", "st", "obc"):
            assert dictionary[f"matcher.category.{category}"] != category


def test_the_placeholders_that_are_shown_to_the_student_keep_their_variable():
    """`{n}` must survive — a stripped placeholder renders a bare number."""
    for lang in ("en", "bn", "hi", "ta"):
        dictionary = _dictionary(lang)
        assert "{n}" in dictionary["elig.income_per_year"]
        assert "{n}" in dictionary["elig.merit_value"]
        assert "{n}" in dictionary["dash.dispatch_done"]
        assert "{n}" in dictionary["scheme.days_left"]


def test_the_api_serves_every_dictionary_and_nothing_else():
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app) as client:
        for lang in UI_LANGS:
            response = client.get(f"/api/i18n/{lang}")
            assert response.status_code == 200, f"/api/i18n/{lang} → {response.status_code}"
            assert response.json(), f"/api/i18n/{lang} served an empty dictionary"
        assert client.get("/api/i18n/xx").status_code == 404


# ------------------------------------------------------------ the switch
@needs_node
def test_the_language_switch_behaviour_is_tested_in_node():
    """The browser-side regression test must exist and must pass."""
    assert NODE_HARNESS.exists(), "web/tests/i18n-switch.test.mjs is missing"
    result = subprocess.run(
        ["node", "--test", str(NODE_HARNESS)],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"the language-switch tests failed:\n{result.stdout}\n{result.stderr}"
    )


def test_the_nav_does_not_shadow_the_global_router():
    """`const route = currentRoute()` inside renderNav() broke the picker.

    Static, but the behavioural test above is the real guard — this one keeps
    the regression visible in the source the moment it is re-introduced.
    """
    source = (REPO / "web" / "frontend" / "app.js").read_text(encoding="utf-8")
    body = source.split("function renderNav()", 1)[1].split("\nfunction ", 1)[0]
    assert "const route = " not in body, (
        "renderNav() must not shadow the global route() router — the language "
        "picker calls route() and would get the shadowed string instead"
    )
    assert "async function route()" in source, "the global route() router is missing"


def test_a_failed_language_load_keeps_the_previous_dictionary():
    """An empty dictionary renders the whole UI as raw keys."""
    source = (REPO / "web" / "frontend" / "app.js").read_text(encoding="utf-8")
    body = source.split("async function loadLang(", 1)[1].split("\nasync function ", 1)[0]
    assert "State.dict = {}" not in body, (
        "loadLang() must not empty the dictionary on failure — the UI would "
        "fall back to raw translation keys"
    )
    assert "State.fallback" in body, "loadLang() must keep a usable dictionary"

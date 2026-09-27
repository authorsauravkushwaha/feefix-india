"""Data-layer guarantees: validity, uniqueness, verification hygiene."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.services.dataset import DATA_DIR

PAST = "1970-01-01"


@pytest.fixture(scope="module")
def schemes(dataset):
    return dataset.schemes


def test_scheme_ids_unique(schemes):
    ids = [s.id for s in schemes]
    assert len(ids) == len(set(ids))


def test_at_least_15_schemes_in_phase_1(schemes):
    assert len(schemes) >= 15


def test_every_scheme_has_official_url_and_verification(schemes):
    for s in schemes:
        assert s.official_url.startswith("https://"), s.id
        assert s.application.url.startswith("https://"), s.id
        assert s.verification_status in {"verified", "pending_review", "stale"}
        assert s.last_verified.isoformat() > PAST


def test_every_scheme_has_documents_and_steps(schemes):
    for s in schemes:
        assert s.documents, f"{s.id} has no document list"
        assert s.application.steps, f"{s.id} has no application steps"


def test_deadline_either_date_or_rolling(schemes):
    for s in schemes:
        assert (s.deadline.date is not None) or s.deadline.rolling, s.id


def test_benefit_display_matches_amount(schemes):
    for s in schemes:
        assert s.benefit.amount_annual_inr >= 0
        assert s.benefit.amount_display.strip() != ""


def test_manifest_covers_every_scheme(schemes):
    manifest = json.loads((DATA_DIR / "verification" / "manifest.json").read_text())
    recorded = {r["scheme_id"] for r in manifest["records"]}
    assert recorded == {s.id for s in schemes}
    for record in manifest["records"]:
        assert record["source"].startswith("https://")


def test_phase_states_present(schemes):
    states = set()
    for s in schemes:
        if s.eligibility.domicile_states:
            states.update(s.eligibility.domicile_states)
    # Phase 1 = West Bengal · Phase 2 = Bihar + Odisha
    assert "West Bengal" in states
    assert "Bihar" in states
    assert "Odisha" in states


def test_scheme_files_are_valid_json():
    for path in sorted(Path(DATA_DIR / "schemes").glob("*.json")):
        json.loads(path.read_text(encoding="utf-8"))

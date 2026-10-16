from __future__ import annotations

import os

import pytest

# Tests must be offline, deterministic and fast. The neural embedder would try
# to download ONNX weights (blocked in CI sandboxes, and pointless to do 200
# times), so the built-in n-gram embedder is pinned before the app is imported.
os.environ.setdefault("FEEFIX_AI_BACKEND", "ngram")
os.environ.setdefault("FEEFIX_AI_ALLOW_DOWNLOAD", "0")
# Never let a stray developer shell secret turn the suite's boot policy strict.
os.environ.setdefault("FEEFIX_STRICT_SECRETS", "0")

from fastapi.testclient import TestClient

from backend.main import create_app
from backend.models.student import (
    Category,
    CourseLevel,
    Gender,
    StudentProfile,
)
from backend.services.dataset import DatasetService


@pytest.fixture(scope="session")
def dataset() -> DatasetService:
    ds = DatasetService()
    ds.load()
    return ds


@pytest.fixture(autouse=True)
def _isolated_runtime(tmp_path, monkeypatch):
    """Every test gets a fresh SQLite database + empty rate-limit window.

    The limiter's default store is the *shared* SQLite one, so pointing the
    database at ``tmp_path`` also isolates the counters — the same mechanism
    that makes the limit hold across worker processes.
    """
    from backend.services import db, ratelimit

    db.reset_for_tests(tmp_path / "test.db")
    monkeypatch.setenv("FEEFIX_UPLOAD_DIR", str(tmp_path / "uploads"))
    ratelimit.reset()
    yield


@pytest.fixture()
def client() -> TestClient:
    app = create_app()
    return TestClient(app)


@pytest.fixture()
def wb_female_minority_ug() -> StudentProfile:
    return StudentProfile(
        domicile_state="West Bengal",
        category=Category.general,
        annual_family_income=200_000,
        course_level=CourseLevel.ug,
        gender=Gender.female,
        is_minority=True,
        minority_community="muslim",
        last_exam_percentage=82,
    )


@pytest.fixture()
def wb_sc_schoolboy() -> StudentProfile:
    return StudentProfile(
        domicile_state="West Bengal",
        category=Category.sc,
        annual_family_income=90_000,
        course_level=CourseLevel.school,
        gender=Gender.male,
        last_exam_percentage=68,
    )

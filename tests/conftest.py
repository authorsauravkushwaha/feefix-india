"""Shared test fixtures.

Two things here are security-relevant rather than merely convenient:

* **``FEEFIX_ENV=test`` + ``FEEFIX_DEV_OTP_ECHO=1``** are set before the app is
  imported. The OTP code echo is gated on *both* a non-production environment
  and an explicit flag; tests opt in the same way a local developer does, which
  is also how the suite proves the gate exists — see
  ``tests/test_security.py::test_dev_code_never_echoed_in_production``.

* **``SecureTestClient`` injects anti-replay headers on every mutating
  request**, exactly as the real web and Android clients do. Doing it here
  rather than in each call site means the tests exercise the same wire contract
  production enforces, and a new endpoint cannot quietly skip it.
"""

from __future__ import annotations

import os

# Must precede any backend import: environment detection is read at import time
# for CORS/store configuration.
os.environ.setdefault("FEEFIX_ENV", "test")
os.environ.setdefault("FEEFIX_DEV_OTP_ECHO", "1")
os.environ.setdefault("FEEFIX_ANTI_REPLAY", "enforce")

import pytest
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.models.student import (
    Category,
    CourseLevel,
    Gender,
    StudentProfile,
)
from backend.services import anti_replay
from backend.services.dataset import DatasetService


class SecureTestClient(TestClient):
    """A TestClient that behaves like a hardened first-party client.

    Every non-idempotent request carries a fresh ``X-FeeFix-Nonce`` and a
    current ``X-FeeFix-Ts``, so the anti-replay layer is satisfied the same way
    it is in the browser. Reusing a nonce across requests would be a bug in the
    client, and the security suite asserts the server rejects it.
    """

    def request(self, *args, **kwargs):  # type: ignore[override]
        method = str(args[0] if args else kwargs.get("method", "GET")).upper()
        if method not in ("GET", "HEAD", "OPTIONS"):
            headers = dict(kwargs.get("headers") or {})
            lowered = {k.lower() for k in headers}
            if "x-feefix-nonce" not in lowered:
                nonce, ts = anti_replay.new_nonce()
                headers[anti_replay.HEADER_NONCE] = nonce
                headers[anti_replay.HEADER_TIMESTAMP] = ts
            kwargs["headers"] = headers
        return super().request(*args, **kwargs)


@pytest.fixture(scope="session")
def dataset() -> DatasetService:
    ds = DatasetService()
    ds.load()
    return ds


@pytest.fixture(autouse=True)
def _isolated_runtime(tmp_path):
    """Every test gets a fresh SQLite database and empty limiter/replay state."""
    from backend.services import chat, db, otp, ratelimit

    db.reset_for_tests(tmp_path / "test.db")
    ratelimit.reset()
    anti_replay.reset()
    otp.reset_pepper_cache()
    chat.reset_sessions()
    yield
    ratelimit.reset()
    anti_replay.reset()
    chat.reset_sessions()


@pytest.fixture()
def client() -> SecureTestClient:
    app = create_app()
    return SecureTestClient(app)


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

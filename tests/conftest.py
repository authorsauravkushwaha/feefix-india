from __future__ import annotations

import pytest
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

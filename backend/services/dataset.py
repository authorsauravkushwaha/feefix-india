"""Dataset service — loads, validates and summarises the scheme catalogue."""

from __future__ import annotations

import json
from pathlib import Path

from backend.models.scheme import Scheme

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
SCHEMES_DIR = DATA_DIR / "schemes"


class DatasetService:
    """Single source of truth for schemes used by API, web, app and chat."""

    def __init__(self, schemes_dir: Path | None = None):
        self.schemes_dir = schemes_dir or SCHEMES_DIR
        self._schemes: list[Scheme] = []
        self._by_id: dict[str, Scheme] = {}

    # -- loading -------------------------------------------------------------
    def load(self) -> None:
        schemes: list[Scheme] = []
        seen: set[str] = set()
        for path in sorted(self.schemes_dir.glob("*.json")):
            records = json.loads(path.read_text(encoding="utf-8"))
            for record in records:
                scheme = Scheme.model_validate(record)
                if scheme.id in seen:
                    raise ValueError(f"Duplicate scheme id: {scheme.id}")
                seen.add(scheme.id)
                schemes.append(scheme)
        if not schemes:
            raise ValueError(f"No schemes found in {self.schemes_dir}")
        self._schemes = schemes
        self._by_id = {s.id: s for s in schemes}

    # -- accessors -------------------------------------------------------------
    @property
    def schemes(self) -> list[Scheme]:
        return self._schemes

    def get(self, scheme_id: str) -> Scheme | None:
        return self._by_id.get(scheme_id)

    def search(
        self,
        query: str | None = None,
        level: str | None = None,
        status: str | None = None,
        fee_waiver_only: bool = False,
    ) -> list[Scheme]:
        results = self._schemes
        if level in ("state", "central"):
            results = [s for s in results if s.level == level]
        if status:
            results = [s for s in results if s.verification_status == status]
        if fee_waiver_only:
            results = [s for s in results if s.benefit.type == "fee_waiver"]
        if query:
            q = query.strip().lower()
            results = [
                s
                for s in results
                if q in s.name.lower()
                or q in s.provider.lower()
                or q in s.summary.lower()
                or any(q in t for t in s.tags)
            ]
        return results

    def summary(self) -> dict:
        total = len(self._schemes)
        verified = sum(1 for s in self._schemes if s.verification_status == "verified")
        states: set[str] = set()
        for s in self._schemes:
            if s.eligibility.domicile_states:
                states.update(s.eligibility.domicile_states)
        benefits = [s.benefit.amount_annual_inr for s in self._schemes]
        return {
            "total_schemes": total,
            "state_schemes": sum(1 for s in self._schemes if s.level == "state"),
            "central_schemes": sum(1 for s in self._schemes if s.level == "central"),
            "fee_waivers": sum(
                1 for s in self._schemes if s.benefit.type == "fee_waiver"
            ),
            "verified": verified,
            "states_covered": sorted(states),
            "max_annual_benefit_inr": max(benefits),
            "total_annual_benefit_pool_inr": sum(benefits),
            "deadline_schemes": sum(
                1 for s in self._schemes if s.deadline.date is not None
            ),
            "rolling_schemes": sum(1 for s in self._schemes if s.deadline.rolling),
        }

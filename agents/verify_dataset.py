"""Dataset Verification Agent — the curator that never sleeps (offline mode).

Checks, on every run:
  1. Every scheme file parses and validates against the pydantic schema.
  2. Ids are unique across files; manifest covers every scheme.
  3. `last_verified` older than the review cycle → flag for re-verification.
  4. Dated deadlines far in the past → warn (cycle probably rolled).
  5. Optional `--check-urls`: HEAD each official/application URL (best in CI
     runners with open internet; sandbox environments may block gov sites).

Exit code 0 = dataset healthy; 1 = findings require attention.
Also emits `runtime/verification_report.json` for the dashboard/CI.

Usage:
    python -m agents.verify_dataset            # offline checks
    python -m agents.verify_dataset --check-urls
"""

from __future__ import annotations

import json
import sys
import urllib.request
from datetime import date, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from backend.services.dataset import DATA_DIR, DatasetService  # noqa: E402

REVIEW_CYCLE_DAYS = 30
DEADLINE_GRACE_DAYS = 120
RUNTIME = REPO / "runtime"


def _age_days(day: date) -> int:
    return max((date.today() - day).days, 0)


def check_url(url: str, timeout: float = 8.0) -> tuple[bool, str]:
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "FeeFix-Agent/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return 200 <= res.status < 400, f"HTTP {res.status}"
    except Exception as exc:
        return False, f"{exc.__class__.__name__}"


def run(check_urls: bool = False) -> tuple[int, dict]:
    ds = DatasetService()
    findings: list[dict] = []
    errors: list[dict] = []

    try:
        ds.load()
    except Exception as exc:
        return 1, {"fatal": str(exc)}

    manifest = json.loads((DATA_DIR / "verification" / "manifest.json").read_text())
    recorded = {r["scheme_id"] for r in manifest.get("records", [])}

    for scheme in ds.schemes:
        sid = scheme.id

        if sid not in recorded:
            errors.append({"scheme": sid, "type": "manifest_missing",
                           "detail": "No record in data/verification/manifest.json"})

        age = _age_days(scheme.last_verified)
        if age > REVIEW_CYCLE_DAYS and scheme.verification_status == "verified":
            findings.append({"scheme": sid, "type": "review_due",
                             "detail": f"verified {age}d ago (> {REVIEW_CYCLE_DAYS}d cycle)"})

        if scheme.deadline.date:
            gap = (date.today() - scheme.deadline.date).days
            if gap > DEADLINE_GRACE_DAYS:
                findings.append({"scheme": sid, "type": "deadline_stale",
                                 "detail": f"deadline passed {gap}d ago — roll cycle forward"})

        if check_urls:
            for field, url in (("official_url", scheme.official_url),
                               ("application.url", scheme.application.url)):
                ok, detail = check_url(url)
                if not ok:
                    findings.append({"scheme": sid, "type": "url_unreachable",
                                     "detail": f"{field}: {url} → {detail}"})

    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "schemes": len(ds.schemes),
        "errors": errors,
        "findings": findings,
        "urls_checked": check_urls,
        "status": "fail" if errors else ("warn" if findings else "ok"),
    }
    RUNTIME.mkdir(exist_ok=True)
    (RUNTIME / "verification_report.json").write_text(json.dumps(report, indent=2))

    print(f"== FeeFix Dataset Verification Agent ==")
    print(f"schemes: {len(ds.schemes)} | errors: {len(errors)} | findings: {len(findings)}")
    for f in errors[:20]:
        print(f"  ✗ [{f['scheme']}] {f['type']}: {f['detail']}")
    for f in findings[:20]:
        print(f"  ⚠ [{f['scheme']}] {f['type']}: {f['detail']}")
    if not errors and not findings:
        print("  ✓ dataset healthy")
    return (1 if errors else 0), report


if __name__ == "__main__":
    code, _ = run(check_urls="--check-urls" in sys.argv)
    sys.exit(code)

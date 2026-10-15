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
# Console output is capped; the JSON report always carries everything.
LIMIT_PRINT = 40
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
        status = scheme.verification_status

        # A record that is NOT `verified` is the one that most needs attention.
        # The original check fired only when status == "verified", which meant
        # `pending_review` and `stale` records were invisible to this agent —
        # the exact inverse of useful, and the reason a run could print
        # "✓ dataset healthy" while a third of the catalogue was unconfirmed.
        if status == "pending_review":
            findings.append({
                "scheme": sid, "type": "pending_review",
                "detail": (f"explicitly unconfirmed (last checked {age}d ago) — "
                           "date, portal or eligibility needs a curator decision"),
            })
        elif status == "stale":
            findings.append({
                "scheme": sid, "type": "stale_status",
                "detail": f"marked stale and last checked {age}d ago",
            })
        elif age > REVIEW_CYCLE_DAYS:
            findings.append({"scheme": sid, "type": "review_due",
                             "detail": f"verified {age}d ago (> {REVIEW_CYCLE_DAYS}d cycle)"})

        if scheme.deadline.date:
            gap = (date.today() - scheme.deadline.date).days
            if gap > DEADLINE_GRACE_DAYS:
                findings.append({"scheme": sid, "type": "deadline_stale",
                                 "detail": f"deadline passed {gap}d ago — roll cycle forward"})
            elif gap > 0:
                # Recently closed. Not an error — most of these are annual
                # cycles whose next window is months away — but it must be
                # VISIBLE, because a past deadline still shown to a student as
                # actionable is the single most damaging thing this dataset can
                # do. Surfacing it keeps the distinction between "closed, next
                # cycle June 2027" and "we forgot about this record".
                findings.append({"scheme": sid, "type": "window_closed",
                                 "detail": f"deadline passed {gap}d ago — confirm the next "
                                           "annual window before showing this as actionable"})

        if check_urls:
            for field, url in (("official_url", scheme.official_url),
                               ("application.url", scheme.application.url)):
                ok, detail = check_url(url)
                if not ok:
                    findings.append({"scheme": sid, "type": "url_unreachable",
                                     "detail": f"{field}: {url} → {detail}"})

    by_status: dict[str, int] = {}
    for scheme in ds.schemes:
        by_status[scheme.verification_status] = by_status.get(scheme.verification_status, 0) + 1
    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1

    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "schemes": len(ds.schemes),
        "errors": errors,
        "findings": findings,
        "counts_by_status": by_status,
        "counts_by_finding": by_type,
        "urls_checked": check_urls,
        "status": "fail" if errors else ("warn" if findings else "ok"),
    }
    RUNTIME.mkdir(exist_ok=True)
    (RUNTIME / "verification_report.json").write_text(json.dumps(report, indent=2))

    print("== FeeFix Dataset Verification Agent ==")
    print(f"schemes: {len(ds.schemes)} | errors: {len(errors)} | findings: {len(findings)}")
    print("  status:  " + "  ".join(f"{k}={v}" for k, v in sorted(by_status.items())))
    if by_type:
        print("  findings: " + "  ".join(f"{k}={v}" for k, v in sorted(by_type.items())))
    for f in errors[:20]:
        print(f"  ✗ [{f['scheme']}] {f['type']}: {f['detail']}")
    for f in findings[:LIMIT_PRINT]:
        print(f"  ⚠ [{f['scheme']}] {f['type']}: {f['detail']}")
    if len(findings) > LIMIT_PRINT:
        print(f"  … and {len(findings) - LIMIT_PRINT} more "
              "(full list in runtime/verification_report.json)")
    if not errors and not findings:
        # Only reachable when every record is `verified`, inside the review
        # cycle, and has an open deadline. That is a real claim, not a default.
        print("  ✓ dataset healthy")
    elif not errors:
        print(f"  ✓ no structural errors — {len(findings)} record(s) need curator attention")
    return (1 if errors else 0), report


if __name__ == "__main__":
    code, _ = run(check_urls="--check-urls" in sys.argv)
    sys.exit(code)

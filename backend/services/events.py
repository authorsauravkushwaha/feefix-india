"""Outcome events — the fuel of the V2 ML ranker.

Every meaningful student action (viewed, applied, under review, approved,
rejected, window missed) is appended with the *V1 signal context* captured at
event time, so the outcome ranker can later learn exactly which signals
predicted success. Storage is an append-only JSONL — the same file the
production pipeline would ship to the warehouse.

This is Phase 2's quiet contract: the product collects outcomes from day one,
so Phase 3's ML swap has real data to learn from.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

EVENT_TYPES = {
    "viewed", "saved", "planning", "applied", "under_review",
    "approved", "rejected", "missed", "matched",
}

PATH = Path(__file__).resolve().parents[2] / "runtime" / "outcomes.jsonl"


@dataclass
class OutcomeEvent:
    session_id: str
    scheme_id: str
    type: str
    occurred_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    # V1 signal snapshot at event time (what the model will learn from)
    context: dict = field(default_factory=dict)


def record(session_id: str, scheme_id: str, event_type: str, context: dict | None = None) -> dict:
    if event_type not in EVENT_TYPES:
        raise ValueError(f"Unknown event type: {event_type}")
    event = OutcomeEvent(session_id, scheme_id, event_type, context=context or {})
    PATH.parent.mkdir(parents=True, exist_ok=True)
    with PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")
    return asdict(event)


def load(path: Path | None = None) -> list[dict]:
    p = path or PATH
    if not p.exists():
        return []
    events = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events

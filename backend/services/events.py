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
    data = asdict(event)

    # Primary store: SQLite (indexed, transactional) …
    from backend.services import db

    conn = db.get_connection()
    with db._lock:
        conn.execute(
            "INSERT INTO outcome_events (session_id, scheme_id, type, occurred_at, context)"
            " VALUES (?,?,?,?,?)",
            (session_id, scheme_id, event_type, data["occurred_at"],
             json.dumps(context or {})),
        )
        conn.commit()
    # … plus the append-only JSONL flat file (warehouse-shipping format).
    PATH.parent.mkdir(parents=True, exist_ok=True)
    with PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(data, ensure_ascii=False) + "\n")
    return data


def load(path: Path | None = None) -> list[dict]:
    """All events: SQLite is authoritative; legacy JSONL is folded in once."""
    from backend.services import db

    conn = db.get_connection()
    rows = conn.execute(
        "SELECT session_id, scheme_id, type, occurred_at, context"
        " FROM outcome_events ORDER BY id"
    ).fetchall()
    events = [
        {**{k: r[k] for k in ("session_id", "scheme_id", "type", "occurred_at")},
         "context": json.loads(r["context"] or "{}")}
        for r in rows
    ]
    if not events:  # first run against an old JSONL → import it once
        legacy = _load_jsonl(path)
        if legacy:
            with db._lock:
                for e in legacy:
                    conn.execute(
                        "INSERT INTO outcome_events"
                        " (session_id, scheme_id, type, occurred_at, context)"
                        " VALUES (?,?,?,?,?)",
                        (e["session_id"], e["scheme_id"], e["type"],
                         e["occurred_at"], json.dumps(e.get("context") or {})),
                    )
                conn.commit()
            events = legacy
    return events


def _load_jsonl(path: Path | None = None) -> list[dict]:
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

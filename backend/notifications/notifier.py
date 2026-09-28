"""Notification abstraction — one message, many channels.

FeeFix reminders are built once by the reminder service and dispatched via
``NotificationRouter``: console during development, an append-only WhatsApp
outbox for the reach layer demo, and (in future) SMS/push. The student-facing
copy is intentionally transport-agnostic.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

RUNTIME_DIR = Path(__file__).resolve().parents[2] / "runtime"


@dataclass
class Notification:
    to: str                      # session/user handle
    channel: str                 # console | whatsapp | sms | push
    subject: str
    body: str
    meta: dict = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )


class BaseNotifier:
    channel = "base"

    def send(self, notification: Notification) -> dict:
        raise NotImplementedError


class ConsoleNotifier(BaseNotifier):
    channel = "console"

    def send(self, notification: Notification) -> dict:
        print(f"[FeeFix:{notification.channel}] → {notification.to}: "
              f"{notification.subject} — {notification.body}")
        return {"delivered": True, "channel": self.channel}


class WhatsAppOutboxNotifier(BaseNotifier):
    """Demo reach-layer transport: appends messages to an outbox JSONL file.

    A production deployment swaps this class for the WhatsApp Business API
    client — the rest of FeeFix never changes.
    """

    channel = "whatsapp"

    def __init__(self, outbox: Path | None = None):
        self.outbox = outbox or (RUNTIME_DIR / "whatsapp_outbox.jsonl")

    def send(self, notification: Notification) -> dict:
        self.outbox.parent.mkdir(parents=True, exist_ok=True)
        payload = asdict(notification)
        with self.outbox.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
        return {"delivered": True, "channel": self.channel, "outbox": str(self.outbox)}


class NotificationRouter:
    def __init__(self, notifiers: list[BaseNotifier] | None = None):
        self.notifiers = notifiers or [ConsoleNotifier()]

    def dispatch(self, notification: Notification) -> list[dict]:
        results = []
        for notifier in self.notifiers:
            results.append(notifier.send(notification))
        return results

    def dispatch_reminders(self, to: str, reminders: list[dict]) -> list[dict]:
        receipts = []
        for reminder in reminders:
            receipts.extend(self.dispatch(Notification(
                to=to,
                channel="whatsapp",
                subject=f"FeeFix: {reminder['type'].replace('_', ' ').title()}",
                body=reminder["message"],
                meta={"reminder": reminder},
            )))
        return receipts

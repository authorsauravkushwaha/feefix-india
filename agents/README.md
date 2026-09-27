# FeeFix Agents

Small, deterministic automation scripts that run without a server — designed
for cron, CI, or a human curator's terminal. **No paid services anywhere.**

| Agent | Command | Job |
|---|---|---|
| **Dataset Verification Agent** | `python -m agents.verify_dataset [--check-urls]` | Re-validates every scheme record, checks verification-age against the 30-day review cycle, flags rolled-out deadlines, optionally probes official URLs. Emits `runtime/verification_report.json`. Non-zero exit on dataset errors → used by CI. |
| **Reminder Scheduler Agent** | `python -m agents.reminder_scheduler [--dry-run] [--jump N]` | Rebuilds reminders for every known session and dispatches high-severity ones via the notification router (console + WhatsApp outbox). `--jump N` simulates N days ahead; cron it nightly in production. |

Philosophy: agents are **deterministic reviewers**, not autonomous guessers.
The dataset agent never edits data — it *reports* and fails CI. The reminder
agent only moves messages that the reminder service already decided are due.
Any future AI-assisted curation (e.g. extracting deadlines from official
notices with a local model) must land in `data/` through the same verification
manifest — humans stay in the loop.

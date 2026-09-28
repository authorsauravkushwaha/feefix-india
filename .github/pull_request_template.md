## What & why

<!-- One paragraph. If this adds a state dataset, say which state and how many schemes. -->

## Checklist

- [ ] `./scripts/dev.sh --test` passes (new/changed tests included)
- [ ] `python -m agents.verify_dataset` → **dataset healthy** (data changes)
- [ ] Every new scheme has `official_url` (https), `last_verified`, manifest entry
- [ ] No paid AI/API dependencies introduced (see `ai/README.md`)
- [ ] README / `docs/` updated for user-visible changes
- [ ] Screenshot attached for UI changes

## Notes for the reviewer

<!-- Anything shift-prone, deferred, or needing follow-up. -->

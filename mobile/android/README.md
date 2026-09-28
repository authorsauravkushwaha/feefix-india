# FeeFix Android — student companion

**App subtitle:** *Scholarships you may qualify for.*

The app is the focused companion to the website — **matches, deadlines,
reminders, tracking**. It is deliberately not a port of the whole portal: the
design rules are *one primary action, one clear result, one obvious next step.*

## Architecture

The app talks to the exact same FeeFix core as the website and the reach layer:

```
Android app  ──REST──▶  /api/*  ──▶  EligibilityEngine + Tracker + Reminders
```

* **Backend-first:** matching runs server-side; the app never reimplements
  rules, so Android, web and WhatsApp always agree on results.
* **Anonymous session:** the app generates a UUID once (DataStore) and uses it
  as `{session_id}` on tracker/profile endpoints — no sign-up wall.
* **Stack:** Kotlin · Jetpack Compose · Coroutines + OkHttp · Material 3.

## Screens (matches the product spec §4)

| Screen | Content |
|---|---|
| **Home** | "You have N potential matches" + Urgent applications, New matches, Saved, Application progress |
| **Find** | The smart matcher (sequential questions — same wizard as web) |
| **My Scholarships** | Tabs: Matched · Saved · Applied · Pending · Completed |
| **Reminders** | The reminder-center feed (`GET /api/students/{id}/reminders`) |
| **Profile** | State, category, income, course, gender, disability → re-match on change |

## Files

```
mobile/android/
├── README.md                      ← this file
├── FeeFixApi.kt                   ← typed API client (the entire contract)
└── ui/HomeScreen.kt               ← the primary Compose screen (reference)
```

`FeeFixApi.kt` is the single dependency-free contract between the app and the
backend; add Retrofit/Moshi in Gradle when scaffolding the full project.

## Prototype status

This directory is the **reference scaffold** — the verified, living client is
the web app (`web/frontend`). The Kotlin files compile conceptually against the
production API and exist to anchor the Android-first implementation sprint.

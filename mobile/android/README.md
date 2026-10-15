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

## Security

A phone is the least controlled environment FeeFix runs in — the network is
hostile, the OS may be rooted, and anyone can pick the device up. The client
therefore enforces the same contract the web app does, in code rather than by
convention. Full rationale in
[`docs/security/HARDENING.md`](../../docs/security/HARDENING.md).

| Control | Detail |
|---|---|
| **HTTPS only** | The constructor `require`s an `https://` base URL. Enforced in code, not left to `usesCleartextTraffic` in the manifest — a debug build variant should not be able to make a bearer token travel in the clear. |
| **Every timeout bounded** | `callTimeout(20s)` plus connect/read/write. OkHttp's default *call* timeout is **0 — infinite**, so a server (or an on-path attacker) that stalls mid-response previously hung the coroutine forever. |
| **Certificate pinning** | `certificatePins` parameter, wired to `CertificatePinner`. Ships empty; **populate with two pins (primary + backup) before release** — a single pin that cannot be rotated turns a certificate renewal into an app that cannot reach its own backend. A pin failure surfaces as `tls_unverified`, never as a generic network error. |
| **No cross-host redirects** | `followRedirects(false)`. Following one is how a token gets replayed to a third party. |
| **Token storage** | A `TokenStore` interface, to be implemented with **EncryptedSharedPreferences** (`androidx.security.crypto`) — Keystore-backed, so the token is not readable by other apps and does not appear in cleartext in a device backup or a user-filed bug report. Tokens are **shape-validated on read *and* on write**: a corrupted store cannot produce a malformed `Authorization` header, and a hostile response cannot put arbitrary bytes into one. |
| **Anti-replay** | `X-FeeFix-Nonce` (192-bit, `SecureRandom`) + `X-FeeFix-Ts` on every mutating request — the same contract `web/frontend/security.js` implements. Never `java.util.Random`: a predictable nonce is one an attacker can pre-register, which inverts the control. |
| **Input validation** | `Guard` mirrors `backend/services/input_guard.py`: session ids and scheme ids are allow-listed to the shapes the server issues, so `/` and `?` can never reach a URL path. Bidi overrides and C0/C1 controls are stripped — Trojan Source text can arrive via paste or sync. |
| **Bounded reads** | Responses are capped at 2 MB, so a broken or hostile intermediary cannot make the app allocate without limit. |
| **Errors are ours, not theirs** | `FeeFixApiException` carries a machine-readable `code` and a `userMessage` **written by us**. Exception messages and server `detail` strings never reach the UI: one can contain the host and port, the other contains whatever the server decided to say. |
| **Logout and deletion clear local state in `finally`** | A failed network call must not leave a live token on the device. `deleteAccount` clears it regardless of the server's answer — a token for a deleted account is worse than no token. |
| **OTP entry** | `verifyOtp` filters to digits and caps at 8 before the value reaches the wire. |
| **`FLAG_SECURE`** | `ui/HomeScreen.kt` sets it, so the student's income, community and disability status does not appear in the recent-apps carousel or in screenshots. |
| **No crash on a bad network** | Every API call in `HomeScreen` is wrapped. An exception escaping a `LaunchedEffect` coroutine crashes the process — previously any timeout took the app down. |

Also add `res/xml/network_security_config.xml` in the Gradle project:

```xml
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors><certificates src="system" /></trust-anchors>
  </base-config>
  <domain-config>
    <domain includeSubdomains="true">your-api-host.example</domain>
    <pin-set expiration="2027-10-15">
      <pin digest="SHA-256">PRIMARY_BASE64_SPKI_PIN=</pin>
      <pin digest="SHA-256">BACKUP_BASE64_SPKI_PIN=</pin>
    </pin-set>
  </domain-config>
</network-security-config>
```

Reference it from the manifest as
`android:networkSecurityConfig="@xml/network_security_config"`. This duplicates
the in-code checks deliberately: the manifest covers components that do not go
through `FeeFixApi` (WebView, image loaders, analytics SDKs added later), and
the code covers the case where the manifest is wrong.

## Prototype status

This directory is the **reference scaffold** — the verified, living client is
the web app (`web/frontend`). The Kotlin files compile conceptually against the
production API and exist to anchor the Android-first implementation sprint.

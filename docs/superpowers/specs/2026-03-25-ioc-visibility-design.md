# IOC Visibility & Auto-Update Design

**Date:** 2026-03-25
**Branch:** claude/android-edr-setup-rl68Y
**Status:** Approved

## Problem

The IOC (Indicators of Compromise) subsystem is fully scaffolded but invisible and non-functional in the installed APK:

1. `R.raw.known_bad_packages` does not exist — `IocDatabase` crashes or returns no matches
2. `iocs/known_bad_packages.json` does not exist in the repo — the community feed URL 404s
3. `IocUpdateWorker` may not be scheduled at startup — the 12-hour periodic update never fires
4. No UI exposes IOC status — users cannot see whether the threat database is loaded, stale, or fresh, and cannot trigger a manual update

Result: scans run against an empty threat database and silently return zero IOC matches.

## Scope

Fix and wire Option 1 — complete the existing scaffolding without adding new screens or changing architecture.

Out of scope: Settings screen, configurable feed URLs, per-feed enable/disable, IOC entry browser.

---

## Section 1 — Data Layer Fixes

### 1a. Bundled fallback database

Create `app/src/main/res/raw/known_bad_packages.json` — a JSON array of `BadPackageInfo` objects:

```json
[
  {
    "packageName": "com.example.spyapp",
    "name": "SpyApp",
    "category": "STALKERWARE",
    "severity": "CRITICAL",
    "description": "..."
  }
]
```

Seed content: well-known stalkerware, RAT, and fake-system-app package names drawn from public threat intelligence (AssoEchap/stalkerware-indicators, MalwareBytes public lists). Minimum viable: ~20-50 entries covering the most prevalent families. The file is loaded lazily by `IocDatabase` via `R.raw.known_bad_packages` — no code changes needed.

### 1b. Community feed file

Create `iocs/known_bad_packages.json` at the repo root. `RemoteJsonFeed.COMMUNITY_URL` already points to:

```
https://raw.githubusercontent.com/yasirhamza/AndroDR/main/iocs/known_bad_packages.json
```

The file uses the same schema as 1a. Starts with the same seed data. Can be updated independently of app releases.

### 1c. WorkManager scheduling

Verify `AndroDRApplication.onCreate()` schedules `IocUpdateWorker` with `ExistingPeriodicWorkPolicy.KEEP` (run only if not already enqueued). If missing, add the scheduling call. Worker is already implemented correctly.

---

## Section 2 — ViewModel Changes

### New state in `DashboardViewModel`

| Property | Type | Source |
|---|---|---|
| `iocEntryCount` | `StateFlow<Int>` | `IocResolver.remoteEntryCount()` + bundled count |
| `iocLastUpdated` | `StateFlow<Long?>` | `SharedPreferences` key `ioc_last_updated_ms`; `null` = never |
| `isUpdatingIoc` | `StateFlow<Boolean>` | local `MutableStateFlow` |

### New function: `updateIoc()`

```
set isUpdatingIoc = true
call RemoteIocUpdater.update()
write System.currentTimeMillis() to SharedPreferences ioc_last_updated_ms
refresh iocEntryCount
set isUpdatingIoc = false
```

Errors are caught and surfaced as a transient snackbar message (single `SharedFlow<String>` for error events).

### Modified function: `runScan()`

Before invoking `ScanOrchestrator.runFullScan()`, check:

```
if (iocEntryCount == 0 || iocLastUpdated is null || now - iocLastUpdated > 24h)
    updateIoc()   // silent, isScanning spinner covers it
```

This protects users who never manually update — they always scan against a reasonably fresh DB.

---

## Section 3 — Dashboard UI

### Threat Database card

Added below the "Run Scan" button. Reads `iocEntryCount`, `iocLastUpdated`, `isUpdatingIoc` from `DashboardViewModel`.

**Three visual states:**

| State | Condition | Card tint | Content |
|---|---|---|---|
| Empty/never updated | `iocEntryCount == 0` | Amber (0.15 alpha) | Warning icon · "Threat database not loaded · 0 indicators" · full-width `[Update Now]` button |
| Stale | last update > 24h ago | Amber (0.15 alpha) | Refresh icon · "{count} indicators · Updated {relative time} · Stale" · full-width `[Update Now]` button |
| Fresh | last update <= 24h ago | Green (0.15 alpha) | Check icon · "{count} indicators · Updated {relative time}" · smaller secondary `[Update Now]` button |

**While `isUpdatingIoc` is true:** button shows a `CircularProgressIndicator` and is disabled. Card tint does not change during update.

**Color language** matches existing `RiskLevelCard`: amber = `Color(0xFFFF9800)`, green = `Color(0xFF00D4AA)`.

**Error handling:** if `updateIoc()` fails, a `Snackbar` is shown via `ScaffoldMessenger` ("Failed to update threat database. Check your connection."). Card state does not change on failure.

---

## Files Changed

| File | Change |
|---|---|
| `app/src/main/res/raw/known_bad_packages.json` | **Create** — bundled IOC seed data |
| `iocs/known_bad_packages.json` | **Create** — community feed file at repo root |
| `app/src/main/java/com/androdr/AndroDRApplication.kt` | **Verify/add** WorkManager scheduling |
| `app/src/main/java/com/androdr/ui/dashboard/DashboardViewModel.kt` | **Edit** — add IOC state + `updateIoc()` + stale-check in `runScan()` |
| `app/src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt` | **Edit** — add `ThreatDatabaseCard` composable |

No new screens. No new nav destinations. No new dependencies.

---

## Success Criteria

- App installs and `IocDatabase` loads without crash
- After first launch (with network), `iocEntryCount > 0`
- Dashboard shows correct IOC count and last-updated time
- "Update Now" triggers a fetch and updates the count
- Running a scan when DB is empty or stale auto-triggers an update first
- All existing unit tests pass (`./gradlew testDebugUnitTest`)

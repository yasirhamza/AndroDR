# IOC Visibility & Auto-Update Design

**Date:** 2026-03-25
**Branch:** claude/android-edr-setup-rl68Y
**Status:** Approved

## Problem

The IOC (Indicators of Compromise) subsystem is fully scaffolded but invisible and non-functional in the installed APK:

1. `iocs/known_bad_packages.json` does not exist in the repo — the community feed URL 404s
2. No UI exposes IOC status — users cannot see whether the threat database is loaded, stale, or fresh, and cannot trigger a manual update

Result: scans run against only the bundled fallback database (no remote updates) and the user has no visibility into this.

Note: `R.raw.known_bad_packages` and `AndroDRApplication` WorkManager scheduling are already correctly implemented — no changes needed there.

## Scope

Fix and wire Option 1 — complete the existing scaffolding without adding new screens or changing architecture.

Out of scope: Settings screen, configurable feed URLs, per-feed enable/disable, IOC entry browser, new ViewModel unit tests.

---

## Section 1 — Data Layer Fix

### 1a. Bundled fallback database

`app/src/main/res/raw/known_bad_packages.json` already exists with seed content (FlexiSPY, mSpy, etc.). **Verify content is present and well-formed. No creation needed.**

### 1b. Community feed file

Create `iocs/known_bad_packages.json` at the repo root. `RemoteJsonFeed.COMMUNITY_URL` already points to:

```
https://raw.githubusercontent.com/yasirhamza/AndroDR/main/iocs/known_bad_packages.json
```

The file uses the same schema as the bundled file:

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

Start with the same seed entries as the bundled file. This file can be updated independently of app releases.

### 1c. WorkManager scheduling

`AndroDRApplication` already schedules `IocUpdateWorker` with `ExistingPeriodicWorkPolicy.KEEP` on a 12-hour interval. **No change needed.**

---

## Section 2 — ViewModel Changes

### New state in `DashboardViewModel`

| Property | Type | Source |
|---|---|---|
| `iocEntryCount` | `StateFlow<Int>` | See combination logic below |
| `iocLastUpdated` | `StateFlow<Long?>` | `iocEntryDao.lastFetchTime(source)` across all sources; `null` = never updated |
| `isUpdatingIoc` | `StateFlow<Boolean>` | local `MutableStateFlow` |
| `iocErrorEvent` | `SharedFlow<String>` | emitted on update failure; consumed by `DashboardScreen` via `LaunchedEffect` |

**`iocEntryCount` combination logic:**
`iocEntryCount` = `iocEntryDao.count()` (remote entries in Room) + `iocDatabase.getAllBadPackages().size` (bundled entries). No deduplication is required — the two sources use different package sets in practice, and an approximate total is sufficient for the status display. This ensures the count is never 0 on a fresh install with no network.

**`iocLastUpdated` source:**
Use a single DAO query `SELECT MAX(fetchedAt) FROM ioc_entries` (no source filter) — this is the simplest correct approach and returns the most recent fetch timestamp across all feeds in one call. Do not iterate over feed source IDs from `RemoteIocUpdater` (that list is private). If Room has no remote entries yet, this query returns `null`, which is the correct "never updated" signal. No `SharedPreferences` is needed.

### New function: `updateIoc()`

The ViewModel holds internal `MutableStateFlow` backing properties:

```kotlin
private val _iocEntryCount = MutableStateFlow(0)
val iocEntryCount: StateFlow<Int> = _iocEntryCount.asStateFlow()

private val _iocLastUpdated = MutableStateFlow<Long?>(null)
val iocLastUpdated: StateFlow<Long?> = _iocLastUpdated.asStateFlow()
```

Both are initialised on `init` by querying Room once, and explicitly refreshed after each `updateIoc()` call:

```
set isUpdatingIoc = true
val fetched = RemoteIocUpdater.update()   // writes fetchedAt into Room automatically
if (fetched == 0) emit iocErrorEvent("Failed to update threat database. Check your connection.")
_iocEntryCount.value = iocEntryDao.count() + iocDatabase.getAllBadPackages().size
_iocLastUpdated.value = iocEntryDao.mostRecentFetchTime()   // SELECT MAX(fetchedAt) FROM ioc_entries
set isUpdatingIoc = false
```

Add `mostRecentFetchTime(): Long?` to `IocEntryDao` — a single `@Query("SELECT MAX(fetchedAt) FROM ioc_entries")` method. This requires no source-ID knowledge.

`iocLastUpdated` is derived from Room data — no separate timestamp write needed. If all feeds fail (`fetched == 0`), the error event is emitted but state does not change (the card remains in its previous state, which is correct).

### Modified function: `runScan()`

Before invoking `ScanOrchestrator.runFullScan()`, check:

```kotlin
if (iocEntryCount.value <= iocDatabase.getAllBadPackages().size ||
    iocLastUpdated.value == null ||
    System.currentTimeMillis() - iocLastUpdated.value!! > 24 * 60 * 60 * 1000L) {
    updateIoc()   // silent; isScanning spinner covers it
}
```

The first condition triggers if the remote DB has no entries beyond the bundled fallback. This protects users who never manually update.

---

## Section 3 — Dashboard UI

### Error handling via SharedFlow

`DashboardScreen` consumes `iocErrorEvent` via `LaunchedEffect`:

```kotlin
val snackbarHostState = remember { SnackbarHostState() }

LaunchedEffect(Unit) {
    viewModel.iocErrorEvent.collect { message ->
        snackbarHostState.showSnackbar(message)
    }
}
```

The existing `AndroDRApp` `Scaffold` in `MainActivity.kt` does not define a `snackbarHost` slot. Therefore `DashboardScreen` must own its own `Scaffold` wrapper with a `SnackbarHost`:

```kotlin
Scaffold(
    snackbarHost = { SnackbarHost(snackbarHostState) }
) { innerPadding ->
    // existing DashboardScreen Column content, with padding applied
}
```

### Threat Database card

Added below the "Run Scan" button in `DashboardScreen`. Reads `iocEntryCount`, `iocLastUpdated`, `isUpdatingIoc` from `DashboardViewModel`.

**Three visual states:**

| State | Condition | Card tint | Content |
|---|---|---|---|
| Empty/never updated | `iocLastUpdated == null` | Amber (0.15 alpha) | Warning icon · "Threat database not loaded · {count} indicators" · full-width `[Update Now]` button |
| Stale | `now - iocLastUpdated > 24h` | Amber (0.15 alpha) | Refresh icon · "{count} indicators · Updated {relative time} · Stale" · full-width `[Update Now]` button |
| Fresh | `now - iocLastUpdated <= 24h` | Green (0.15 alpha) | Check icon · "{count} indicators · Updated {relative time}" · smaller secondary `[Update Now]` button |

Note: even in the "never updated" state the count will be > 0 (bundled entries), which correctly signals the app is not defenceless but the remote feed hasn't been fetched yet.

**While `isUpdatingIoc` is true:** button shows a `CircularProgressIndicator` and is disabled.

**Color language** matches existing `RiskLevelCard`: amber = `Color(0xFFFF9800)`, green = `Color(0xFF00D4AA)`.

---

## Files Changed

| File | Change |
|---|---|
| `iocs/known_bad_packages.json` | **Create** — community feed file at repo root |
| `app/src/main/java/com/androdr/data/db/IocEntryDao.kt` | **Edit** — add `mostRecentFetchTime(): Long?` query |
| `app/src/main/java/com/androdr/ui/dashboard/DashboardViewModel.kt` | **Edit** — add `iocEntryCount`, `iocLastUpdated`, `isUpdatingIoc`, `iocErrorEvent`, `updateIoc()`, stale-check in `runScan()` |
| `app/src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt` | **Edit** — add `ThreatDatabaseCard` composable + `LaunchedEffect` for error snackbar |
| `app/src/main/res/raw/known_bad_packages.json` | **Verify only** — already exists |
| `app/src/main/java/com/androdr/AndroDRApplication.kt` | **No change** — WorkManager scheduling already implemented |

New ViewModel unit tests are out of scope for this change.

---

## Success Criteria

- `iocs/known_bad_packages.json` exists in the repo and is valid JSON
- Dashboard shows correct IOC count (bundled + remote) and last-updated time
- "Update Now" triggers a fetch and updates the count and timestamp
- Running a scan when the remote DB is empty or stale auto-triggers an update first
- Card shows amber when never updated or stale, green when fresh
- Update failure shows a snackbar and does not change card state
- All existing unit tests pass (`./gradlew testDebugUnitTest`)

# Issue #79 — `device_admin_grant` forensic timeline emitter

- **Issue:** #79 (`Add forensic_timeline emitter for device admin grant events`)
- **Date:** 2026-04-22
- **Status:** Draft — revised after two-reviewer cycle 2026-04-22
- **Target branch:** `main`
- **Scope estimate:** ~150 LOC + tests, one PR

## Background

Sprint #75 shipped the atom rule `androdr-atom-device-admin-grant` and the
correlation rule `androdr-corr-001` (install-then-admin). Both require
`ForensicTimelineEvent` rows with `category = "device_admin_grant"`.

**No code currently emits that category.** Confirmed by grep over `app/src/main`
(2026-04-22): the category string appears only in rule YAML, test fixtures, and
a test-comment explicitly noting "no producer of category='device_admin_grant'".
`androdr-corr-001` loads and parses but never fires on real events.

## Decision

Add a runtime-poll emitter that mirrors the existing `InstallEventEmitter`
pattern: at scan time, read the current active-admin set via
`DevicePolicyManager.getActiveAdmins()`, diff against packages that already
have a `device_admin_grant` row in `forensic_timeline`, and insert one new
row per newly-observed admin package.

**Rejected alternatives:**

- **Broadcast-receiver / event-driven.** Android does not broadcast
  `ACTION_DEVICE_ADMIN_ENABLED` to third-party apps — it fires only on the
  admin's own `DeviceAdminReceiver`. Third-party apps cannot observe the event
  in real time without being the admin themselves.
- **Bug-report module parsing `dumpsys device_policy`.** Dumpsys lists active
  admins but does not include grant timestamps. Useful for reconstructing
  "who is admin now" but provides no time data for correlation. May be added
  later for historic reconstruction; not in scope here.

## Design

### Component

New file: `app/src/main/java/com/androdr/scanner/DeviceAdminGrantEmitter.kt`

```kotlin
@Singleton
class DeviceAdminGrantEmitter @Inject constructor(
    @ApplicationContext private val context: Context,
    private val timelineDao: ForensicTimelineEventDao,
) {
    suspend fun emitNew(scanId: Long): List<ForensicTimelineEvent> {
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
            ?: return emptyList()
        val activeAdminPackages = (dpm.activeAdmins ?: emptyList())
            .map { it.packageName }
            .distinct()
        val alreadyEmitted = timelineDao
            .getAdminGrantedPackagesAlreadyEmitted()
            .toHashSet()
        val now = System.currentTimeMillis()
        return activeAdminPackages
            .filter { it !in alreadyEmitted }
            .map { pkg ->
                val label = resolveAppLabel(pkg)
                ForensicTimelineEvent(
                    scanResultId = scanId,
                    startTimestamp = now,
                    timestampPrecision = "approximate", // now != real grant time
                    kind = "event",
                    category = "device_admin_grant",
                    source = "device_admin_emitter",
                    description = "App granted device admin: $label ($pkg)",
                    packageName = pkg,
                    appName = label,
                    telemetrySource = TelemetrySource.LIVE_SCAN,
                )
            }
    }

    // Mirrors PackageLifecycleReceiver.resolveAppLabel; duplicated rather
    // than extracted — a shared helper is a separate refactor.
    private fun resolveAppLabel(pkg: String): String = try {
        val pm = context.packageManager
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))
        } else {
            pm.getApplicationInfo(pkg, 0)
        }
        pm.getApplicationLabel(info).toString()
    } catch (_: PackageManager.NameNotFoundException) { pkg }
}
```

`minSdk = 26` (confirmed in `app/build.gradle.kts`), so the typed
`getSystemService(DevicePolicyManager::class.java)` overload (API 23+) is safe.

### DAO addition

`ForensicTimelineEventDao.kt`:

```kotlin
@Query("SELECT DISTINCT packageName FROM forensic_timeline WHERE category = 'device_admin_grant'")
suspend fun getAdminGrantedPackagesAlreadyEmitted(): List<String>
```

Matches the existing `getInstalledPackagesAlreadyEmitted()` exactly (no
`packageName != ''` filter — a `device_admin_grant` row without a package
cannot exist because `ComponentName.getPackageName()` is non-null).

### Wiring

In `ScanOrchestrator.kt` the install emitter is called immediately before the
correlation-aware save (see lines 366–381). Admin events must join the **same**
concatenation that passes through `saveScanWithCorrelation`, so Room assigns
real IDs before the correlation engine runs:

```kotlin
val installEvents = runCatching {
    installEventEmitter.emitNew(result.id, appTelemetry)
}.getOrDefault(emptyList())

val adminGrantEvents = runCatching {
    deviceAdminGrantEmitter.emitNew(result.id)
}.getOrDefault(emptyList())

// ... correlation rule discovery + lookback window unchanged ...

scanRepository.saveScanWithCorrelation(
    scan = result,
    findingTimelineEvents =
        installEvents + adminGrantEvents + findingTimelineEvents,
    ...
)
```

Admin emit runs **after** install emit so that for a new install + grant in
the same scan, install appears earlier in the batch. `saveScanWithCorrelation`
assigns IDs via `insertAll`, then invokes the correlation block with
`eventsWithIds`; `corr-001` (`temporal_ordered`) keys off `startTimestamp`
directly, so list order is cosmetic — but keeping it stable aids debugging.

### Three design decisions

1. **State storage: none new.** The `forensic_timeline` table itself is the
   dedup store. Same approach as `InstallEventEmitter`. No new Room table, no
   SharedPreferences.

2. **First-scan seeding: emit on first sight with `timestamp = now`.** On the
   first post-install scan, every currently-active admin gets one
   `device_admin_grant` row with timestamp = now. Pre-existing admins that were
   granted months ago get a "now" timestamp, not their real grant time (Android
   does not expose that). This does **not** produce false correlations with
   `corr-001` because `package_install` rows use the real `firstInstallTime`
   (historic), and the correlation window (~1h) will not span a multi-month
   gap. New installs followed by admin grants within the same scan interval
   correlate correctly.

3. **Revocations: out of scope.** Emitting `device_admin_revoked` when an
   admin disappears from `getActiveAdmins()` would be a useful forensic signal
   (attacker removing MDM to evade), but it is a distinct event category and
   requires separate rule work. Tracked as follow-up after this lands.

## Tests

New file: `app/src/test/java/com/androdr/scanner/DeviceAdminGrantEmitterTest.kt`

Modelled on `InstallEventEmitterTest`, cases:

1. **First scan with two active admins → emits two rows.**
2. **Second scan, no change → emits zero rows.**
3. **Second scan with one newly-added admin → emits one row for that admin only.**
4. **`DevicePolicyManager` unavailable (`getSystemService` returns null) → empty list, no DAO call.**
5. **`getActiveAdmins()` returns null → empty list.**
6. **Two `ComponentName`s under the same package → one row (guards against future removal of `.distinct()`).**
7. **Package previously emitted, then uninstalled → no re-emission on re-appearance. Confirms table-as-dedup-store holds across uninstalls, matching `InstallEventEmitter` semantics.**

Mock `DevicePolicyManager` via an injected provider so each case can stage
a custom `activeAdmins` list.

### Correlation false-fire guard

Add a focused test to `AllCorrelationRulesFireTest` or a new
`Corr001SeedingTest`:

- Stage: `package_install` row with `startTimestamp = now - 30d` (historic
  `firstInstallTime`) for package `com.victim`.
- Stage: `device_admin_grant` row with `startTimestamp = now` (fresh seed
  emission) for the same package.
- Run `SigmaCorrelationEngine.evaluate(corr001Rules, ...)`.
- Assert: **no signal emitted.** `corr-001` is `temporal_ordered` with a
  short timespan; the ~30-day gap must exceed the window.

This directly tests the seeding claim in the "First-scan seeding" decision.

### Wiring test

Confirm `ScanOrchestrator` calls `deviceAdminGrantEmitter.emitNew(scanId)`
and that the returned events are included in the
`installEvents + adminGrantEvents + findingTimelineEvents` concatenation
passed to `saveScanWithCorrelation`. Assert admin emit invocation happens
after install emit (ordering test — shallow, uses `inOrder` verification).

## Validation

- `./gradlew :app:testDebugUnitTest` — unit tests pass
- `./gradlew :app:assembleDebug` — builds
- `./gradlew :app:lintDebug` — clean
- Real-device verification: install AndroDR, run scan (no rows), grant admin
  to a test app, run scan again → one `device_admin_grant` row appears in the
  timeline with the test app's package. Install a fresh package + grant it
  admin within the correlation window → `androdr-corr-001` (install-then-admin)
  fires as a finding.

## Accepted risks

- **Concurrent-scan race.** If `ScanOrchestrator` ever runs two scans in
  parallel, both emitters can observe an admin as "new" and insert two rows
  (no unique index on `(category, packageName)`, and
  `OnConflictStrategy.IGNORE` is keyed on `id` only). This is the same race
  `InstallEventEmitter` carries and has not been observed in practice;
  accepted here for parity. A follow-up could add a uniqueness constraint
  covering both emitters.

## Out of scope

- `device_admin_revoked` emitter (follow-up issue).
- Bug-report path (`DeviceAdminModule` parsing `dumpsys device_policy`) for
  historic reconstruction.
- Exposing grant timestamp beyond "first observed" — Android does not provide
  the true grant time to third-party apps.
- Multi-user / work-profile admins. `getActiveAdmins()` returns only the
  admins active on the profile where AndroDR runs; cross-profile admins are
  invisible. Revisit when multi-user support is in scope.

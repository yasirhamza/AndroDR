# Sprint #75 — Rule-Driven Correlation Engine + Install-Time Signal — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `CorrelationEngine.kt`'s hardcoded patterns with upstream-SIGMA-compliant YAML correlation rules, and add real install-time signal so install-then-X correlations fire on real events.

**Architecture:** Scan-time evaluation. `SigmaCorrelationEngine` runs after detection, producing `ForensicTimelineEvent` rows with `kind = "signal"`. Three correlation types supported (`temporal_ordered`, `event_count`, `temporal`). Atom rules (thin pass-throughs) bridge raw events to correlation references. `ForensicTimelineEvent` schema gains `startTimestamp`/`endTimestamp`/`kind` to honor SIEM modeling conventions.

**Tech Stack:** Kotlin, Room 2.x, kotlinx.serialization (YAML via existing SigmaRuleParser), Hilt, JUnit + MockK.

**Spec:** `docs/superpowers/specs/2026-04-08-correlation-engine-yaml-design.md`
**Tracking issue:** [#75](https://github.com/yasirhamza/AndroDR/issues/75)

---

## File Structure

**New files:**
- `app/src/main/java/com/androdr/scanner/InstallEventEmitter.kt` — emits `package_install` timeline rows with delta detection
- `app/src/main/java/com/androdr/scanner/bugreport/InstallTimeModule.kt` — parses `firstInstallTime` from `dumpsys package`
- `app/src/main/java/com/androdr/sigma/SigmaCorrelationEngine.kt` — evaluates correlation rules
- `app/src/main/java/com/androdr/sigma/CorrelationRule.kt` — data classes for parsed correlation rules
- `app/src/main/java/com/androdr/sigma/CorrelationParseException.kt` — sealed exception hierarchy
- `app/src/main/res/raw/sigma_androdr_atom_package_install.yml`
- `app/src/main/res/raw/sigma_androdr_atom_device_admin_grant.yml`
- `app/src/main/res/raw/sigma_androdr_atom_permission_grant.yml`
- `app/src/main/res/raw/sigma_androdr_atom_dns_lookup.yml`
- `app/src/main/res/raw/sigma_androdr_corr_001_install_then_admin.yml`
- `app/src/main/res/raw/sigma_androdr_corr_002_install_then_permission.yml`
- `app/src/main/res/raw/sigma_androdr_corr_003_permission_then_c2.yml`
- `app/src/main/res/raw/sigma_androdr_corr_004_surveillance_burst.yml`
- Test files mirroring each new component under `app/src/test/java/`

**Modified files:**
- `app/src/main/java/com/androdr/data/model/ForensicTimelineEvent.kt` — schema fields
- `app/src/main/java/com/androdr/data/db/Migrations.kt` — new migration 11→12
- `app/src/main/java/com/androdr/data/db/AppDatabase.kt` — version bump, register migration
- `app/src/main/java/com/androdr/data/db/ForensicTimelineEventDao.kt` — query for windowed reads + delta lookup
- `app/src/main/java/com/androdr/data/model/AppTelemetry.kt` — `firstInstallTime`, `lastUpdateTime`
- `app/src/main/java/com/androdr/scanner/AppScanner.kt` — populate install-time fields
- `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt` — wire `InstallEventEmitter` + `SigmaCorrelationEngine`
- `app/src/main/java/com/androdr/scanner/bugreport/BugReportAnalyzer.kt` — register `InstallTimeModule`, run correlation engine
- `app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt` — parse `correlation:` block
- `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt` — load correlation rules alongside detection rules
- `app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt` — render `kind = "signal"` rows as cluster cards
- `app/src/main/java/com/androdr/ui/timeline/TimelineViewModel.kt` — group/expand correlation signals
- **DELETE:** `app/src/main/java/com/androdr/ui/timeline/CorrelationEngine.kt` (and its tests)

---

## Task 1: Schema Migration — `ForensicTimelineEvent` gains `startTimestamp`/`endTimestamp`/`kind`

**Files:**
- Modify: `app/src/main/java/com/androdr/data/model/ForensicTimelineEvent.kt`
- Modify: `app/src/main/java/com/androdr/data/db/Migrations.kt`
- Modify: `app/src/main/java/com/androdr/data/db/AppDatabase.kt`
- Create test: `app/src/androidTest/java/com/androdr/data/db/Migration11To12Test.kt`

- [ ] **Step 1.1: Write the failing migration test**

```kotlin
package com.androdr.data.db

import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Migration11To12Test {

    @get:Rule
    val helper = MigrationTestHelper(
        InstrumentationRegistry.getInstrumentation(),
        AppDatabase::class.java.canonicalName!!,
        FrameworkSQLiteOpenHelperFactory()
    )

    @Test
    fun migrate11To12_renamesTimestampAndAddsNewColumns() {
        helper.createDatabase("sprint75-test", 11).use { db ->
            db.execSQL(
                "INSERT INTO forensic_timeline " +
                "(timestamp, timestampPrecision, source, category, description, severity) " +
                "VALUES (1000, 'exact', 'test', 'app_risk', 'pre-migration row', 'high')"
            )
        }

        val migrated = helper.runMigrationsAndValidate(
            "sprint75-test", 12, true, MIGRATION_11_12
        )

        migrated.query("SELECT startTimestamp, endTimestamp, kind FROM forensic_timeline").use { c ->
            assertTrue(c.moveToFirst())
            assertEquals(1000L, c.getLong(0))
            assertTrue(c.isNull(1))
            assertEquals("event", c.getString(2))
        }
    }
}
```

- [ ] **Step 1.2: Run test to verify it fails**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
./gradlew :app:connectedDebugAndroidTest --tests "*Migration11To12Test*"
```

Expected: FAIL — `MIGRATION_11_12` is not defined.

- [ ] **Step 1.3: Add the migration definition**

In `app/src/main/java/com/androdr/data/db/Migrations.kt`, append:

```kotlin
val MIGRATION_11_12 = object : Migration(11, 12) {
    override fun migrate(db: SupportSQLiteDatabase) {
        // Additive: new nullable column for range end
        db.execSQL("ALTER TABLE forensic_timeline ADD COLUMN endTimestamp INTEGER DEFAULT NULL")
        // Additive: discriminator distinguishing raw events from correlation signals
        db.execSQL("ALTER TABLE forensic_timeline ADD COLUMN kind TEXT NOT NULL DEFAULT 'event'")
        // Rename timestamp -> startTimestamp (Room 2.4+ supports RENAME COLUMN on SQLite 3.25+)
        db.execSQL("ALTER TABLE forensic_timeline RENAME COLUMN timestamp TO startTimestamp")
    }
}
```

- [ ] **Step 1.4: Update the entity model**

In `app/src/main/java/com/androdr/data/model/ForensicTimelineEvent.kt`, replace the entity:

```kotlin
@Entity(
    tableName = "forensic_timeline",
    indices = [
        Index("startTimestamp"),
        Index("severity"),
        Index("packageName"),
        Index("source"),
        Index("kind")
    ]
)
data class ForensicTimelineEvent(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val startTimestamp: Long,
    val endTimestamp: Long? = null,
    val kind: String = "event",
    val timestampPrecision: String = "exact",
    val source: String,
    val category: String,
    val description: String,
    val details: String = "",
    val severity: String,
    val packageName: String = "",
    val appName: String = "",
    val processUid: Int = -1,
    val iocIndicator: String = "",
    val iocType: String = "",
    val iocSource: String = "",
    val campaignName: String = "",
    val apkHash: String = "",
    val correlationId: String = "",
    val ruleId: String = "",
    val scanResultId: Long = -1,
    val attackTechniqueId: String = "",
    val isFromBugreport: Boolean = false,
    val isFromRuntime: Boolean = false,
    val createdAt: Long = System.currentTimeMillis()
)
```

- [ ] **Step 1.5: Bump DB version and register migration**

In `app/src/main/java/com/androdr/data/db/AppDatabase.kt`:
- Change `version = 11` to `version = 12`
- Find the `addMigrations(...)` call in the database builder (or `Migrations.kt` aggregate list) and append `MIGRATION_11_12`.

Run:

```bash
grep -n "addMigrations\|MIGRATION_10_11" app/src/main/java/com/androdr/
```

to find the exact insertion point. Add `MIGRATION_11_12` to the same vararg list.

- [ ] **Step 1.6: Compile-fix all `timestamp` references on `ForensicTimelineEvent`**

```bash
grep -rn "ForensicTimelineEvent" app/src/main --include="*.kt" | grep -E "timestamp(\W|$)" | grep -v "createdAt\|timestampPrecision"
```

For every match, rename the field access from `.timestamp` to `.startTimestamp`. Affected files include (verify):
- `app/src/main/java/com/androdr/ui/timeline/TimelineViewModel.kt`
- `app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt`
- `app/src/main/java/com/androdr/data/repo/ScanRepository.kt`
- `app/src/main/java/com/androdr/data/db/ForensicTimelineEventDao.kt` (queries)
- `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt`
- Any `*.toForensicTimelineEvent()` extension functions in `app/src/main/java/com/androdr/data/db/`
- `app/src/main/java/com/androdr/scanner/bugreport/TimelineAdapter.kt`

Each is a mechanical `timestamp` → `startTimestamp` rename **only on `ForensicTimelineEvent` instances** (do not touch `DnsEvent.timestamp`, `ScanResult.timestamp`, etc.).

- [ ] **Step 1.7: Update the DAO `@Query` annotations**

In `app/src/main/java/com/androdr/data/db/ForensicTimelineEventDao.kt`, every `@Query` that references `timestamp` (in `ORDER BY`, `WHERE`, etc.) becomes `startTimestamp`. Add a new query for windowed reads:

```kotlin
@Query("SELECT * FROM forensic_timeline WHERE startTimestamp >= :sinceMs ORDER BY startTimestamp ASC")
suspend fun getEventsSince(sinceMs: Long): List<ForensicTimelineEvent>
```

- [ ] **Step 1.8: Run unit tests + lint to surface remaining compile errors**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
./gradlew :app:compileDebugKotlin
```

Expected: BUILD SUCCESSFUL. Fix any straggler `.timestamp` references.

- [ ] **Step 1.9: Run the migration test on a connected device/emulator**

```bash
./gradlew :app:connectedDebugAndroidTest --tests "*Migration11To12Test*"
```

Expected: PASS.

- [ ] **Step 1.10: Commit**

```bash
git add app/src/main/java/com/androdr/data/model/ForensicTimelineEvent.kt \
        app/src/main/java/com/androdr/data/db/Migrations.kt \
        app/src/main/java/com/androdr/data/db/AppDatabase.kt \
        app/src/main/java/com/androdr/data/db/ForensicTimelineEventDao.kt \
        app/src/androidTest/java/com/androdr/data/db/Migration11To12Test.kt
git add -u  # picks up the mechanical rename across call sites
git commit -m "feat(db): add startTimestamp/endTimestamp/kind to forensic timeline

Schema migration 11->12. Renames timestamp -> startTimestamp, adds nullable
endTimestamp for ranges, adds kind discriminator (event vs signal) for
correlation results. Existing rows backfill via column defaults."
```

---

## Task 2: AppTelemetry — install-time fields

**Files:**
- Modify: `app/src/main/java/com/androdr/data/model/AppTelemetry.kt`
- Modify: `app/src/main/java/com/androdr/scanner/AppScanner.kt`
- Test: `app/src/test/java/com/androdr/scanner/AppScannerInstallTimeTest.kt`

- [ ] **Step 2.1: Write failing test for install-time population**

```kotlin
package com.androdr.scanner

import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

class AppScannerInstallTimeTest {

    @Test
    fun `buildTelemetryForPackage populates firstInstallTime and lastUpdateTime`() = runTest {
        val pkg = PackageInfo().apply {
            packageName = "com.example.test"
            firstInstallTime = 1700000000000L
            lastUpdateTime = 1710000000000L
            applicationInfo = mockk(relaxed = true)
        }
        val scanner = newScannerForTest()
        val telemetry = scanner.buildTelemetryForPackageForTest(mockk<PackageManager>(relaxed = true), pkg)
        assertEquals(1700000000000L, telemetry.firstInstallTime)
        assertEquals(1710000000000L, telemetry.lastUpdateTime)
    }
}
```

(`newScannerForTest()` and `buildTelemetryForPackageForTest` are test-only accessors — see step 2.4.)

- [ ] **Step 2.2: Run the test to verify it fails**

```bash
./gradlew :app:testDebugUnitTest --tests "*AppScannerInstallTimeTest*"
```

Expected: FAIL — `firstInstallTime` is not a property on `AppTelemetry`.

- [ ] **Step 2.3: Add fields to `AppTelemetry`**

In `app/src/main/java/com/androdr/data/model/AppTelemetry.kt`, add to the data class (preserve existing field order, add at the end before the field-map function):

```kotlin
val firstInstallTime: Long,
val lastUpdateTime: Long,
```

In the same file, find `fun toFieldMap(): Map<String, Any?>` (or equivalent) and add:

```kotlin
"first_install_time" to firstInstallTime,
"last_update_time" to lastUpdateTime,
```

- [ ] **Step 2.4: Populate from `PackageInfo` in `AppScanner.buildTelemetryForPackage`**

In `app/src/main/java/com/androdr/scanner/AppScanner.kt`, find the `AppTelemetry(...)` constructor call inside `buildTelemetryForPackage` and append:

```kotlin
firstInstallTime = pkg.firstInstallTime,
lastUpdateTime = pkg.lastUpdateTime,
```

For the test to compile, expose a thin internal accessor:

```kotlin
@VisibleForTesting
internal suspend fun buildTelemetryForPackageForTest(pm: PackageManager, pkg: PackageInfo): AppTelemetry =
    buildTelemetryForPackage(pm, pkg)
```

- [ ] **Step 2.5: Fix all callers / mocks across the codebase**

Every test fixture that constructs `AppTelemetry(...)` will fail to compile until it provides values for the two new fields. Run:

```bash
./gradlew :app:compileDebugUnitTestKotlin 2>&1 | grep "AppTelemetry"
```

For each error, add `firstInstallTime = 0L, lastUpdateTime = 0L` to the constructor call.

- [ ] **Step 2.6: Run tests**

```bash
./gradlew :app:testDebugUnitTest --tests "*AppScanner*"
```

Expected: PASS (including the new test).

- [ ] **Step 2.7: Commit**

```bash
git add app/src/main/java/com/androdr/data/model/AppTelemetry.kt \
        app/src/main/java/com/androdr/scanner/AppScanner.kt \
        app/src/test/java/com/androdr/scanner/AppScannerInstallTimeTest.kt
git add -u  # constructor fixups across other tests
git commit -m "feat(scanner): expose firstInstallTime/lastUpdateTime on AppTelemetry"
```

---

## Task 3: `InstallEventEmitter` — runtime install-event production with delta detection

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/InstallEventEmitter.kt`
- Create test: `app/src/test/java/com/androdr/scanner/InstallEventEmitterTest.kt`

- [ ] **Step 3.1: Write failing tests**

```kotlin
package com.androdr.scanner

import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.ForensicTimelineEvent
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class InstallEventEmitterTest {

    private fun telem(pkg: String, first: Long) = mockk<AppTelemetry>(relaxed = true).also {
        every { it.packageName } returns pkg
        every { it.firstInstallTime } returns first
        every { it.appName } returns pkg
    }

    @Test
    fun `first scan emits one row per package`() = runTest {
        val dao = mockk<ForensicTimelineEventDao>(relaxed = true)
        coEvery { dao.getInstalledPackagesAlreadyEmitted() } returns emptySet()
        val emitter = InstallEventEmitter(dao)
        val rows = emitter.emitNew(scanId = 1L, telemetry = listOf(
            telem("com.a", 1000), telem("com.b", 2000)
        ))
        assertEquals(2, rows.size)
        assertEquals("com.a", rows[0].packageName)
        assertEquals(1000L, rows[0].startTimestamp)
        assertEquals("event", rows[0].kind)
        assertEquals("package_install", rows[0].category)
    }

    @Test
    fun `subsequent scan with no new installs emits zero rows`() = runTest {
        val dao = mockk<ForensicTimelineEventDao>(relaxed = true)
        coEvery { dao.getInstalledPackagesAlreadyEmitted() } returns setOf("com.a", "com.b")
        val emitter = InstallEventEmitter(dao)
        val rows = emitter.emitNew(scanId = 2L, telemetry = listOf(
            telem("com.a", 1000), telem("com.b", 2000)
        ))
        assertTrue(rows.isEmpty())
    }

    @Test
    fun `scan with one new install emits exactly one row`() = runTest {
        val dao = mockk<ForensicTimelineEventDao>(relaxed = true)
        coEvery { dao.getInstalledPackagesAlreadyEmitted() } returns setOf("com.a")
        val emitter = InstallEventEmitter(dao)
        val rows = emitter.emitNew(scanId = 3L, telemetry = listOf(
            telem("com.a", 1000), telem("com.b", 2000)
        ))
        assertEquals(1, rows.size)
        assertEquals("com.b", rows[0].packageName)
    }

    @Test
    fun `package with firstInstallTime = 0 is skipped`() = runTest {
        val dao = mockk<ForensicTimelineEventDao>(relaxed = true)
        coEvery { dao.getInstalledPackagesAlreadyEmitted() } returns emptySet()
        val emitter = InstallEventEmitter(dao)
        val rows = emitter.emitNew(scanId = 1L, telemetry = listOf(telem("com.a", 0)))
        assertTrue(rows.isEmpty())
    }
}
```

- [ ] **Step 3.2: Run tests to verify they fail**

```bash
./gradlew :app:testDebugUnitTest --tests "*InstallEventEmitterTest*"
```

Expected: FAIL — `InstallEventEmitter` does not exist.

- [ ] **Step 3.3: Add the DAO query**

In `app/src/main/java/com/androdr/data/db/ForensicTimelineEventDao.kt`, append:

```kotlin
@Query("SELECT DISTINCT packageName FROM forensic_timeline WHERE category = 'package_install'")
suspend fun getInstalledPackagesAlreadyEmitted(): Set<String>
```

(If Room rejects `Set<String>` as the return type, use `List<String>` and call `.toSet()` in the emitter.)

- [ ] **Step 3.4: Implement `InstallEventEmitter`**

Create `app/src/main/java/com/androdr/scanner/InstallEventEmitter.kt`:

```kotlin
package com.androdr.scanner

import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.ForensicTimelineEvent
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Emits one ForensicTimelineEvent per newly installed package on each scan.
 *
 * Forensic value of an install event is "this happened" — re-emitting on every
 * scan only adds noise. We dedupe against prior scans by querying which package
 * names already have a package_install row.
 */
@Singleton
class InstallEventEmitter @Inject constructor(
    private val timelineDao: ForensicTimelineEventDao
) {
    suspend fun emitNew(scanId: Long, telemetry: List<AppTelemetry>): List<ForensicTimelineEvent> {
        val alreadyEmitted = timelineDao.getInstalledPackagesAlreadyEmitted()
        return telemetry
            .filter { it.firstInstallTime > 0L }
            .filter { it.packageName !in alreadyEmitted }
            .map { t ->
                ForensicTimelineEvent(
                    scanResultId = scanId,
                    startTimestamp = t.firstInstallTime,
                    kind = "event",
                    category = "package_install",
                    source = "app_scanner",
                    description = "Package installed: ${t.appName}",
                    severity = "info",
                    packageName = t.packageName,
                    appName = t.appName,
                    isFromRuntime = true
                )
            }
    }
}
```

- [ ] **Step 3.5: Run tests, confirm pass**

```bash
./gradlew :app:testDebugUnitTest --tests "*InstallEventEmitterTest*"
```

Expected: PASS (4 tests).

- [ ] **Step 3.6: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/InstallEventEmitter.kt \
        app/src/main/java/com/androdr/data/db/ForensicTimelineEventDao.kt \
        app/src/test/java/com/androdr/scanner/InstallEventEmitterTest.kt
git commit -m "feat(scanner): InstallEventEmitter emits package_install rows with delta detection"
```

---

## Task 4: `InstallTimeModule` — bug-report install-time parser

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/bugreport/InstallTimeModule.kt`
- Create test: `app/src/test/java/com/androdr/scanner/bugreport/InstallTimeModuleTest.kt`

- [ ] **Step 4.1: Write failing tests**

```kotlin
package com.androdr.scanner.bugreport

import org.junit.Assert.*
import org.junit.Test

class InstallTimeModuleTest {

    private val sample = """
        Package [com.example.foo] (ab12cd):
          versionName=1.0
          firstInstallTime=2024-03-15 14:23:01
          lastUpdateTime=2024-03-20 09:11:45
        Package [com.example.bar] (ef34gh):
          firstInstallTime=2025-01-02 08:00:00
          lastUpdateTime=2025-01-02 08:00:00
    """.trimIndent()

    @Test
    fun `parses both packages with first and last install times`() {
        val mod = InstallTimeModule()
        val events = mod.parseSection(sample)
        assertEquals(2, events.size)
        assertEquals("com.example.foo", events[0].packageName)
        assertEquals("package_install", events[0].category)
        assertTrue(events[0].startTimestamp > 0)
    }

    @Test
    fun `package with only firstInstallTime still emits a row`() {
        val text = """
            Package [com.x] (z):
              firstInstallTime=2024-01-01 00:00:00
        """.trimIndent()
        val events = InstallTimeModule().parseSection(text)
        assertEquals(1, events.size)
    }

    @Test
    fun `malformed timestamp is skipped, not exception`() {
        val text = """
            Package [com.x] (z):
              firstInstallTime=GARBAGE
              lastUpdateTime=ALSO BROKEN
        """.trimIndent()
        val events = InstallTimeModule().parseSection(text)
        assertTrue(events.isEmpty())
    }

    @Test
    fun `package missing both times produces no row`() {
        val text = """
            Package [com.empty] (a):
              versionName=1
        """.trimIndent()
        assertTrue(InstallTimeModule().parseSection(text).isEmpty())
    }
}
```

- [ ] **Step 4.2: Run tests, verify failure**

```bash
./gradlew :app:testDebugUnitTest --tests "*InstallTimeModuleTest*"
```

Expected: FAIL — class missing.

- [ ] **Step 4.3: Implement `InstallTimeModule`**

Create `app/src/main/java/com/androdr/scanner/bugreport/InstallTimeModule.kt`:

```kotlin
package com.androdr.scanner.bugreport

import com.androdr.data.model.ForensicTimelineEvent
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

/**
 * Parses the `package` section of a bug report (`dumpsys package`) to emit
 * package_install timeline events. Handles missing timestamps gracefully —
 * a package without a parseable firstInstallTime produces no event.
 */
class InstallTimeModule {

    private val packageHeaderRegex = Regex("""^Package \[([^\]]+)\]""", RegexOption.MULTILINE)
    private val firstInstallRegex = Regex("""firstInstallTime=([\d\- :]+)""")
    private val lastUpdateRegex = Regex("""lastUpdateTime=([\d\- :]+)""")

    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).apply {
        timeZone = TimeZone.getDefault()
    }

    fun parseSection(text: String): List<ForensicTimelineEvent> {
        val packageStarts = packageHeaderRegex.findAll(text).toList()
        if (packageStarts.isEmpty()) return emptyList()

        return packageStarts.mapIndexedNotNull { idx, match ->
            val pkg = match.groupValues[1]
            val sectionEnd = if (idx + 1 < packageStarts.size) packageStarts[idx + 1].range.first else text.length
            val packageBlock = text.substring(match.range.first, sectionEnd)

            val firstInstallMs = firstInstallRegex.find(packageBlock)
                ?.groupValues?.get(1)?.trim()
                ?.let { runCatching { dateFormat.parse(it)?.time }.getOrNull() }
                ?: return@mapIndexedNotNull null

            ForensicTimelineEvent(
                startTimestamp = firstInstallMs,
                kind = "event",
                category = "package_install",
                source = "bugreport",
                description = "Package installed: $pkg",
                severity = "info",
                packageName = pkg,
                appName = pkg,
                isFromBugreport = true
            )
        }
    }
}
```

- [ ] **Step 4.4: Run tests, confirm pass**

```bash
./gradlew :app:testDebugUnitTest --tests "*InstallTimeModuleTest*"
```

Expected: PASS (4 tests).

- [ ] **Step 4.5: Wire `InstallTimeModule` into `BugReportAnalyzer`**

In `app/src/main/java/com/androdr/scanner/bugreport/BugReportAnalyzer.kt`, find the section dispatch (similar to other modules like `AppOpsModule`, `ReceiverModule`). Locate the `package` dumpsys section parsing and call:

```kotlin
val installEvents = InstallTimeModule().parseSection(packageSectionText)
allTimelineEvents.addAll(installEvents)
```

(Exact integration depends on the existing module-collection pattern — match the surrounding modules.)

- [ ] **Step 4.6: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/bugreport/InstallTimeModule.kt \
        app/src/main/java/com/androdr/scanner/bugreport/BugReportAnalyzer.kt \
        app/src/test/java/com/androdr/scanner/bugreport/InstallTimeModuleTest.kt
git commit -m "feat(bugreport): InstallTimeModule emits package_install events from dumpsys"
```

---

## Task 5: Atom Rules — four pass-through SIGMA YAML files

**Files:**
- Create 4 YAML files in `app/src/main/res/raw/`

- [ ] **Step 5.1: Create `sigma_androdr_atom_package_install.yml`**

```yaml
title: Atom — package install event
id: androdr-atom-package-install
status: production
description: Internal atom rule. Matches raw package install events for use by correlation rules. Not rendered as a standalone finding.
author: AndroDR
date: 2026-04-08
logsource:
    product: androdr
    service: timeline
detection:
    selection:
        category: package_install
    condition: selection
level: informational
display:
    suppress_finding: true
```

- [ ] **Step 5.2: Create `sigma_androdr_atom_device_admin_grant.yml`**

```yaml
title: Atom — device admin granted
id: androdr-atom-device-admin-grant
status: production
description: Internal atom rule. Matches raw device admin grant events for use by correlation rules.
author: AndroDR
date: 2026-04-08
logsource:
    product: androdr
    service: timeline
detection:
    selection:
        category: device_admin_grant
    condition: selection
level: informational
display:
    suppress_finding: true
```

- [ ] **Step 5.3: Create `sigma_androdr_atom_permission_grant.yml`**

```yaml
title: Atom — permission granted
id: androdr-atom-permission-grant
status: production
description: Internal atom rule. Matches raw permission grant events for use by correlation rules.
author: AndroDR
date: 2026-04-08
logsource:
    product: androdr
    service: timeline
detection:
    selection:
        category: permission_grant
    condition: selection
level: informational
display:
    suppress_finding: true
```

- [ ] **Step 5.4: Create `sigma_androdr_atom_dns_lookup.yml`**

```yaml
title: Atom — suspicious DNS lookup
id: androdr-atom-dns-lookup
status: production
description: Internal atom rule. Matches DNS lookup events that were flagged by the VPN layer (reason != null).
author: AndroDR
date: 2026-04-08
logsource:
    product: androdr
    service: timeline
detection:
    selection:
        category: dns_match
    condition: selection
level: informational
display:
    suppress_finding: true
```

- [ ] **Step 5.5: Verify findings UI suppression of `level: informational`**

```bash
grep -n "informational\|suppress_finding\|level == " app/src/main/java/com/androdr/sigma/ app/src/main/java/com/androdr/ui/findings/ -r
```

If no existing filter excludes `informational` from the findings UI, add one in the findings ViewModel/repository: filter out findings whose source rule has `level == "informational"`. (Spec calls this out as the mechanism.) Document the filter location in a comment.

- [ ] **Step 5.6: Commit**

```bash
git add app/src/main/res/raw/sigma_androdr_atom_*.yml
# Plus the findings filter file if you modified one
git commit -m "feat(rules): atom SIGMA rules for correlation references"
```

---

## Task 6: `CorrelationRule` data classes + `CorrelationParseException`

**Files:**
- Create: `app/src/main/java/com/androdr/sigma/CorrelationRule.kt`
- Create: `app/src/main/java/com/androdr/sigma/CorrelationParseException.kt`

- [ ] **Step 6.1: Create the exception hierarchy**

```kotlin
package com.androdr.sigma

sealed class CorrelationParseException(message: String) : RuntimeException(message) {
    class UnsupportedType(ruleId: String, type: String) :
        CorrelationParseException("Rule $ruleId uses unsupported correlation type '$type'. Supported: temporal_ordered, event_count, temporal.")

    class TimespanExceeded(ruleId: String, requested: String, capDays: Int) :
        CorrelationParseException("Rule $ruleId timespan '$requested' exceeds the engine cap of $capDays days.")

    class UnresolvedRule(ruleId: String, missing: String) :
        CorrelationParseException("Rule $ruleId references unknown rule '$missing'. Make sure the referenced rule is loaded.")

    class InvalidGrammar(ruleId: String, detail: String) :
        CorrelationParseException("Rule $ruleId has invalid correlation grammar: $detail")
}
```

- [ ] **Step 6.2: Create `CorrelationRule.kt`**

```kotlin
package com.androdr.sigma

enum class CorrelationType { TEMPORAL_ORDERED, EVENT_COUNT, TEMPORAL }

data class CorrelationRule(
    val id: String,
    val title: String,
    val type: CorrelationType,
    val referencedRuleIds: List<String>,
    val timespanMs: Long,
    val groupBy: List<String>,
    val minEvents: Int,            // for event_count, else 1
    val severity: String,
    val displayLabel: String,
    val displayCategory: String = "correlation"
)
```

- [ ] **Step 6.3: Commit (no test yet — these are data shapes, exercised by the parser tests in Task 7)**

```bash
git add app/src/main/java/com/androdr/sigma/CorrelationRule.kt \
        app/src/main/java/com/androdr/sigma/CorrelationParseException.kt
git commit -m "feat(sigma): correlation rule data shapes + parse exceptions"
```

---

## Task 7: `SigmaRuleParser` — `correlation:` block parsing

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt`
- Create test: `app/src/test/java/com/androdr/sigma/SigmaRuleParserCorrelationTest.kt`

- [ ] **Step 7.1: Write the failing parser tests**

```kotlin
package com.androdr.sigma

import org.junit.Assert.*
import org.junit.Test

class SigmaRuleParserCorrelationTest {

    private fun parser() = SigmaRuleParser()

    @Test
    fun `parses temporal_ordered rule`() {
        val yaml = """
            title: Install then admin
            id: androdr-corr-001
            correlation:
                type: temporal_ordered
                rules:
                    - androdr-atom-package-install
                    - androdr-atom-device-admin-grant
                timespan: 1h
                group-by:
                    - package_name
            display:
                category: correlation
                severity: high
                label: "Install then admin"
        """.trimIndent()
        val rule = parser().parseCorrelation(yaml)
        assertEquals("androdr-corr-001", rule.id)
        assertEquals(CorrelationType.TEMPORAL_ORDERED, rule.type)
        assertEquals(2, rule.referencedRuleIds.size)
        assertEquals(3600_000L, rule.timespanMs)
        assertEquals("package_name", rule.groupBy.single())
    }

    @Test
    fun `parses event_count rule with gte condition`() {
        val yaml = """
            title: Burst
            id: androdr-corr-004
            correlation:
                type: event_count
                rules: [androdr-atom-permission-grant]
                timespan: 5m
                group-by: [package_name]
                condition:
                    gte: 3
            display:
                category: correlation
                severity: high
                label: "Burst"
        """.trimIndent()
        val rule = parser().parseCorrelation(yaml)
        assertEquals(CorrelationType.EVENT_COUNT, rule.type)
        assertEquals(3, rule.minEvents)
        assertEquals(300_000L, rule.timespanMs)
    }

    @Test(expected = CorrelationParseException.UnsupportedType::class)
    fun `value_count rejected at parse time`() {
        parser().parseCorrelation("""
            title: T
            id: x
            correlation:
                type: value_count
                rules: [a]
                timespan: 1h
                condition: { gte: 1 }
        """.trimIndent())
    }

    @Test(expected = CorrelationParseException.TimespanExceeded::class)
    fun `timespan exceeding 90 days rejected`() {
        parser().parseCorrelation("""
            title: T
            id: x
            correlation:
                type: temporal_ordered
                rules: [a, b]
                timespan: 91d
        """.trimIndent())
    }

    @Test(expected = CorrelationParseException.InvalidGrammar::class)
    fun `missing rules list rejected`() {
        parser().parseCorrelation("""
            title: T
            id: x
            correlation:
                type: temporal_ordered
                timespan: 1h
        """.trimIndent())
    }

    @Test
    fun `parses timespan in seconds, minutes, hours, days`() {
        fun span(s: String): Long = parser().parseCorrelation("""
            title: T
            id: x
            correlation:
                type: temporal_ordered
                rules: [a, b]
                timespan: $s
            display:
                category: correlation
                severity: high
                label: T
        """.trimIndent()).timespanMs

        assertEquals(45_000L, span("45s"))
        assertEquals(120_000L, span("2m"))
        assertEquals(7200_000L, span("2h"))
        assertEquals(86400_000L * 7, span("7d"))
    }
}
```

- [ ] **Step 7.2: Run tests, verify failure**

```bash
./gradlew :app:testDebugUnitTest --tests "*SigmaRuleParserCorrelationTest*"
```

Expected: FAIL — `parseCorrelation` doesn't exist.

- [ ] **Step 7.3: Add `parseCorrelation` to `SigmaRuleParser`**

In `app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt`, add:

```kotlin
companion object {
    private const val CORRELATION_TIMESPAN_CAP_DAYS = 90
    private val TIMESPAN_REGEX = Regex("""^(\d+)([smhd])$""")
}

fun parseCorrelation(yaml: String): CorrelationRule {
    // Reuse the existing YAML loader (snakeyaml or kotlinx.serialization) the
    // detection-rule parser uses. Pseudocode:
    val root = loadYaml(yaml) as Map<String, Any?>
    val id = root["id"] as? String
        ?: throw CorrelationParseException.InvalidGrammar("<unknown>", "missing id")
    val title = root["title"] as? String ?: id

    val corr = root["correlation"] as? Map<String, Any?>
        ?: throw CorrelationParseException.InvalidGrammar(id, "missing correlation block")

    val typeStr = corr["type"] as? String
        ?: throw CorrelationParseException.InvalidGrammar(id, "missing correlation.type")
    val type = when (typeStr) {
        "temporal_ordered" -> CorrelationType.TEMPORAL_ORDERED
        "event_count"      -> CorrelationType.EVENT_COUNT
        "temporal"         -> CorrelationType.TEMPORAL
        else -> throw CorrelationParseException.UnsupportedType(id, typeStr)
    }

    @Suppress("UNCHECKED_CAST")
    val rules = (corr["rules"] as? List<String>)
        ?: throw CorrelationParseException.InvalidGrammar(id, "missing or invalid rules list")
    if (rules.isEmpty()) throw CorrelationParseException.InvalidGrammar(id, "rules list is empty")

    val timespanStr = corr["timespan"] as? String
        ?: throw CorrelationParseException.InvalidGrammar(id, "missing timespan")
    val timespanMs = parseTimespan(id, timespanStr)

    @Suppress("UNCHECKED_CAST")
    val groupBy = (corr["group-by"] as? List<String>) ?: emptyList()

    val minEvents = if (type == CorrelationType.EVENT_COUNT) {
        @Suppress("UNCHECKED_CAST")
        val cond = corr["condition"] as? Map<String, Any?>
            ?: throw CorrelationParseException.InvalidGrammar(id, "event_count requires condition.gte")
        (cond["gte"] as? Number)?.toInt()
            ?: throw CorrelationParseException.InvalidGrammar(id, "event_count requires condition.gte (int)")
    } else 1

    @Suppress("UNCHECKED_CAST")
    val display = (root["display"] as? Map<String, Any?>) ?: emptyMap()
    val severity = display["severity"] as? String ?: "medium"
    val label = display["label"] as? String ?: title

    return CorrelationRule(
        id = id, title = title, type = type,
        referencedRuleIds = rules,
        timespanMs = timespanMs,
        groupBy = groupBy,
        minEvents = minEvents,
        severity = severity,
        displayLabel = label
    )
}

private fun parseTimespan(ruleId: String, raw: String): Long {
    val m = TIMESPAN_REGEX.matchEntire(raw.trim())
        ?: throw CorrelationParseException.InvalidGrammar(ruleId, "invalid timespan '$raw'")
    val value = m.groupValues[1].toLong()
    val unit = m.groupValues[2]
    val ms = when (unit) {
        "s" -> value * 1_000L
        "m" -> value * 60_000L
        "h" -> value * 3_600_000L
        "d" -> value * 86_400_000L
        else -> throw CorrelationParseException.InvalidGrammar(ruleId, "invalid timespan unit '$unit'")
    }
    if (ms > CORRELATION_TIMESPAN_CAP_DAYS * 86_400_000L) {
        throw CorrelationParseException.TimespanExceeded(ruleId, raw, CORRELATION_TIMESPAN_CAP_DAYS)
    }
    return ms
}
```

(Adapt `loadYaml` to whatever YAML library `SigmaRuleParser` already uses. Look at the existing `parse(...)` method to see the import.)

- [ ] **Step 7.4: Run tests, confirm pass**

```bash
./gradlew :app:testDebugUnitTest --tests "*SigmaRuleParserCorrelationTest*"
```

Expected: PASS (6 tests).

- [ ] **Step 7.5: Validate referenced-rule existence in `SigmaRuleEngine.loadCorrelationRules()`**

This validation can't happen in `parseCorrelation` (which sees one rule at a time). Instead, in `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt`, add a `loadCorrelationRules` step that runs *after* detection rules are loaded. For each correlation rule, verify every `referencedRuleIds` value is in the loaded detection-rule set; otherwise throw `CorrelationParseException.UnresolvedRule`.

```kotlin
fun loadCorrelationRules(parsedRules: List<CorrelationRule>) {
    val knownIds = detectionRules.map { it.id }.toSet()
    parsedRules.forEach { rule ->
        rule.referencedRuleIds.forEach { ref ->
            if (ref !in knownIds) {
                throw CorrelationParseException.UnresolvedRule(rule.id, ref)
            }
        }
    }
    correlationRules = parsedRules
}
```

(Add the `correlationRules: List<CorrelationRule>` field to the engine.)

- [ ] **Step 7.6: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt \
        app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt \
        app/src/test/java/com/androdr/sigma/SigmaRuleParserCorrelationTest.kt
git commit -m "feat(sigma): parse upstream SIGMA correlation grammar (3 of 4 types)"
```

---

## Task 8: `SigmaCorrelationEngine` — type-specific evaluators

**Files:**
- Create: `app/src/main/java/com/androdr/sigma/SigmaCorrelationEngine.kt`
- Create test: `app/src/test/java/com/androdr/sigma/SigmaCorrelationEngineTest.kt`

- [ ] **Step 8.1: Write failing tests for each correlation type**

```kotlin
package com.androdr.sigma

import com.androdr.data.model.ForensicTimelineEvent
import org.junit.Assert.*
import org.junit.Test

class SigmaCorrelationEngineTest {

    private fun event(
        id: Long, ts: Long, category: String, pkg: String = "com.test"
    ) = ForensicTimelineEvent(
        id = id, startTimestamp = ts, kind = "event", category = category,
        source = "test", description = "evt", severity = "info", packageName = pkg
    )

    private val installRule = CorrelationRule(
        id = "test-install-then-admin",
        title = "T",
        type = CorrelationType.TEMPORAL_ORDERED,
        referencedRuleIds = listOf("atom-install", "atom-admin"),
        timespanMs = 3_600_000L,
        groupBy = listOf("package_name"),
        minEvents = 1,
        severity = "high",
        displayLabel = "Install then admin"
    )

    private val burstRule = CorrelationRule(
        id = "test-burst",
        title = "T",
        type = CorrelationType.EVENT_COUNT,
        referencedRuleIds = listOf("atom-perm"),
        timespanMs = 300_000L,
        groupBy = listOf("package_name"),
        minEvents = 3,
        severity = "high",
        displayLabel = "Burst"
    )

    // The engine needs a way to know which atom rule each event satisfies.
    // We pass a precomputed map (eventId -> set of matching rule ids).
    private fun bindings(vararg pairs: Pair<Long, Set<String>>): Map<Long, Set<String>> = pairs.toMap()

    @Test
    fun `temporal_ordered fires when both events occur in order within window`() {
        val events = listOf(
            event(1, 1000, "package_install"),
            event(2, 2000, "device_admin_grant")
        )
        val binds = bindings(1L to setOf("atom-install"), 2L to setOf("atom-admin"))
        val signals = SigmaCorrelationEngine().evaluate(listOf(installRule), events, binds)
        assertEquals(1, signals.size)
        assertEquals("test-install-then-admin", signals[0].ruleId)
        assertEquals(1000L, signals[0].startTimestamp)
        assertEquals(2000L, signals[0].endTimestamp)
        assertEquals("signal", signals[0].kind)
        assertEquals("1,2", signals[0].matchContext["member_event_ids"])
    }

    @Test
    fun `temporal_ordered does not fire when order is reversed`() {
        val events = listOf(
            event(1, 1000, "device_admin_grant"),
            event(2, 2000, "package_install")
        )
        val binds = bindings(1L to setOf("atom-admin"), 2L to setOf("atom-install"))
        val signals = SigmaCorrelationEngine().evaluate(listOf(installRule), events, binds)
        assertTrue(signals.isEmpty())
    }

    @Test
    fun `temporal_ordered does not fire when window exceeded`() {
        val events = listOf(
            event(1, 1000, "package_install"),
            event(2, 1000 + 3_600_001L, "device_admin_grant")
        )
        val binds = bindings(1L to setOf("atom-install"), 2L to setOf("atom-admin"))
        val signals = SigmaCorrelationEngine().evaluate(listOf(installRule), events, binds)
        assertTrue(signals.isEmpty())
    }

    @Test
    fun `event_count fires when threshold met within window`() {
        val events = listOf(
            event(1, 1000, "permission_grant"),
            event(2, 2000, "permission_grant"),
            event(3, 3000, "permission_grant")
        )
        val binds = bindings(
            1L to setOf("atom-perm"),
            2L to setOf("atom-perm"),
            3L to setOf("atom-perm")
        )
        val signals = SigmaCorrelationEngine().evaluate(listOf(burstRule), events, binds)
        assertEquals(1, signals.size)
        assertEquals(3, signals[0].matchContext["member_event_ids"]?.split(",")?.size)
    }

    @Test
    fun `event_count does not fire when below threshold`() {
        val events = listOf(
            event(1, 1000, "permission_grant"),
            event(2, 2000, "permission_grant")
        )
        val binds = bindings(1L to setOf("atom-perm"), 2L to setOf("atom-perm"))
        val signals = SigmaCorrelationEngine().evaluate(listOf(burstRule), events, binds)
        assertTrue(signals.isEmpty())
    }

    @Test
    fun `group-by isolates clusters per package`() {
        val events = listOf(
            event(1, 1000, "package_install", pkg = "com.a"),
            event(2, 2000, "device_admin_grant", pkg = "com.b") // different pkg!
        )
        val binds = bindings(1L to setOf("atom-install"), 2L to setOf("atom-admin"))
        val signals = SigmaCorrelationEngine().evaluate(listOf(installRule), events, binds)
        assertTrue("group-by package_name should prevent cross-package match", signals.isEmpty())
    }
}
```

- [ ] **Step 8.2: Run tests, verify failure**

```bash
./gradlew :app:testDebugUnitTest --tests "*SigmaCorrelationEngineTest*"
```

Expected: FAIL — class missing.

- [ ] **Step 8.3: Implement `SigmaCorrelationEngine`**

```kotlin
package com.androdr.sigma

import com.androdr.data.model.ForensicTimelineEvent
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Evaluates upstream-SIGMA-compliant correlation rules over a list of timeline events.
 *
 * Inputs:
 *  - rules: parsed correlation rules to evaluate
 *  - events: candidate events (typically a per-rule windowed slice of forensic_timeline)
 *  - bindings: map of eventId -> set of atom rule IDs that the event satisfies.
 *    Computed by SigmaRuleEngine after detection runs.
 *
 * Output: list of ForensicTimelineEvent rows with kind = "signal" representing
 * each cluster that fired.
 */
@Singleton
class SigmaCorrelationEngine @Inject constructor() {

    fun evaluate(
        rules: List<CorrelationRule>,
        events: List<ForensicTimelineEvent>,
        bindings: Map<Long, Set<String>>
    ): List<ForensicTimelineEvent> {
        val signals = mutableListOf<ForensicTimelineEvent>()
        rules.forEach { rule ->
            signals += when (rule.type) {
                CorrelationType.TEMPORAL_ORDERED -> evaluateTemporalOrdered(rule, events, bindings)
                CorrelationType.EVENT_COUNT      -> evaluateEventCount(rule, events, bindings)
                CorrelationType.TEMPORAL         -> evaluateTemporalUnordered(rule, events, bindings)
            }
        }
        return signals
    }

    private fun evaluateTemporalOrdered(
        rule: CorrelationRule,
        events: List<ForensicTimelineEvent>,
        bindings: Map<Long, Set<String>>
    ): List<ForensicTimelineEvent> {
        val grouped = events.groupBy { groupKey(it, rule.groupBy) }
        val results = mutableListOf<ForensicTimelineEvent>()
        grouped.forEach { (_, groupEvents) ->
            val sorted = groupEvents.sortedBy { it.startTimestamp }
            val firstStepRule = rule.referencedRuleIds.first()
            val lastStepRule = rule.referencedRuleIds.last()
            // Walk first-step events; for each, check whether subsequent events
            // satisfy the remaining steps in order, all within the window.
            sorted.forEachIndexed { i, e ->
                if (firstStepRule !in (bindings[e.id] ?: emptySet())) return@forEachIndexed
                val chain = mutableListOf(e)
                var nextStepIdx = 1
                for (j in (i + 1) until sorted.size) {
                    val candidate = sorted[j]
                    if (candidate.startTimestamp - e.startTimestamp > rule.timespanMs) break
                    val needRule = rule.referencedRuleIds[nextStepIdx]
                    if (needRule in (bindings[candidate.id] ?: emptySet())) {
                        chain += candidate
                        nextStepIdx++
                        if (nextStepIdx >= rule.referencedRuleIds.size) break
                    }
                }
                if (chain.size == rule.referencedRuleIds.size) {
                    results += signal(rule, chain)
                }
            }
        }
        return results
    }

    private fun evaluateEventCount(
        rule: CorrelationRule,
        events: List<ForensicTimelineEvent>,
        bindings: Map<Long, Set<String>>
    ): List<ForensicTimelineEvent> {
        val refRules = rule.referencedRuleIds.toSet()
        val grouped = events.groupBy { groupKey(it, rule.groupBy) }
        val results = mutableListOf<ForensicTimelineEvent>()
        grouped.forEach { (_, groupEvents) ->
            val matching = groupEvents
                .filter { (bindings[it.id] ?: emptySet()).any { id -> id in refRules } }
                .sortedBy { it.startTimestamp }
            // Sliding window of size = timespan
            var i = 0
            while (i < matching.size) {
                val windowEnd = matching[i].startTimestamp + rule.timespanMs
                val window = matching.subList(i, matching.size).takeWhile { it.startTimestamp <= windowEnd }
                if (window.size >= rule.minEvents) {
                    results += signal(rule, window)
                    i += window.size  // skip ahead, no overlapping clusters
                } else {
                    i++
                }
            }
        }
        return results
    }

    private fun evaluateTemporalUnordered(
        rule: CorrelationRule,
        events: List<ForensicTimelineEvent>,
        bindings: Map<Long, Set<String>>
    ): List<ForensicTimelineEvent> {
        val needed = rule.referencedRuleIds.toSet()
        val grouped = events.groupBy { groupKey(it, rule.groupBy) }
        val results = mutableListOf<ForensicTimelineEvent>()
        grouped.forEach { (_, groupEvents) ->
            val sorted = groupEvents.sortedBy { it.startTimestamp }
            // Sliding window: for each anchor event, look forward within timespan
            // and check whether all needed rules appear at least once.
            for (i in sorted.indices) {
                val anchor = sorted[i]
                val window = mutableListOf(anchor)
                val seenRules = (bindings[anchor.id] ?: emptySet()).intersect(needed).toMutableSet()
                for (j in (i + 1) until sorted.size) {
                    if (sorted[j].startTimestamp - anchor.startTimestamp > rule.timespanMs) break
                    window += sorted[j]
                    seenRules += (bindings[sorted[j].id] ?: emptySet()).intersect(needed)
                    if (seenRules.containsAll(needed)) {
                        results += signal(rule, window)
                        break
                    }
                }
            }
        }
        return results
    }

    private fun groupKey(event: ForensicTimelineEvent, groupBy: List<String>): String =
        when (groupBy.firstOrNull()) {
            "package_name" -> event.packageName
            null -> ""
            else -> ""  // unsupported group field — single bucket
        }

    private fun signal(rule: CorrelationRule, members: List<ForensicTimelineEvent>): ForensicTimelineEvent {
        val first = members.first()
        val last = members.last()
        return ForensicTimelineEvent(
            scanResultId = first.scanResultId,
            startTimestamp = first.startTimestamp,
            endTimestamp = last.startTimestamp,
            kind = "signal",
            category = "correlation",
            source = "sigma_correlation_engine",
            description = rule.displayLabel,
            severity = rule.severity,
            packageName = first.packageName,
            ruleId = rule.id,
            correlationId = rule.id + ":" + members.joinToString(",") { it.id.toString() }
            // matchContext stored separately — see toFieldMap conversion downstream
        ).copy(
            // Hack: Room entity doesn't have a matchContext map — encode in details
            // until we add it. (See spec: matchContext is the conceptual model;
            // physically we encode in `details` as JSON or pipe-delimited until
            // a future schema bump moves it to a real column.)
            details = """{"correlation_type":"${rule.type.name.lowercase()}","rule_id":"${rule.id}","member_event_ids":"${members.joinToString(",") { it.id.toString() }}"}"""
        )
    }
}
```

Note on `matchContext`: the existing `ForensicTimelineEvent` doesn't have a `matchContext` map column. The spec describes `matchContext` as the conceptual model. Physically, we encode the three keys (`correlation_type`, `rule_id`, `member_event_ids`) into the existing `details` field as a small JSON string. The Timeline UI parses it back. A future schema bump can promote `matchContext` to a real column if it grows beyond three keys.

Update the test assertions accordingly: the tests use `matchContext["member_event_ids"]` — replace those with assertions that parse `signals[0].details` and look for `"member_event_ids":"1,2"`. Update step 8.1 fixtures before running step 8.4.

- [ ] **Step 8.4: Run tests, confirm pass**

```bash
./gradlew :app:testDebugUnitTest --tests "*SigmaCorrelationEngineTest*"
```

Expected: PASS (6 tests).

- [ ] **Step 8.5: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/SigmaCorrelationEngine.kt \
        app/src/test/java/com/androdr/sigma/SigmaCorrelationEngineTest.kt
git commit -m "feat(sigma): SigmaCorrelationEngine evaluator for 3 correlation types"
```

---

## Task 9: Migrate four hardcoded patterns to YAML

**Files:**
- Create 4 YAML files in `app/src/main/res/raw/`

- [ ] **Step 9.1: Create `sigma_androdr_corr_001_install_then_admin.yml`**

```yaml
title: Sideloaded install followed by device admin grant
id: androdr-corr-001
status: production
description: Detects an install event followed by a device admin grant on the same package within one hour. Strong indicator of a sideloaded surveillance app gaining persistence.
author: AndroDR
date: 2026-04-08
tags:
    - attack.t1626
    - attack.t1098
correlation:
    type: temporal_ordered
    rules:
        - androdr-atom-package-install
        - androdr-atom-device-admin-grant
    timespan: 1h
    group-by:
        - package_name
display:
    category: correlation
    severity: high
    label: "Install then device admin grant"
```

- [ ] **Step 9.2: Create `sigma_androdr_corr_002_install_then_permission.yml`**

```yaml
title: Sideloaded install followed by dangerous permission grant
id: androdr-corr-002
status: production
description: Detects an install event followed by a dangerous permission grant on the same package within one hour.
author: AndroDR
date: 2026-04-08
tags:
    - attack.t1626
correlation:
    type: temporal_ordered
    rules:
        - androdr-atom-package-install
        - androdr-atom-permission-grant
    timespan: 1h
    group-by:
        - package_name
display:
    category: correlation
    severity: high
    label: "Install then permission grant"
```

- [ ] **Step 9.3: Create `sigma_androdr_corr_003_permission_then_c2.yml`**

```yaml
title: Permission grant followed by suspicious DNS lookup
id: androdr-corr-003
status: production
description: Detects a permission grant followed within 30 minutes by a DNS lookup that the VPN layer flagged as suspicious. Possible C2 activation.
author: AndroDR
date: 2026-04-08
tags:
    - attack.t1071.004
correlation:
    type: temporal_ordered
    rules:
        - androdr-atom-permission-grant
        - androdr-atom-dns-lookup
    timespan: 30m
    group-by:
        - package_name
display:
    category: correlation
    severity: high
    label: "Permission grant then suspicious DNS"
```

- [ ] **Step 9.4: Create `sigma_androdr_corr_004_surveillance_burst.yml`**

```yaml
title: Surveillance permission burst
id: androdr-corr-004
status: production
description: Three or more permission grant events within five minutes on the same package. Indicates a permission accept burst common to surveillanceware first-run flows.
author: AndroDR
date: 2026-04-08
tags:
    - attack.t1429
    - attack.t1430
correlation:
    type: event_count
    rules:
        - androdr-atom-permission-grant
    timespan: 5m
    group-by:
        - package_name
    condition:
        gte: 3
display:
    category: correlation
    severity: high
    label: "Multiple permissions accessed rapidly"
```

- [ ] **Step 9.5: Commit**

```bash
git add app/src/main/res/raw/sigma_androdr_corr_*.yml
git commit -m "feat(rules): migrate hardcoded correlation patterns to upstream SIGMA YAML"
```

---

## Task 10: Wire correlation engine into `ScanOrchestrator` and `BugReportAnalyzer`

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt`
- Modify: `app/src/main/java/com/androdr/scanner/bugreport/BugReportAnalyzer.kt`
- Modify: `app/src/main/java/com/androdr/data/repo/ScanRepository.kt`

- [ ] **Step 10.1: Inject `InstallEventEmitter` and `SigmaCorrelationEngine` into `ScanOrchestrator`**

Add to the constructor:

```kotlin
private val installEventEmitter: InstallEventEmitter,
private val sigmaCorrelationEngine: SigmaCorrelationEngine,
```

Add corresponding mocks to `ScanOrchestratorErrorHandlingTest` and any other orchestrator tests (look for `mockk(relaxed = true)` setup blocks).

- [ ] **Step 10.2: Call the emitter and engine after detection**

In `runFullScanInner` (or wherever the scan body lives), after detection findings are produced and before `saveScanResults`:

```kotlin
// 1. Emit install events from this scan's app telemetry (delta-detected)
val installEvents = installEventEmitter.emitNew(scanId, appTelemetryList)

// 2. Run correlation rules over (this scan's events + lookback window)
val maxRuleWindowMs = sigmaRuleEngine.correlationRules.maxOfOrNull { it.timespanMs } ?: 0L
val lookbackEvents = if (maxRuleWindowMs > 0) {
    forensicTimelineEventDao.getEventsSince(System.currentTimeMillis() - maxRuleWindowMs)
} else emptyList()

val candidateEvents = lookbackEvents + installEvents + findingTimelineEvents
val ruleBindings = sigmaRuleEngine.computeAtomBindings(candidateEvents)
val correlationSignals = sigmaCorrelationEngine.evaluate(
    sigmaRuleEngine.correlationRules,
    candidateEvents,
    ruleBindings
)

val allTimelineEvents = installEvents + findingTimelineEvents + correlationSignals
```

- [ ] **Step 10.3: Add `computeAtomBindings` to `SigmaRuleEngine`**

In `SigmaRuleEngine.kt`:

```kotlin
/**
 * For each event, compute the set of atom rule IDs that match it. This is the
 * binding map consumed by the correlation engine.
 */
fun computeAtomBindings(events: List<ForensicTimelineEvent>): Map<Long, Set<String>> {
    val atomRules = detectionRules.filter { it.level == "informational" }
    return events.associate { event ->
        event.id to atomRules.filter { matchesAtom(it, event) }.map { it.id }.toSet()
    }
}

private fun matchesAtom(rule: SigmaRule, event: ForensicTimelineEvent): Boolean {
    // Atom rules only match on `category`. If the rule's selection has
    // `category: <value>`, the event matches when its category equals that value.
    val expectedCategory = rule.detectionSelection["category"] as? String ?: return false
    return event.category == expectedCategory
}
```

- [ ] **Step 10.4: Pass the combined timeline events into `saveScanResults`**

`ScanRepository.saveScanResults` already accepts `findingTimelineEvents: List<ForensicTimelineEvent>` — pass `allTimelineEvents` (the install events + findings + signals union) here.

- [ ] **Step 10.5: Wire the bug-report path identically**

In `BugReportAnalyzer.kt`, after the modules produce raw events and `SigmaRuleEngine.evaluate*` produces findings:

```kotlin
val allEvents = rawEvents + findings
val bindings = sigmaRuleEngine.computeAtomBindings(allEvents)
val signals = sigmaCorrelationEngine.evaluate(sigmaRuleEngine.correlationRules, allEvents, bindings)
val finalEvents = allEvents + signals
```

(Bug reports don't need the lookback query — they're a self-contained snapshot.)

- [ ] **Step 10.6: Compile + run all tests**

```bash
./gradlew :app:testDebugUnitTest
```

Expected: BUILD SUCCESSFUL. Fix any test fixtures broken by the new constructor params.

- [ ] **Step 10.7: Commit**

```bash
git add -u
git commit -m "feat(scanner): wire SigmaCorrelationEngine + InstallEventEmitter into runtime + bugreport"
```

---

## Task 11: Behavioral equivalence tests for migrated rules

**Files:**
- Create: `app/src/test/java/com/androdr/sigma/CorrelationMigrationEquivalenceTest.kt`

- [ ] **Step 11.1: Write equivalence tests pinning each migrated rule's behavior**

For each of corr-001 through corr-004, build a fixture event list, run it through both the old `CorrelationEngine` (still present at this point) and `SigmaCorrelationEngine` with the YAML rule loaded, and assert they produce the same number of clusters with the same time bounds.

```kotlin
package com.androdr.sigma

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.ui.timeline.CorrelationEngine
import com.androdr.ui.timeline.TimelineCategory
import org.junit.Assert.assertEquals
import org.junit.Test

class CorrelationMigrationEquivalenceTest {

    @Test
    fun `corr-001 install_then_admin matches Kotlin original output`() {
        val fixture = listOf(
            event(1, 1000, "package_install", pkg = "com.test"),
            event(2, 1000 + 30 * 60_000, "device_admin_grant", pkg = "com.test")
        )

        val kotlinClusters = CorrelationEngine().detectInstallThenAdmin(fixture.toLegacy())
        val yamlSignals = SigmaCorrelationEngine().evaluate(
            listOf(loadRule("sigma_androdr_corr_001_install_then_admin.yml")),
            fixture,
            atomBindingsFor(fixture)
        )
        assertEquals(kotlinClusters.size, yamlSignals.size)
        if (yamlSignals.isNotEmpty()) {
            assertEquals(1000L, yamlSignals[0].startTimestamp)
            assertEquals(1000L + 30 * 60_000L, yamlSignals[0].endTimestamp)
        }
    }

    // Repeat for corr-002, corr-003, corr-004 with appropriate fixtures.

    private fun event(id: Long, ts: Long, category: String, pkg: String) =
        ForensicTimelineEvent(
            id = id, startTimestamp = ts, kind = "event",
            category = category, source = "test", description = "e",
            severity = "info", packageName = pkg
        )

    // Helper stubs — implement these against your real loaders
    private fun loadRule(resourceName: String): CorrelationRule = TODO("read YAML from test resources")
    private fun atomBindingsFor(events: List<ForensicTimelineEvent>): Map<Long, Set<String>> = TODO()
    private fun List<ForensicTimelineEvent>.toLegacy(): List<*> = TODO("convert to whatever CorrelationEngine expects")
}
```

(The `TODO()` stubs need real implementations. The reason this task is its own step: we need to inspect `CorrelationEngine.detect*` signatures to know what to convert *to*. After Task 12 deletes those methods, this test file is updated to drop the comparison and keep just the YAML-side assertions as a regression net.)

- [ ] **Step 11.2: Run tests, expect PASS for all four**

If any rule disagrees with its Kotlin original, debug by printing both outputs side by side and either fixing the YAML rule or fixing the engine's evaluator to match.

- [ ] **Step 11.3: Commit**

```bash
git add app/src/test/java/com/androdr/sigma/CorrelationMigrationEquivalenceTest.kt
git commit -m "test(sigma): behavioral equivalence between Kotlin and YAML correlation rules"
```

---

## Task 12: Delete `CorrelationEngine.kt` and update Timeline UI for `kind = "signal"` rendering

**Files:**
- DELETE: `app/src/main/java/com/androdr/ui/timeline/CorrelationEngine.kt`
- DELETE: `app/src/test/java/com/androdr/ui/timeline/CorrelationEngineTest.kt` (if exists)
- Modify: `app/src/main/java/com/androdr/ui/timeline/TimelineViewModel.kt`
- Modify: `app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt`
- Modify: `app/src/test/java/com/androdr/sigma/CorrelationMigrationEquivalenceTest.kt` (drop legacy comparison)

- [ ] **Step 12.1: Identify all callers of `CorrelationEngine` and remove the calls**

```bash
grep -rn "CorrelationEngine\|detectInstallThenAdmin\|detectMultiPermissionBurst\|detectGenericTemporal\|detectInstallThenPermission\|detectPermissionThenC2" app/src/main/
```

Every call site is replaced by reading correlation signals directly from the timeline DB. The Timeline VM should query for `kind = "signal"` rows and render them via the existing `CorrelationClusterCard`.

- [ ] **Step 12.2: Update `TimelineViewModel` to read signals as a flow**

The existing flow already returns all `ForensicTimelineEvent` rows. Add a transform that:
- Separates `kind = "event"` rows (rendered as raw events) from `kind = "signal"` rows (rendered as clusters).
- For each signal row, parse `details` JSON to extract `member_event_ids` and join those by ID for the expanded view.

```kotlin
data class TimelineSignal(
    val signal: ForensicTimelineEvent,
    val members: List<ForensicTimelineEvent>
)

private fun buildSignals(allEvents: List<ForensicTimelineEvent>): List<TimelineSignal> {
    val byId = allEvents.associateBy { it.id }
    return allEvents
        .filter { it.kind == "signal" }
        .map { sig ->
            val memberIds = parseDetailsJson(sig.details)["member_event_ids"]
                ?.split(",")
                ?.mapNotNull { it.toLongOrNull() }
                ?: emptyList()
            TimelineSignal(sig, memberIds.mapNotNull(byId::get))
        }
}
```

- [ ] **Step 12.3: Update `TimelineEventCard` to render `kind = "signal"` rows**

Reuse the existing `CorrelationClusterCard` composable. The conditional in `TimelineEventCard` becomes: `if (event.kind == "signal") CorrelationClusterCard(...) else PointEventCard(...)`.

- [ ] **Step 12.4: Delete `CorrelationEngine.kt`**

```bash
git rm app/src/main/java/com/androdr/ui/timeline/CorrelationEngine.kt
git rm app/src/test/java/com/androdr/ui/timeline/CorrelationEngineTest.kt 2>/dev/null || true
```

- [ ] **Step 12.5: Update `CorrelationMigrationEquivalenceTest` to drop the legacy comparison**

The Kotlin side no longer exists. Each test now asserts only the YAML-side signal output is correct against the fixture. Keep the test file as the regression net.

- [ ] **Step 12.6: Build + full test suite**

```bash
./gradlew :app:testDebugUnitTest :app:lintDebug
```

Expected: BUILD SUCCESSFUL.

- [ ] **Step 12.7: Commit**

```bash
git add -u
git commit -m "refactor(timeline): delete CorrelationEngine.kt, render signals from DB

The hardcoded correlation patterns now live in YAML rules under res/raw/.
Timeline UI reads kind=signal rows and renders them via the existing
CorrelationClusterCard. This completes the rule-driven correlation migration."
```

---

## Task 13: On-device verification

**Files:** none (verification only)

- [ ] **Step 13.1: Build + install debug APK on a real device**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
./gradlew installDebug
```

- [ ] **Step 13.2: Verify install events appear on first scan**

Open the app, run a full scan, navigate to Timeline. Confirm:
- One row per installed app with `category = package_install` and a real install date going back years.
- Rows are sorted oldest to newest.

- [ ] **Step 13.3: Verify delta detection**

Run the scan a second time with no app changes. Confirm:
- Zero new `package_install` rows appear.

- [ ] **Step 13.4: Verify install_then_admin correlation fires**

Sideload a test APK, immediately grant it device admin. Run a scan. Confirm:
- A new `kind = signal` row with `ruleId = androdr-corr-001` appears in the timeline.
- Tapping it expands to show both the install event and the admin grant event as members.

- [ ] **Step 13.5: Verify bug-report path produces install rows**

Capture a bug report from the device, share it to AndroDR for analysis. Confirm:
- `package_install` rows appear in the analyzed timeline.
- Correlation signals fire if the bug report contains qualifying patterns.

- [ ] **Step 13.6: Verify atom rules don't appear in findings UI**

Navigate to App Risks / Findings. Confirm:
- No findings labeled "Atom — package install" or similar appear.
- Only correlation signals and real detection findings are visible.

- [ ] **Step 13.7: Manual perf check**

Time the scan with logcat:

```bash
adb logcat -c && adb logcat | grep -E "ScanOrchestrator|SigmaCorrelation"
```

Run a scan; note the elapsed time. If correlation evaluation pushes total scan time above 25 seconds on the test device, batch the per-rule windowed queries into a single union query (the perf-budget mitigation in the spec's risk table).

---

## Self-Review Checklist

Before declaring the plan complete, verify:

- **Spec coverage:** Every bullet in `docs/superpowers/specs/2026-04-08-correlation-engine-yaml-design.md` § "Locked design decisions" is implemented by some task above. (1: Task 10, 2: Task 7, 3: Task 7+8, 4: Task 5, 5: Task 7+10, 6: Task 1, 7: Task 3+4)
- **No placeholders:** All steps contain real code or real commands. No "implement appropriately" or "add tests later".
- **Type consistency:** `CorrelationRule` shape in Task 6 matches usage in Tasks 7, 8, 10. `ForensicTimelineEvent.startTimestamp` is the renamed field in every reference after Task 1.
- **Migration correctness:** Task 1 column rename uses Room 2.4+ `RENAME COLUMN` syntax (verify the project's Room version supports it). If Room is older, replace with the SQLite create-temp-table pattern and rerun the migration test.

---

## Notes for the implementing engineer

- **Don't fight existing patterns.** `SigmaRuleParser` already loads YAML through some mechanism — find it before writing your own loader. Same for the SIGMA engine's rule registration path.
- **The `details` field encoding for `matchContext` is a stopgap.** A future task can add a real `matchContext: Map<String, String>` column when correlation metadata grows beyond three keys.
- **The `level: informational` filter** for atom rules must already exist or must be added in Task 5 step 5. Don't proceed past Task 10 without verifying this filter — otherwise atom rules will spam the findings UI.
- **`CorrelationEngine.kt` deletion happens last** (Task 12), not first, because the equivalence tests in Task 11 need both sides simultaneously.
- **Branch:** create from main as `feat/sprint-75-correlation-yaml`.

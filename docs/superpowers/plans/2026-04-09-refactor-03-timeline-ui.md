# Refactor Plan 3: Timeline UI

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Parent refactor:** Unified telemetry/findings architecture (#84). Spec: `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`, §10.

**Plan order:** Plan 3 of 7. Starts after plan 2's final commit `9328877`. Serialized execution on branch `claude/unified-telemetry-findings-refactor`.

**Goal:** Separate telemetry rows from finding rows in the timeline UI so users never see a neutral observation rendered with a severity badge. Remove `ForensicTimelineEvent.severity` from the data model (it's a telemetry layer leak — severity belongs only on findings). Introduce a `TimelineRow` sealed type that lets the ViewModel emit both telemetry and finding entries in a single chronological stream with type-distinct rendering. Add a "Hide informational telemetry" filter toggle (default OFF) and an export mode selector (telemetry only / findings only / both, default both).

**Architecture:**
- `ForensicTimelineEvent` drops its `severity: String` field (Room v15→v16).
- `UsageStatsScanner.kt:126` and any other telemetry producers stop writing severity.
- Finding-derived timeline entries continue to exist but flow via `Finding` objects from the rule engine, NOT by forcing severity into `ForensicTimelineEvent`.
- `TimelineViewModel` queries telemetry events and findings separately, merges them chronologically, and emits `List<TimelineRow>` via a `StateFlow`.
- `TimelineRow` is a sealed type with two variants: `TelemetryRow(event: ForensicTimelineEvent)` and `FindingRow(finding: Finding, anchorEvent: ForensicTimelineEvent?)`.
- `TimelineScreen` / `TimelineEventCard` render each variant distinctly: `TelemetryRow` is neutral (grey, no severity badge); `FindingRow` has a severity badge, category indicator, rule ID.
- A new filter toggle "Hide informational telemetry" in the existing filter panel hides `TelemetryRow` entries not referenced by any `FindingRow`.
- The export dialog gains a radio-button mode selector: telemetry only / findings only / both (default). `ReportExporter` produces bundles accordingly. Export format version bumped.

**Tech Stack:** Kotlin, Jetpack Compose (existing timeline UI), Hilt, Room (migration v15→v16), JUnit 4 + MockK.

**Acceptance criteria:**
- `ForensicTimelineEvent` no longer has a `severity` field.
- Room migration v15→v16 drops the column and its index, tested.
- `UsageStatsScanner` no longer writes `severity`.
- `SigmaRuleEvaluator` / `SigmaCorrelationEngine` / any other writer of `ForensicTimelineEvent` no longer writes `severity`.
- `TimelineRow` sealed type exists with `TelemetryRow` and `FindingRow` variants.
- `TimelineViewModel` exposes a `StateFlow<List<TimelineRow>>`.
- `TimelineScreen` and `TimelineEventCard` render both variants distinctly.
- "Hide informational telemetry" filter toggle exists in the UI, defaulted OFF.
- Export mode selector (3 radio options) exists in the export dialog.
- Export format version field bumped by 1.
- All gradle checks pass.
- No sigma package code, no rule YAML, no bugreport modules touched (those are plans 5-7).

---

## Pre-plan audit

The Timeline UI is in `app/src/main/java/com/androdr/ui/timeline/` — 4 files, ~1,525 lines total. Before implementing, the subagent MUST read each file and understand its current state:

- `TimelineScreen.kt` (~634 lines) — top-level Composable
- `TimelineViewModel.kt` (~302 lines) — ViewModel emitting timeline state
- `TimelineEventCard.kt` (~425 lines) — per-row rendering
- `TimelineClusters.kt` (~164 lines) — clustering / grouping logic

Also read:
- `app/src/main/java/com/androdr/data/model/ForensicTimelineEvent.kt` — current shape (has `severity: String` field still)
- `app/src/main/java/com/androdr/data/db/ForensicTimelineEventDao.kt` — DAO queries
- `app/src/main/java/com/androdr/reporting/ReportExporter.kt` — export flow (find the current version field)

Implementation tasks in this plan assume the subagent has read the current code before modifying. Where possible, the plan provides exact shapes; where the existing code is too complex to pre-specify, the plan gives acceptance criteria and lets the implementer shape the change.

---

## File Structure

### Created

- `app/src/main/java/com/androdr/ui/timeline/TimelineRow.kt` — sealed type with `TelemetryRow` and `FindingRow` variants
- `app/src/test/java/com/androdr/data/db/Migration15To16Test.kt` — Room migration test (or `androidTest/` if that's the project's convention)

### Modified

- `app/src/main/java/com/androdr/data/model/ForensicTimelineEvent.kt` — remove `severity` field, remove its `Index`
- `app/src/main/java/com/androdr/data/db/Migrations.kt` — add `MIGRATION_15_16`
- `app/src/main/java/com/androdr/data/db/AppDatabase.kt` — bump version to 16
- `app/src/main/java/com/androdr/di/AppModule.kt` (or wherever migrations are registered) — register `MIGRATION_15_16`
- `app/src/main/java/com/androdr/data/db/ForensicTimelineEventDao.kt` — remove any query or index referencing `severity`
- `app/src/main/java/com/androdr/scanner/UsageStatsScanner.kt` — stop writing `severity`
- `app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt` — stop writing `severity` on any `ForensicTimelineEvent` constructor call
- `app/src/main/java/com/androdr/sigma/SigmaCorrelationEngine.kt` — same
- `app/src/main/java/com/androdr/data/db/TimelineAdapter.kt` — remove severity from any mapping
- `app/src/main/java/com/androdr/ui/timeline/TimelineViewModel.kt` — emit `TimelineRow` stream, add `hideInformationalTelemetry` filter state
- `app/src/main/java/com/androdr/ui/timeline/TimelineScreen.kt` — render `TimelineRow` variants, add filter toggle to the filter panel
- `app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt` — render `TelemetryRow` and `FindingRow` distinctly
- `app/src/main/java/com/androdr/ui/timeline/TimelineClusters.kt` — if clustering depends on severity, update to work without it (clusters group by package/category/time, not severity)
- `app/src/main/java/com/androdr/reporting/ReportExporter.kt` — add export mode enum and per-mode bundle construction; bump format version
- `app/src/main/java/com/androdr/reporting/ReportFormatter.kt` — adapt to export mode if relevant
- `app/src/main/java/com/androdr/ui/history/HistoryScreen.kt` (or wherever export is triggered) — add export mode selector UI
- `app/src/main/java/com/androdr/ui/history/HistoryViewModel.kt` — plumbing for the export mode
- Existing tests that touched `severity` on `ForensicTimelineEvent` — update

### Not touched

- `FindingCategory` / `RuleCategory` / `SigmaRule` / `SigmaRuleParser` / any rule YAML
- Any bugreport module (`scanner/bugreport/`)
- `TelemetrySource` enum (established by plan 2)
- The seven new telemetry types (plan 2)

---

## Phase A: Remove `severity` from `ForensicTimelineEvent`

### Task A1: Data class edit + migration write

**Files:**
- Modify: `app/src/main/java/com/androdr/data/model/ForensicTimelineEvent.kt`
- Modify: `app/src/main/java/com/androdr/data/db/Migrations.kt`
- Modify: `app/src/main/java/com/androdr/data/db/AppDatabase.kt`
- Modify: `app/src/main/java/com/androdr/di/AppModule.kt`

- [ ] **Step 1: Read the current `ForensicTimelineEvent.kt`** and confirm the `severity` field and its `Index("severity")` entry in `@Entity`.

- [ ] **Step 2: Remove `severity` field**

Delete `val severity: String,` from the data class primary constructor. Delete `Index("severity")` from the `indices` list in the `@Entity` annotation.

- [ ] **Step 3: Write migration 15→16**

Append to `Migrations.kt`:

```kotlin
val MIGRATION_15_16 = object : Migration(15, 16) {
    override fun migrate(db: SupportSQLiteDatabase) {
        // Remove severity column from forensic_timeline.
        //
        // Timeline events are telemetry — pure observation, no severity.
        // Severity lives only on findings produced by the rule engine.
        // This migration drops the column and its index, completing the
        // Layer 1 / Layer 2 separation from spec §3.
        //
        // SQLite supports DROP COLUMN only from 3.35 / API 34; the portable
        // pattern is table recreation. See MIGRATION_14_15 for the same
        // technique.

        db.execSQL("""
            CREATE TABLE forensic_timeline_new (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                startTimestamp      INTEGER NOT NULL,
                endTimestamp        INTEGER DEFAULT NULL,
                kind                TEXT NOT NULL DEFAULT 'event',
                timestampPrecision  TEXT NOT NULL DEFAULT 'exact',
                source              TEXT NOT NULL,
                category            TEXT NOT NULL,
                description         TEXT NOT NULL,
                details             TEXT NOT NULL DEFAULT '',
                packageName         TEXT NOT NULL DEFAULT '',
                appName             TEXT NOT NULL DEFAULT '',
                processUid          INTEGER NOT NULL DEFAULT -1,
                iocIndicator        TEXT NOT NULL DEFAULT '',
                iocType             TEXT NOT NULL DEFAULT '',
                iocSource           TEXT NOT NULL DEFAULT '',
                campaignName        TEXT NOT NULL DEFAULT '',
                apkHash             TEXT NOT NULL DEFAULT '',
                correlationId       TEXT NOT NULL DEFAULT '',
                ruleId              TEXT NOT NULL DEFAULT '',
                scanResultId        INTEGER NOT NULL DEFAULT -1,
                attackTechniqueId   TEXT NOT NULL DEFAULT '',
                telemetrySource     TEXT NOT NULL DEFAULT 'LIVE_SCAN',
                createdAt           INTEGER NOT NULL
            )
        """.trimIndent())

        db.execSQL("""
            INSERT INTO forensic_timeline_new (
                id, startTimestamp, endTimestamp, kind, timestampPrecision,
                source, category, description, details,
                packageName, appName, processUid, iocIndicator, iocType,
                iocSource, campaignName, apkHash, correlationId, ruleId,
                scanResultId, attackTechniqueId, telemetrySource, createdAt
            )
            SELECT
                id, startTimestamp, endTimestamp, kind, timestampPrecision,
                source, category, description, details,
                packageName, appName, processUid, iocIndicator, iocType,
                iocSource, campaignName, apkHash, correlationId, ruleId,
                scanResultId, attackTechniqueId, telemetrySource, createdAt
            FROM forensic_timeline
        """.trimIndent())

        db.execSQL("DROP TABLE forensic_timeline")
        db.execSQL("ALTER TABLE forensic_timeline_new RENAME TO forensic_timeline")

        db.execSQL("CREATE INDEX IF NOT EXISTS index_forensic_timeline_startTimestamp ON forensic_timeline(startTimestamp)")
        db.execSQL("CREATE INDEX IF NOT EXISTS index_forensic_timeline_packageName ON forensic_timeline(packageName)")
        db.execSQL("CREATE INDEX IF NOT EXISTS index_forensic_timeline_source ON forensic_timeline(source)")
        db.execSQL("CREATE INDEX IF NOT EXISTS index_forensic_timeline_kind ON forensic_timeline(kind)")
        db.execSQL("CREATE INDEX IF NOT EXISTS index_forensic_timeline_telemetrySource ON forensic_timeline(telemetrySource)")
        // Note: no severity index — the column no longer exists.
    }
}
```

- [ ] **Step 4: Bump database version**

In `AppDatabase.kt`, change `version = 15` to `version = 16`.

In `AppModule.kt` (or wherever migrations are registered), add `MIGRATION_15_16` to the `.addMigrations(...)` list, in order.

- [ ] **Step 5: Do NOT compile yet** — many callers will break because they reference `severity`. Next task fixes them.

### Task A2: Update all callers of `ForensicTimelineEvent.severity`

**Files:**
- Multiple — use grep to find all of them

- [ ] **Step 1: Find all references**

```bash
cd /home/yasir/AndroDR
grep -rn "\.severity" app/src/main/java/com/androdr/scanner/UsageStatsScanner.kt
grep -rn "severity = " app/src/main/java/com/androdr/scanner/ app/src/main/java/com/androdr/sigma/ app/src/main/java/com/androdr/data/ app/src/main/java/com/androdr/ui/ app/src/main/java/com/androdr/reporting/ --include="*.kt" | grep -i "forensic\|timeline\|event"
```

Expected hits:
- `UsageStatsScanner.kt:126` — `severity = "INFO"` → delete this argument
- `SigmaRuleEvaluator.kt` — any `ForensicTimelineEvent(...)` with a `severity =` argument → delete the argument (finding severity now lives on `Finding`, not the timeline event)
- `SigmaCorrelationEngine.kt` — same
- `TimelineAdapter.kt` — mapping from findings to `ForensicTimelineEvent` → remove severity mapping
- `ForensicTimelineEventDao.kt` — any query referencing `severity`
- UI code reading `event.severity` for display → for `TimelineRow.FindingRow`, severity comes from `finding.level`, not from the event

- [ ] **Step 2: Update each site**

For each match:
- **Write sites**: delete the `severity = X` argument from the constructor call. The data class no longer has this field, so including it is a compile error.
- **Read sites**: refactor to read severity from the associated `Finding` object instead (if one exists), or drop the severity display entirely if it was part of neutral telemetry rendering.
- **Database query sites**: remove any `ORDER BY severity`, `WHERE severity = X`, or `SELECT severity` clauses. If a DAO method was returning severity as part of a projection, remove it from the projection.

- [ ] **Step 3: Compile — expect it to pass**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -10
```

If there are still errors, they're either:
- Missed references (go back to grep)
- A place that used severity for UI state that needs a different approach (typically: the `FindingRow` variant should hold its own severity via the `Finding.level` field)

- [ ] **Step 4: Do NOT run tests yet** — the migration test comes next. Tests that touch Room will fail without the migration applied.

### Task A3: Write the migration test

**Files:**
- Create: test file following the project's existing migration test pattern

- [ ] **Step 1: Check the existing migration test location**

```bash
find app/src -name "Migration*Test*.kt"
```

Plan 2 placed `Migration14To15Test.kt` under `app/src/androidTest/java/com/androdr/data/db/` because Robolectric wasn't available. Use the same pattern for `Migration15To16Test.kt`.

- [ ] **Step 2: Write the test**

```kotlin
package com.androdr.data.db

import androidx.room.testing.MigrationTestHelper
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Migration15To16Test {
    private val testDbName = "migration-test-15-16.db"

    @get:Rule
    val helper: MigrationTestHelper = MigrationTestHelper(
        InstrumentationRegistry.getInstrumentation(),
        AppDatabase::class.java,
    )

    @Test
    fun `migration 15 to 16 drops severity column and preserves rows`() {
        helper.createDatabase(testDbName, 15).use { db ->
            db.execSQL("""
                INSERT INTO forensic_timeline (
                    startTimestamp, kind, timestampPrecision, source, category,
                    description, details, severity, packageName, appName,
                    processUid, iocIndicator, iocType, iocSource, campaignName,
                    apkHash, correlationId, ruleId, scanResultId, attackTechniqueId,
                    telemetrySource, createdAt
                ) VALUES (
                    1000, 'event', 'exact', 'usage_stats', 'app_foreground',
                    'test row', '', 'high', 'com.example.test', 'Test',
                    -1, '', '', '', '', '', '', '', -1, '',
                    'LIVE_SCAN', 2000
                )
            """.trimIndent())
        }

        helper.runMigrationsAndValidate(
            testDbName, 16, true, MIGRATION_15_16
        ).use { db ->
            val cursor = db.query("SELECT startTimestamp, telemetrySource FROM forensic_timeline")
            assertEquals(1, cursor.count)
            cursor.moveToFirst()
            assertEquals(1000L, cursor.getLong(0))
            assertEquals("LIVE_SCAN", cursor.getString(1))
            cursor.close()
        }

        // Verify severity column is gone by running PRAGMA table_info
        helper.runMigrationsAndValidate(
            testDbName, 16, true, MIGRATION_15_16
        ).use { db ->
            val cursor = db.query("PRAGMA table_info(forensic_timeline)")
            val columns = mutableListOf<String>()
            while (cursor.moveToNext()) {
                columns.add(cursor.getString(cursor.getColumnIndexOrThrow("name")))
            }
            cursor.close()
            assert(!columns.contains("severity")) { "severity column should be dropped; columns: $columns" }
            assert(columns.contains("telemetrySource")) { "telemetrySource should still exist" }
        }
    }
}
```

- [ ] **Step 3: Commit the A-phase work**

```bash
git add app/src/main/java/com/androdr/data/model/ForensicTimelineEvent.kt \
        app/src/main/java/com/androdr/data/db/Migrations.kt \
        app/src/main/java/com/androdr/data/db/AppDatabase.kt \
        app/src/main/java/com/androdr/di/AppModule.kt \
        app/src/main/java/com/androdr/data/db/ForensicTimelineEventDao.kt \
        app/src/main/java/com/androdr/data/db/TimelineAdapter.kt \
        app/src/main/java/com/androdr/scanner/UsageStatsScanner.kt \
        app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt \
        app/src/main/java/com/androdr/sigma/SigmaCorrelationEngine.kt \
        app/src/androidTest/java/com/androdr/data/db/Migration15To16Test.kt
# Plus any other files that required updates
git commit -m "refactor(data): remove severity column from ForensicTimelineEvent (#84)

Severity is a property of findings, not telemetry. Per spec §3, the
telemetry layer must carry no severity — only pure observation.
Findings produced by the rule engine carry severity; the timeline UI
in plan 3's next phase renders them distinctly from telemetry.

- ForensicTimelineEvent.severity field removed
- Room migration v15 → v16 drops the column and its index
- UsageStatsScanner no longer writes severity = INFO
- SigmaRuleEvaluator / SigmaCorrelationEngine no longer write severity
  on ForensicTimelineEvent constructions (correlation signal severity
  still lives on Finding, not on the event)
- Migration test verifies column is gone and existing rows preserved

Part of #84 (plan 3, phase A)."
```

### Task A4: Verify the full test suite still passes

- [ ] **Step 1: Run the full suite**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
./gradlew testDebugUnitTest 2>&1 | tail -20
```
Expected: BUILD SUCCESSFUL.

If any test fails because it asserted on `severity`, update the test (the assertion is no longer valid after this refactor).

---

## Phase B: `TimelineRow` sealed type

### Task B1: Create `TimelineRow`

**Files:**
- Create: `app/src/main/java/com/androdr/ui/timeline/TimelineRow.kt`

- [ ] **Step 1: Write the file**

```kotlin
package com.androdr.ui.timeline

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.sigma.Finding

/**
 * A single row in the timeline UI. Sealed type with two variants that
 * enforce the spec §3 layer separation at the UI level:
 *
 * - [TelemetryRow] wraps a pure-observation [ForensicTimelineEvent] with
 *   no severity. Rendered as a neutral entry — no severity badge, low
 *   visual weight.
 * - [FindingRow] wraps a rule-produced [Finding] with a severity, category,
 *   and ruleId. Rendered with a severity badge and category indicator.
 *
 * The [TimelineViewModel] merges telemetry events and findings into a
 * single chronological stream of `TimelineRow`. The `Screen` renders
 * each variant via a `when` exhaustive branch so the compiler enforces
 * that every variant has a visual treatment.
 *
 * See `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`
 * §10 for the rationale.
 */
sealed interface TimelineRow {
    /** Timestamp used to sort rows chronologically. */
    val timestamp: Long

    /**
     * A telemetry observation (no severity). Examples: app foreground/background,
     * DNS query, permission grant, wakelock acquisition. The user can hide
     * these with the "Hide informational telemetry" filter if they're not
     * referenced by any finding.
     *
     * @property event the underlying telemetry event
     * @property referencedByFindingIds the IDs of findings whose evidence
     *           references this event (used by the filter to decide whether
     *           to hide this row when the filter is on)
     */
    data class TelemetryRow(
        val event: ForensicTimelineEvent,
        val referencedByFindingIds: List<String> = emptyList(),
    ) : TimelineRow {
        override val timestamp: Long get() = event.startTimestamp
    }

    /**
     * A rule-produced finding. Rendered with a severity badge, category
     * indicator, and ruleId. The anchor event, if present, is the telemetry
     * row the finding's evidence points at — rendered visually linked
     * (e.g. side rail, indentation) so the user can see the evidence in
     * context.
     *
     * @property finding the rule-produced finding
     * @property anchorEvent the telemetry event that most directly triggered
     *           the finding, if the ViewModel could resolve one; null otherwise
     */
    data class FindingRow(
        val finding: Finding,
        val anchorEvent: ForensicTimelineEvent? = null,
    ) : TimelineRow {
        override val timestamp: Long
            get() = anchorEvent?.startTimestamp ?: System.currentTimeMillis()
    }
}
```

- [ ] **Step 2: Compile**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -5
```
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: No commit yet** — commit with the ViewModel refactor in B2.

### Task B2: Refactor `TimelineViewModel` to emit `List<TimelineRow>`

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/timeline/TimelineViewModel.kt`

- [ ] **Step 1: Read the current ViewModel**

```bash
cat app/src/main/java/com/androdr/ui/timeline/TimelineViewModel.kt
```

Understand the current state shape. The ViewModel likely emits a `StateFlow<List<ForensicTimelineEvent>>` or a `StateFlow<TimelineState>` containing events. Note the data source (DAO method, repository, Flow<List<X>>).

- [ ] **Step 2: Add a findings data source**

The ViewModel needs to query findings as well as telemetry events. Find how findings are currently fetched elsewhere (the Dashboard or Apps screen) and use the same repository/DAO/SharedFlow.

If there's no existing findings flow, the simplest option is to inject the `ScanRepository` (or equivalent) and query its current scan's findings synchronously when building the timeline state.

- [ ] **Step 3: Add state for the "Hide informational telemetry" filter**

```kotlin
private val _hideInformationalTelemetry = MutableStateFlow(false)
val hideInformationalTelemetry: StateFlow<Boolean> = _hideInformationalTelemetry.asStateFlow()

fun setHideInformationalTelemetry(hidden: Boolean) {
    _hideInformationalTelemetry.value = hidden
}
```

- [ ] **Step 4: Build the merged `List<TimelineRow>` stream**

The ViewModel's public state should be a `StateFlow<List<TimelineRow>>`. Internally, combine:
- The existing telemetry events flow
- The findings flow (new)
- The filter state flow

Merge logic:
1. Wrap each telemetry event as `TimelineRow.TelemetryRow(event, referencedByFindingIds = findingsThatReferenceThisEvent)`
2. Wrap each finding as `TimelineRow.FindingRow(finding, anchorEvent = findRelatedEvent(finding, events))`
3. Sort the combined list by `timestamp`
4. If `hideInformationalTelemetry.value == true`, filter out `TelemetryRow` entries with empty `referencedByFindingIds`
5. Emit

The `findRelatedEvent` helper: for a finding with a `ruleId`, find the first telemetry event whose `ruleId == finding.ruleId` (if the existing schema stores that linkage), or fall back to the first event in the same scan with matching package name. If no good match, return null.

The `referencedByFindingIds` helper: for each event, collect finding IDs where `finding.ruleId` matches the event's `ruleId` (if that linkage exists).

Both helpers can be approximate for the first iteration — the spec's intent is that telemetry and findings be visually distinct, not that the linkage be perfect.

- [ ] **Step 5: Preserve existing timeline UI state (filters, sort order, etc.)**

The existing ViewModel may have additional state for date range filters, source filters, etc. Preserve all of it — the refactor is purely about the row type and adding one new filter. Don't break other existing filters.

- [ ] **Step 6: Compile**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -10
```
Expected: BUILD SUCCESSFUL. If the screen hasn't been updated yet, it will FAIL because it's still consuming the old state shape. Defer compilation check until B3.

### Task B3: Update `TimelineScreen` + `TimelineEventCard` + `TimelineClusters`

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/timeline/TimelineScreen.kt`
- Modify: `app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt`
- Modify: `app/src/main/java/com/androdr/ui/timeline/TimelineClusters.kt`

- [ ] **Step 1: Read all three files**

```bash
cat app/src/main/java/com/androdr/ui/timeline/TimelineScreen.kt
cat app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt
cat app/src/main/java/com/androdr/ui/timeline/TimelineClusters.kt
```

Understand the current composable structure and how events are rendered.

- [ ] **Step 2: Update `TimelineScreen` to consume `StateFlow<List<TimelineRow>>`**

Replace the existing event list consumer with one that takes `List<TimelineRow>`. In the LazyColumn or similar, use a `when` branch to render each variant:

```kotlin
LazyColumn {
    items(rows, key = { it.timestamp.toString() + it.hashCode() }) { row ->
        when (row) {
            is TimelineRow.TelemetryRow -> TimelineEventCard.Telemetry(row)
            is TimelineRow.FindingRow -> TimelineEventCard.Finding(row)
        }
    }
}
```

- [ ] **Step 3: Add the "Hide informational telemetry" filter toggle to the filter panel**

Find the existing filter panel in `TimelineScreen.kt` (date range, source filter, etc.) and add a new `Switch` or `Checkbox`:

```kotlin
val hideInformational by viewModel.hideInformationalTelemetry.collectAsState()
Row(verticalAlignment = Alignment.CenterVertically) {
    Switch(
        checked = hideInformational,
        onCheckedChange = viewModel::setHideInformationalTelemetry,
    )
    Spacer(modifier = Modifier.width(8.dp))
    Text("Hide informational telemetry")
}
```

Default state: OFF (the ViewModel's MutableStateFlow default).

- [ ] **Step 4: Update `TimelineEventCard` with two rendering variants**

Split the current single `TimelineEventCard` composable into two (or an outer composable that branches internally):

```kotlin
@Composable
fun TelemetryCard(row: TimelineRow.TelemetryRow) {
    // Neutral style: grey background, no severity badge, low visual weight
    // Show: timestamp, source, description, packageName if any
}

@Composable
fun FindingCard(row: TimelineRow.FindingRow) {
    // Distinct style: severity badge (color by finding.level), category chip
    // (by finding.category), rule ID visible on tap/expand
    // Show: timestamp, severity badge, category, finding.title, finding.description,
    // ruleId in small text, the anchor event link if anchorEvent != null
}
```

Preserve any existing expansion / tap behavior from the old single card composable — just split the visual treatment.

- [ ] **Step 5: Update `TimelineClusters` if it depends on severity**

```bash
grep -n "severity" app/src/main/java/com/androdr/ui/timeline/TimelineClusters.kt
```

If the clustering logic ordered or filtered by severity, refactor to use a different key (cluster by package, category, or time window — whatever preserves user-facing intent). Severity is no longer on the telemetry event.

- [ ] **Step 6: Compile**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -10
```
Expected: BUILD SUCCESSFUL. If still failing, grep for `.severity` on `ForensicTimelineEvent` instances in the UI package and fix each site.

### Task B4: Timeline UI unit tests

- [ ] **Step 1: Find existing Timeline UI tests**

```bash
find app/src/test -name "Timeline*Test*.kt" -o -name "*TimelineTest*.kt"
```

- [ ] **Step 2: Update existing tests that assert on severity**

Any test that constructed a `ForensicTimelineEvent` with `severity = "..."` or asserted on `event.severity` needs updating. Remove the severity argument from constructor calls.

- [ ] **Step 3: Add a new test for `TimelineViewModel` row emission**

```kotlin
// Illustrative — adapt to the project's test conventions
@Test
fun `ViewModel emits both TelemetryRow and FindingRow variants in chronological order`() {
    // Given: 2 telemetry events and 1 finding
    val e1 = makeEvent(timestamp = 1000L)
    val e2 = makeEvent(timestamp = 3000L)
    val f1 = makeFinding(ruleId = "androdr-001", level = "high")
    // When: ViewModel combines them
    // Then: expect 3 rows, sorted by timestamp, with the finding positioned
    //       by its anchor event
}

@Test
fun `hideInformationalTelemetry filter drops telemetry rows not referenced by findings`() {
    // Given: 2 telemetry events, one referenced by a finding, one not;
    //        1 finding referencing the first event
    // When: filter is OFF
    // Then: expect 3 rows (2 telemetry + 1 finding)
    // When: filter is ON
    // Then: expect 2 rows (1 referenced telemetry + 1 finding)
}
```

- [ ] **Step 4: Run tests**

```bash
./gradlew testDebugUnitTest --tests "*Timeline*" 2>&1 | tail -15
```
Expected: BUILD SUCCESSFUL.

### Task B5: Commit phase B

```bash
git add app/src/main/java/com/androdr/ui/timeline/TimelineRow.kt \
        app/src/main/java/com/androdr/ui/timeline/TimelineViewModel.kt \
        app/src/main/java/com/androdr/ui/timeline/TimelineScreen.kt \
        app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt \
        app/src/main/java/com/androdr/ui/timeline/TimelineClusters.kt
# Plus any test files updated or added
git commit -m "refactor(ui): distinguish telemetry from findings in timeline (#84)

Introduces TimelineRow sealed type with TelemetryRow (neutral, no
severity badge) and FindingRow (severity badge + category indicator +
rule ID) variants. TimelineViewModel now emits a merged chronological
stream of both; TimelineScreen renders each variant distinctly.

Adds 'Hide informational telemetry' filter toggle (default OFF) that
hides telemetry rows not referenced by any finding. Finding rows and
their anchor telemetry events remain visible regardless.

This enforces spec §3 layer separation at the UI level — a neutral
observation can never accidentally display a severity badge because
TelemetryRow has no severity to render.

Part of #84 (plan 3, phase B)."
```

---

## Phase C: Export Mode Selector

### Task C1: Define export modes + update `ReportExporter`

**Files:**
- Modify: `app/src/main/java/com/androdr/reporting/ReportExporter.kt`

- [ ] **Step 1: Read the current exporter**

```bash
cat app/src/main/java/com/androdr/reporting/ReportExporter.kt
```

Find the export method and the format version constant.

- [ ] **Step 2: Define the export mode enum**

At the top of `ReportExporter.kt` (or in a sibling file if more appropriate):

```kotlin
/**
 * Three-way export mode selector per spec §10.
 *
 * - [TELEMETRY_ONLY] — writes only the telemetry section. Intended for
 *   analyst handoff: the recipient can run their own rules against the
 *   telemetry without being biased by the device's current ruleset.
 * - [FINDINGS_ONLY] — writes only the findings section. Useful for
 *   sharing "what did the app find" without exposing the raw telemetry.
 * - [BOTH] — writes both sections. Default.
 */
enum class ExportMode {
    TELEMETRY_ONLY,
    FINDINGS_ONLY,
    BOTH,
}
```

- [ ] **Step 3: Update the export method to accept the mode**

Change the signature:

```kotlin
suspend fun export(
    scanResultId: Long,
    mode: ExportMode = ExportMode.BOTH,
): File
```

In the body, branch on `mode`:

```kotlin
when (mode) {
    ExportMode.TELEMETRY_ONLY -> writeTelemetrySection(...)
    ExportMode.FINDINGS_ONLY -> writeFindingsSection(...)
    ExportMode.BOTH -> {
        writeTelemetrySection(...)
        writeFindingsSection(...)
    }
}
```

If the existing exporter inlines telemetry and findings into a single render pass, split into two private methods that each build their respective section, then call them based on mode.

- [ ] **Step 4: Bump the export format version**

Find the format version constant (likely something like `const val EXPORT_FORMAT_VERSION = 3`). Bump it by 1:

```kotlin
const val EXPORT_FORMAT_VERSION = 4
```

Add a comment noting why: "v4 — plan 3 refactor: explicit TELEMETRY / FINDINGS sections, severity removed from telemetry".

- [ ] **Step 5: Compile**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -10
```

Expected: BUILD SUCCESSFUL. Callers might need updating — they pass `mode` explicitly or rely on the default `BOTH`. Either is fine.

### Task C2: Add export mode selector to the UI

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/history/HistoryScreen.kt` (or wherever the export button/dialog lives)
- Modify: `app/src/main/java/com/androdr/ui/history/HistoryViewModel.kt`

- [ ] **Step 1: Find the current export flow**

```bash
grep -rn "export(\|ReportExporter\|exportReport" app/src/main/java/com/androdr/ui/
```

Identify where the user clicks "Export" and how the request flows through the ViewModel.

- [ ] **Step 2: Add a 3-option radio dialog**

When the user clicks "Export", show a dialog with three radio options:
- "Telemetry only (for analyst handoff)"
- "Findings only"
- "Both (full report)" — default selected

Example Compose dialog:

```kotlin
@Composable
fun ExportModeDialog(
    onDismiss: () -> Unit,
    onConfirm: (ExportMode) -> Unit,
) {
    var selectedMode by remember { mutableStateOf(ExportMode.BOTH) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Export report") },
        text = {
            Column {
                ExportMode.values().forEach { mode ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectable(
                                selected = selectedMode == mode,
                                onClick = { selectedMode = mode },
                            )
                            .padding(vertical = 8.dp),
                    ) {
                        RadioButton(
                            selected = selectedMode == mode,
                            onClick = { selectedMode = mode },
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(modeLabel(mode))
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(selectedMode) }) {
                Text("Export")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        },
    )
}

private fun modeLabel(mode: ExportMode): String = when (mode) {
    ExportMode.TELEMETRY_ONLY -> "Telemetry only (for analyst handoff)"
    ExportMode.FINDINGS_ONLY -> "Findings only"
    ExportMode.BOTH -> "Both (full report)"
}
```

- [ ] **Step 3: Wire the dialog into the screen**

In `HistoryScreen.kt`, when the export button is clicked, show the dialog. When the user confirms, call `viewModel.exportReport(scanId, mode)`.

- [ ] **Step 4: Update the ViewModel's export method**

```kotlin
fun exportReport(scanId: Long, mode: ExportMode) {
    viewModelScope.launch {
        val file = reportExporter.export(scanId, mode)
        // existing file sharing / intent launching logic
    }
}
```

- [ ] **Step 5: Compile and run tests**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -5
./gradlew testDebugUnitTest 2>&1 | tail -15
```
Expected: BUILD SUCCESSFUL.

### Task C3: Commit phase C

```bash
git add app/src/main/java/com/androdr/reporting/ReportExporter.kt \
        app/src/main/java/com/androdr/ui/history/HistoryScreen.kt \
        app/src/main/java/com/androdr/ui/history/HistoryViewModel.kt
# Plus any related test updates
git commit -m "feat(export): 3-mode export selector (telemetry / findings / both) (#84)

Per spec §10, the export dialog now offers three explicit modes:

- TELEMETRY_ONLY: analyst-handoff bundle. Contains only the telemetry
  section so a recipient can run their own rules without being biased
  by the device's current ruleset.
- FINDINGS_ONLY: rule-evaluation snapshot. Contains only the findings
  section without the raw telemetry.
- BOTH: full report (default, preserves existing behavior).

ReportExporter accepts an ExportMode parameter. The export format
version is bumped to 4 so external tooling can detect the new bundle
structure.

Part of #84 (plan 3, phase C)."
```

---

## Phase D: Final Verification

### Task D1: Run the full check suite

- [ ] **Step 1: Unit tests**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
./gradlew testDebugUnitTest 2>&1 | tail -20
```
Expected: BUILD SUCCESSFUL.

- [ ] **Step 2: Lint**

```bash
./gradlew lintDebug 2>&1 | tail -10
```
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Assemble**

```bash
./gradlew assembleDebug 2>&1 | tail -5
```
Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Detekt**

```bash
./gradlew detekt 2>&1 | tail -10
```
Expected: BUILD SUCCESSFUL. Fix any new violations introduced by plan 3.

### Task D2: Verify invariants

- [ ] **Step 1: `severity` is fully removed from `ForensicTimelineEvent`**

```bash
grep -n "severity" app/src/main/java/com/androdr/data/model/ForensicTimelineEvent.kt
```
Expected: zero hits.

- [ ] **Step 2: No code writes `severity = ...` to a `ForensicTimelineEvent`**

```bash
grep -rn "severity = " app/src/main/java/com/androdr/scanner/ app/src/main/java/com/androdr/sigma/ app/src/main/java/com/androdr/data/ app/src/main/java/com/androdr/reporting/ --include="*.kt" | grep -i "forensic\|timeline"
```
Expected: zero hits. (Non-ForensicTimelineEvent usages of `severity = ` are fine.)

- [ ] **Step 3: `TimelineRow` exists with two variants**

```bash
grep -n "TelemetryRow\|FindingRow" app/src/main/java/com/androdr/ui/timeline/TimelineRow.kt
```
Expected: both names present.

- [ ] **Step 4: `ExportMode` enum + `export(...)` signature updated**

```bash
grep -n "enum class ExportMode\|ExportMode\." app/src/main/java/com/androdr/reporting/ReportExporter.kt
```
Expected: enum definition + usage in export method.

- [ ] **Step 5: Export format version bumped**

```bash
grep -n "EXPORT_FORMAT_VERSION\|exportFormatVersion" app/src/main/java/com/androdr/reporting/
```
Expected: the version number incremented from its prior value.

- [ ] **Step 6: "Hide informational telemetry" toggle exists**

```bash
grep -rn "hideInformationalTelemetry\|Hide informational telemetry" app/src/main/java/com/androdr/ui/timeline/
```
Expected: hits in ViewModel (state) and Screen (label).

- [ ] **Step 7: No unintended edits to plans 1 / 2 files**

```bash
git diff 9328877..HEAD -- app/src/main/java/com/androdr/sigma/RuleCategory.kt \
                           app/src/main/java/com/androdr/sigma/SeverityCapPolicy.kt \
                           app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt \
                           app/src/main/java/com/androdr/data/model/TelemetrySource.kt \
                           'app/src/main/res/raw/sigma_androdr_*.yml'
```
Expected: empty (no changes to these files in plan 3).

### Task D3: Working tree clean + commit log

- [ ] **Step 1: `git status`** — expect clean.
- [ ] **Step 2: `git log 9328877..HEAD --oneline`** — expect ~4-6 commits for plan 3.

---

## Plan 3 Retrospective Checklist

- [ ] `ForensicTimelineEvent.severity` field removed
- [ ] Room migration v15→v16 written, registered, and tested
- [ ] No code writes severity to a timeline event
- [ ] `TimelineRow` sealed type exists with `TelemetryRow` and `FindingRow`
- [ ] `TimelineViewModel` emits `StateFlow<List<TimelineRow>>`
- [ ] `TimelineScreen` renders both variants distinctly
- [ ] `TimelineEventCard` has two rendering paths
- [ ] "Hide informational telemetry" filter toggle works
- [ ] `ExportMode` enum exists with 3 values
- [ ] Export dialog shows 3 radio options with BOTH as default
- [ ] `ReportExporter.export()` takes `mode: ExportMode`
- [ ] Export format version bumped
- [ ] `testDebugUnitTest`, `lintDebug`, `assembleDebug`, `detekt` all pass
- [ ] No rule YAML, no sigma package changes, no bugreport changes

---

**End of plan 3.**

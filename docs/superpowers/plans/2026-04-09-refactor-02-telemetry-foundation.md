# Refactor Plan 2: Telemetry Foundation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Parent refactor:** Unified telemetry/findings architecture (tracking issue #84). See `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md` for the full design.

**Plan order:** Plan 2 of 7. Starts after plan 1's final commit `8b3d465`. Plans execute strictly in order on branch `claude/unified-telemetry-findings-refactor`.

**Goal:** Establish the telemetry layer foundation. Introduce a `TelemetrySource` enum, add a required `source: TelemetrySource` field to every existing runtime telemetry data class, update every runtime scanner to set `source = LIVE_SCAN` explicitly, create seven new telemetry data classes (empty shells — populated by plans 5 and 6), and reconcile `ForensicTimelineEvent`'s existing ad-hoc provenance (free-form `source: String` plus `isFromBugreport`/`isFromRuntime` booleans) into a canonical `telemetrySource: TelemetrySource` column via a Room migration. Also addresses five items flagged during plan 1 execution.

**Architecture:** `TelemetrySource` lives in `com.androdr.data.model/` and carries values `LIVE_SCAN`, `BUGREPORT_IMPORT`. The enum is source-agnostic: later plans add producers for `BUGREPORT_IMPORT` without touching the enum. Every runtime telemetry data class gains a required `source: TelemetrySource` field (no default — every constructor call must name it). `ForensicTimelineEvent` consolidates the two legacy booleans into a single enum-valued column; Room migration v14→v15 preserves existing data by mapping booleans to enum values.

**Tech Stack:** Kotlin, Android Room (migration v14→v15), JUnit 4, MockK.

**Acceptance criteria:**
- `TelemetrySource` enum exists with values `LIVE_SCAN` and `BUGREPORT_IMPORT`.
- All 7 existing runtime telemetry types (`AppTelemetry`, `AppOpsTelemetry`, `ReceiverTelemetry`, `AccessibilityTelemetry`, `DeviceTelemetry`, `ProcessTelemetry`, `FileArtifactTelemetry`) have a required `source: TelemetrySource` field.
- Every runtime scanner that constructs these types sets `source = TelemetrySource.LIVE_SCAN` explicitly.
- 7 new telemetry data classes exist with required `source: TelemetrySource` field: `PackageInstallHistoryEntry`, `BatteryDailyEvent`, `TombstoneEvent`, `WakelockAcquisition`, `PlatformCompatChange`, `SystemPropertySnapshot`, `DatabasePathObservation`. No producers yet — they're empty shells for plans 5 and 6.
- `ForensicTimelineEvent` has `telemetrySource: TelemetrySource` field. Legacy booleans `isFromBugreport` / `isFromRuntime` are removed. Room migration v14→v15 is written, tested, and preserves existing data.
- `UsageStatsScanner` (the one place in runtime scanners that writes `ForensicTimelineEvent` directly) sets `telemetrySource = LIVE_SCAN`.
- `SigmaRuleEvaluator` / `SigmaCorrelationEngine` / any other producers of `ForensicTimelineEvent` set `telemetrySource` correctly.
- Five plan 1 follow-ups addressed (see Phase E).
- `./gradlew testDebugUnitTest lintDebug assembleDebug detekt` all pass.
- Branch history shows coherent commit progression.

---

## File Structure

### Created

- `app/src/main/java/com/androdr/data/model/TelemetrySource.kt` — enum
- `app/src/main/java/com/androdr/data/model/PackageInstallHistoryEntry.kt`
- `app/src/main/java/com/androdr/data/model/BatteryDailyEvent.kt`
- `app/src/main/java/com/androdr/data/model/TombstoneEvent.kt`
- `app/src/main/java/com/androdr/data/model/WakelockAcquisition.kt`
- `app/src/main/java/com/androdr/data/model/PlatformCompatChange.kt`
- `app/src/main/java/com/androdr/data/model/SystemPropertySnapshot.kt`
- `app/src/main/java/com/androdr/data/model/DatabasePathObservation.kt`
- `app/src/test/java/com/androdr/data/db/Migration14To15Test.kt` — Room migration test

### Modified

- `app/src/main/java/com/androdr/data/model/AppTelemetry.kt` — add `source` field
- `app/src/main/java/com/androdr/data/model/AppOpsTelemetry.kt` — add `source` field
- `app/src/main/java/com/androdr/data/model/ReceiverTelemetry.kt` — add `source` field
- `app/src/main/java/com/androdr/data/model/AccessibilityTelemetry.kt` — add `source` field
- `app/src/main/java/com/androdr/data/model/DeviceTelemetry.kt` — add `source` field
- `app/src/main/java/com/androdr/data/model/ProcessTelemetry.kt` — add `source` field
- `app/src/main/java/com/androdr/data/model/FileArtifactTelemetry.kt` — add `source` field
- `app/src/main/java/com/androdr/data/model/ForensicTimelineEvent.kt` — add `telemetrySource` field, remove `isFromBugreport` / `isFromRuntime` booleans
- `app/src/main/java/com/androdr/data/db/AppDatabase.kt` — bump version to 15
- `app/src/main/java/com/androdr/data/db/Migrations.kt` — add MIGRATION_14_15
- `app/src/main/java/com/androdr/scanner/AppScanner.kt` — set `source = LIVE_SCAN`
- `app/src/main/java/com/androdr/scanner/DeviceAuditor.kt` — set `source = LIVE_SCAN`
- `app/src/main/java/com/androdr/scanner/ReceiverAuditScanner.kt` — set `source = LIVE_SCAN`
- `app/src/main/java/com/androdr/scanner/AccessibilityAuditScanner.kt` — set `source = LIVE_SCAN`
- `app/src/main/java/com/androdr/scanner/AppOpsScanner.kt` — set `source = LIVE_SCAN`
- `app/src/main/java/com/androdr/scanner/FileArtifactScanner.kt` — set `source = LIVE_SCAN`
- `app/src/main/java/com/androdr/scanner/ProcessScanner.kt` — set `source = LIVE_SCAN`
- `app/src/main/java/com/androdr/scanner/UsageStatsScanner.kt` — set `telemetrySource = LIVE_SCAN` on the `ForensicTimelineEvent` it constructs
- `app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt` — set `telemetrySource` on any emitted `ForensicTimelineEvent`
- `app/src/main/java/com/androdr/sigma/SigmaCorrelationEngine.kt` — set `telemetrySource` on emitted correlation signals
- `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt` — addresses plan 1 follow-ups (KDoc, getRules rename, disabled rule asymmetry fix)
- `app/src/main/java/com/androdr/sigma/CorrelationRule.kt` — KDoc addition
- `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt` — use `effectiveRules()` or equivalent for `atomRulesById` construction (plan 1 follow-up item 1)
- Test files that construct any of the affected telemetry types (update to include `source`)

### Not touched

- `FindingCategory` / `RuleCategory` / `SeverityCapPolicy` / any rule YAML / UI code
- Any file under `scanner/bugreport/` (that's plan 5)
- `Finding` data class body (plan 1 follow-up item 4 is addressed via KDoc only in this plan; the factory pattern is deferred)

---

## Phase A: `TelemetrySource` Enum

### Task A1: Create the `TelemetrySource` enum

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/TelemetrySource.kt`

- [ ] **Step 1: Write the file**

```kotlin
package com.androdr.data.model

import kotlinx.serialization.Serializable

/**
 * Provenance classification for every telemetry row. Identifies where the
 * data came from so analysts and rules can filter by source when needed.
 *
 * Telemetry is source-agnostic by design: the same canonical type (e.g.
 * [AppOpsTelemetry]) can be produced by multiple sources. A live-device
 * scanner emits `LIVE_SCAN`; a bugreport parser emits `BUGREPORT_IMPORT`.
 * Rules evaluate the telemetry uniformly regardless of source.
 *
 * **Every telemetry data class has a required `source: TelemetrySource`
 * field with no default.** Each constructor call must name it explicitly —
 * this prevents accidental "implicit LIVE_SCAN" drift and makes the source
 * visible in code review.
 *
 * See `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`
 * §4 for the full rationale.
 */
@Serializable
enum class TelemetrySource {
    /**
     * Produced by a runtime scanner against the current device state.
     * Examples: [AppTelemetry] from `AppScanner`, [DeviceTelemetry] from
     * `DeviceAuditor`, [ForensicTimelineEvent] from `UsageStatsScanner`.
     */
    LIVE_SCAN,

    /**
     * Produced by parsing an imported Android bugreport file. Plan 5 wires
     * up the first producers. Existing rule code paths must not assume
     * LIVE_SCAN without checking this field.
     */
    BUGREPORT_IMPORT,
}
```

- [ ] **Step 2: Compile check**

```bash
cd /home/yasir/AndroDR && ./gradlew compileDebugKotlin 2>&1 | tail -5
```
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/data/model/TelemetrySource.kt
git commit -m "refactor(telemetry): add TelemetrySource enum for provenance

Canonical two-value enum (LIVE_SCAN, BUGREPORT_IMPORT) used by every
telemetry row to identify where the data came from. Source-agnostic
by design: the same telemetry type can be produced by multiple
sources, and rules evaluate it uniformly.

Part of #84 (plan 2, phase A)."
```

---

## Phase B: Add `source` field to existing telemetry types + update runtime scanners

This phase adds the required `source: TelemetrySource` field to each of the 7 existing runtime telemetry data classes and updates every construction site in the runtime scanners to pass `source = TelemetrySource.LIVE_SCAN`. Done in one atomic commit per type to keep compilation working at every step.

### Task B1: `AppTelemetry` + `AppScanner`

**Files:**
- Modify: `app/src/main/java/com/androdr/data/model/AppTelemetry.kt`
- Modify: `app/src/main/java/com/androdr/scanner/AppScanner.kt`

- [ ] **Step 1: Add `source: TelemetrySource` as the last field of `AppTelemetry`**

Required field, no default. Position at the end of the primary constructor parameter list so it reads last when inspecting the data class.

```kotlin
// In AppTelemetry.kt, the primary constructor becomes (append `source` as the last parameter):
data class AppTelemetry(
    val packageName: String,
    // ... existing fields unchanged ...
    val firstInstallTime: Long = 0L,
    val lastUpdateTime: Long = 0L,
    val source: TelemetrySource,
)
```

- [ ] **Step 2: Update `AppScanner` to pass `source = TelemetrySource.LIVE_SCAN`**

In `AppScanner.kt`, find the `AppTelemetry(...)` constructor call (audit said around line 244). Add `source = TelemetrySource.LIVE_SCAN` as the last argument. Import `com.androdr.data.model.TelemetrySource` at the top of the file.

- [ ] **Step 3: Compile and fix any missed callers**

```bash
cd /home/yasir/AndroDR && ./gradlew compileDebugKotlin 2>&1 | tail -10
```
Expected: BUILD SUCCESSFUL. If compilation fails, it's because another file constructs `AppTelemetry` — grep for it:

```bash
grep -rn "AppTelemetry(" app/src/main/java/ app/src/test/java/
```

Update every call site to include `source = TelemetrySource.LIVE_SCAN`. For test files, the default of `LIVE_SCAN` is appropriate unless the test specifically wants to simulate a bugreport import.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/data/model/AppTelemetry.kt \
        app/src/main/java/com/androdr/scanner/AppScanner.kt
# Plus any other files that needed updating
git commit -m "refactor(telemetry): add source field to AppTelemetry, wire AppScanner

AppTelemetry gains a required source: TelemetrySource field with no
default. AppScanner sets source = LIVE_SCAN at every construction
site. Any test fixtures that construct AppTelemetry directly are
updated to include source.

Part of #84 (plan 2, phase B, step 1 of 7)."
```

### Task B2: `AppOpsTelemetry` + `AppOpsScanner`

**Files:**
- Modify: `app/src/main/java/com/androdr/data/model/AppOpsTelemetry.kt`
- Modify: `app/src/main/java/com/androdr/scanner/AppOpsScanner.kt`

- [ ] **Step 1: Add `source: TelemetrySource` as the last field of `AppOpsTelemetry`**

Same pattern as B1: required field at the end of the primary constructor.

- [ ] **Step 2: Update `AppOpsScanner` to pass `source = TelemetrySource.LIVE_SCAN`**

Audit said around line 78. Import `TelemetrySource`.

- [ ] **Step 3: Compile and fix missed callers**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -10
grep -rn "AppOpsTelemetry(" app/src/main/java/ app/src/test/java/
```

Update every construction site.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/data/model/AppOpsTelemetry.kt \
        app/src/main/java/com/androdr/scanner/AppOpsScanner.kt
# Plus test fixture files
git commit -m "refactor(telemetry): add source field to AppOpsTelemetry, wire AppOpsScanner

Part of #84 (plan 2, phase B, step 2 of 7)."
```

### Task B3: `ReceiverTelemetry` + `ReceiverAuditScanner`

Same pattern as B1/B2. Audit said constructor call is around line 47 in `ReceiverAuditScanner.kt`.

- [ ] **Step 1: Add `source: TelemetrySource` to `ReceiverTelemetry`**
- [ ] **Step 2: Update `ReceiverAuditScanner`**
- [ ] **Step 3: Compile and fix missed callers**
- [ ] **Step 4: Commit**

```bash
git commit -m "refactor(telemetry): add source field to ReceiverTelemetry, wire ReceiverAuditScanner

Part of #84 (plan 2, phase B, step 3 of 7)."
```

### Task B4: `AccessibilityTelemetry` + `AccessibilityAuditScanner`

Same pattern. Audit said constructor call is around line 30 in `AccessibilityAuditScanner.kt`.

- [ ] **Step 1: Add `source: TelemetrySource` to `AccessibilityTelemetry`**
- [ ] **Step 2: Update `AccessibilityAuditScanner`**
- [ ] **Step 3: Compile and fix missed callers**
- [ ] **Step 4: Commit**

```bash
git commit -m "refactor(telemetry): add source field to AccessibilityTelemetry, wire AccessibilityAuditScanner

Part of #84 (plan 2, phase B, step 4 of 7)."
```

### Task B5: `DeviceTelemetry` + `DeviceAuditor`

Same pattern. Audit said constructor call is around line 109 in `DeviceAuditor.kt`.

- [ ] **Step 1: Add `source: TelemetrySource` to `DeviceTelemetry`**
- [ ] **Step 2: Update `DeviceAuditor`**
- [ ] **Step 3: Compile and fix missed callers**
- [ ] **Step 4: Commit**

```bash
git commit -m "refactor(telemetry): add source field to DeviceTelemetry, wire DeviceAuditor

Part of #84 (plan 2, phase B, step 5 of 7)."
```

### Task B6: `ProcessTelemetry` + `ProcessScanner`

Same pattern. Audit said constructor call is around line 34 in `ProcessScanner.kt`.

- [ ] **Step 1: Add `source: TelemetrySource` to `ProcessTelemetry`**
- [ ] **Step 2: Update `ProcessScanner`**
- [ ] **Step 3: Compile and fix missed callers**
- [ ] **Step 4: Commit**

```bash
git commit -m "refactor(telemetry): add source field to ProcessTelemetry, wire ProcessScanner

Part of #84 (plan 2, phase B, step 6 of 7)."
```

### Task B7: `FileArtifactTelemetry` + `FileArtifactScanner`

Same pattern. Audit said constructor call is around line 51 in `FileArtifactScanner.kt`.

- [ ] **Step 1: Add `source: TelemetrySource` to `FileArtifactTelemetry`**
- [ ] **Step 2: Update `FileArtifactScanner`**
- [ ] **Step 3: Compile and fix missed callers**
- [ ] **Step 4: Commit**

```bash
git commit -m "refactor(telemetry): add source field to FileArtifactTelemetry, wire FileArtifactScanner

Part of #84 (plan 2, phase B, step 7 of 7)."
```

### Task B-final: Full-suite verification

After all 7 types are updated, run the full test suite to confirm nothing regressed.

- [ ] **Step 1: Run tests**

```bash
cd /home/yasir/AndroDR && ./gradlew testDebugUnitTest 2>&1 | tail -20
```
Expected: BUILD SUCCESSFUL. Every test passes.

- [ ] **Step 2: Run lint + assemble**

```bash
./gradlew lintDebug 2>&1 | tail -10
./gradlew assembleDebug 2>&1 | tail -5
```
Expected: both BUILD SUCCESSFUL.

If anything fails, diagnose before proceeding to phase C.

---

## Phase C: `ForensicTimelineEvent` Provenance Reconciliation

### Task C1: Add `telemetrySource` field + remove legacy booleans

**Files:**
- Modify: `app/src/main/java/com/androdr/data/model/ForensicTimelineEvent.kt`

- [ ] **Step 1: Read the current file**

```bash
cat app/src/main/java/com/androdr/data/model/ForensicTimelineEvent.kt
```

Current shape: `@Entity` Room class with fields including `source: String` (producer name, e.g. `"usage_stats"`), `isFromBugreport: Boolean = false`, `isFromRuntime: Boolean = false`, plus many others.

- [ ] **Step 2: Replace the booleans with `telemetrySource`**

In the `@Entity` annotation, add `"telemetrySource"` to the `indices` list alongside the existing indices:

```kotlin
@Entity(
    tableName = "forensic_timeline",
    indices = [
        Index("startTimestamp"),
        Index("severity"),
        Index("packageName"),
        Index("source"),
        Index("kind"),
        Index("telemetrySource"),
    ]
)
```

In the data class body: remove `val isFromBugreport: Boolean = false,` and `val isFromRuntime: Boolean = false,`. Add `val telemetrySource: TelemetrySource = TelemetrySource.LIVE_SCAN,` at the position where the booleans were. Default to LIVE_SCAN for constructor ergonomics — the Room migration will populate existing rows correctly regardless of the default.

```kotlin
// Replaces: val isFromBugreport: Boolean = false, val isFromRuntime: Boolean = false,
val telemetrySource: TelemetrySource = TelemetrySource.LIVE_SCAN,
```

Import `com.androdr.data.model.TelemetrySource` if not already imported (it's in the same package, so no import needed).

- [ ] **Step 3: Add a Room type converter for `TelemetrySource`**

Find `Converters` class (likely at `app/src/main/java/com/androdr/data/db/Converters.kt` — `grep -rn "class Converters" app/src/main/java/`). Add:

```kotlin
@TypeConverter
fun telemetrySourceToString(source: TelemetrySource): String = source.name

@TypeConverter
fun stringToTelemetrySource(value: String): TelemetrySource =
    try { TelemetrySource.valueOf(value) } catch (_: IllegalArgumentException) {
        TelemetrySource.LIVE_SCAN  // safe default for forward compatibility
    }
```

Add the import for `TelemetrySource`.

- [ ] **Step 4: Don't compile yet** — tests and callers will fail because the boolean fields were removed. That's the next task.

### Task C2: Update callers that referenced `isFromBugreport` / `isFromRuntime`

**Files:**
- Multiple — use grep to find all of them

- [ ] **Step 1: Find all references**

```bash
grep -rn "isFromBugreport\|isFromRuntime" app/src/ --include="*.kt"
```

Expected: one or more hits in `UsageStatsScanner.kt` (currently sets `isFromRuntime = true`), possibly tests, possibly views that color-code timeline events by source.

- [ ] **Step 2: Update each reference**

For each file:
- If it was writing `isFromRuntime = true` → write `telemetrySource = TelemetrySource.LIVE_SCAN`
- If it was writing `isFromBugreport = true` → write `telemetrySource = TelemetrySource.BUGREPORT_IMPORT`
- If it was writing both or neither → apply judgment based on the code context
- If it was READING the boolean fields (e.g., `if (event.isFromBugreport) { ... }`) → read `event.telemetrySource == TelemetrySource.BUGREPORT_IMPORT` instead

Specifically expected: `UsageStatsScanner.kt` (line ~126 area) currently sets `isFromRuntime = true`. Replace with `telemetrySource = TelemetrySource.LIVE_SCAN`.

- [ ] **Step 3: Update `SigmaCorrelationEngine.signal()` and any other `ForensicTimelineEvent` constructors in sigma**

```bash
grep -rn "ForensicTimelineEvent(" app/src/main/java/com/androdr/sigma/
```

Each construction site must set `telemetrySource` appropriately. For correlation findings produced from live-scan data, `LIVE_SCAN` is correct. For correlation findings produced from bugreport-imported data, `BUGREPORT_IMPORT` — but bugreport import isn't wired yet (plan 5), so all current construction sites should use `LIVE_SCAN`.

Since the field defaults to `LIVE_SCAN` in the data class, existing call sites that don't mention it will continue to work. The explicit-set requirement is for runtime scanners specifically; sigma engine code can use the default. (Rationale: sigma engine doesn't distinguish sources — it just produces findings. The source is only relevant for the telemetry itself.)

Actually, to stay consistent with the "explicit everywhere" invariant, explicitly set `telemetrySource = TelemetrySource.LIVE_SCAN` in sigma engine constructions too. It costs one line per site.

- [ ] **Step 4: Compile**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -10
```
Expected: BUILD SUCCESSFUL. If fails, look at the remaining references and fix them.

- [ ] **Step 5: Do NOT run tests yet** — the Room migration is next, and tests that instantiate the in-memory database will fail without it.

### Task C3: Write the Room migration v14→v15

**Files:**
- Modify: `app/src/main/java/com/androdr/data/db/Migrations.kt`
- Modify: `app/src/main/java/com/androdr/data/db/AppDatabase.kt`

- [ ] **Step 1: Read the existing migrations file**

```bash
cat app/src/main/java/com/androdr/data/db/Migrations.kt
```

Examine the existing migration patterns (particularly MIGRATION_11_12 shown in the audit — it uses `ALTER TABLE ... ADD COLUMN` and `RENAME COLUMN`).

- [ ] **Step 2: Add MIGRATION_14_15**

Append to `Migrations.kt`:

```kotlin
val MIGRATION_14_15 = object : Migration(14, 15) {
    override fun migrate(db: SupportSQLiteDatabase) {
        // ForensicTimelineEvent provenance reconciliation.
        //
        // Before: two booleans (isFromBugreport, isFromRuntime) indicate where
        // a timeline event came from. Neither, one, or both may be set.
        //
        // After: a single telemetrySource column (TEXT, LIVE_SCAN | BUGREPORT_IMPORT)
        // holds the canonical enum value.
        //
        // Strategy: add the new column with a default, populate it from the
        // booleans via a CASE expression, then drop the booleans by recreating
        // the table (SQLite supports DROP COLUMN only from 3.35 / API 34;
        // recreation is the compatible pattern for older Androids).
        //
        // See docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md §4.

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
                severity            TEXT NOT NULL,
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
                source, category, description, details, severity,
                packageName, appName, processUid, iocIndicator, iocType,
                iocSource, campaignName, apkHash, correlationId, ruleId,
                scanResultId, attackTechniqueId, telemetrySource, createdAt
            )
            SELECT
                id, startTimestamp, endTimestamp, kind, timestampPrecision,
                source, category, description, details, severity,
                packageName, appName, processUid, iocIndicator, iocType,
                iocSource, campaignName, apkHash, correlationId, ruleId,
                scanResultId, attackTechniqueId,
                CASE
                    WHEN isFromBugreport = 1 THEN 'BUGREPORT_IMPORT'
                    ELSE 'LIVE_SCAN'
                END,
                createdAt
            FROM forensic_timeline
        """.trimIndent())

        db.execSQL("DROP TABLE forensic_timeline")
        db.execSQL("ALTER TABLE forensic_timeline_new RENAME TO forensic_timeline")

        // Recreate all indices. Room requires the exact naming
        // `index_<table>_<column>` for Room-managed indices.
        db.execSQL("CREATE INDEX IF NOT EXISTS index_forensic_timeline_startTimestamp ON forensic_timeline(startTimestamp)")
        db.execSQL("CREATE INDEX IF NOT EXISTS index_forensic_timeline_severity ON forensic_timeline(severity)")
        db.execSQL("CREATE INDEX IF NOT EXISTS index_forensic_timeline_packageName ON forensic_timeline(packageName)")
        db.execSQL("CREATE INDEX IF NOT EXISTS index_forensic_timeline_source ON forensic_timeline(source)")
        db.execSQL("CREATE INDEX IF NOT EXISTS index_forensic_timeline_kind ON forensic_timeline(kind)")
        db.execSQL("CREATE INDEX IF NOT EXISTS index_forensic_timeline_telemetrySource ON forensic_timeline(telemetrySource)")
    }
}
```

- [ ] **Step 3: Register the migration in `AppDatabase`**

Open `AppDatabase.kt`. Find where the database builder is constructed (either in a `@Provides` Hilt module or directly). Add `MIGRATION_14_15` to the `.addMigrations(...)` list. Bump the `version` in `@Database(...)` from `14` to `15`.

```kotlin
@Database(
    entities = [ /* ... */ ],
    version = 15,
    exportSchema = false
)
```

And wherever `addMigrations` is called, add `MIGRATION_14_15`.

Search with: `grep -rn "addMigrations\|MIGRATION_" app/src/main/java/com/androdr/data/db/ app/src/main/java/com/androdr/di/`

- [ ] **Step 4: Compile**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -5
```
Expected: BUILD SUCCESSFUL.

- [ ] **Step 5: Do NOT commit yet** — test comes next.

### Task C4: Migration test

**Files:**
- Create: `app/src/test/java/com/androdr/data/db/Migration14To15Test.kt`

- [ ] **Step 1: Check existing migration test patterns**

```bash
find app/src/test -name "*Migration*Test*.kt" -o -name "*MigrationTest*.kt"
find app/src/androidTest -name "*Migration*" 2>/dev/null
```

Android Room migration tests typically live in `androidTest` (instrumentation) because they require the actual Room runtime. Check if the project has any existing migration tests to understand the pattern.

If instrumentation testing isn't feasible in this plan's scope (too slow, needs device), use a **unit test with Robolectric** instead. Check if the project uses Robolectric: `grep -rn "robolectric\|RobolectricTestRunner" app/src/test/`.

- [ ] **Step 2: Write the migration test**

If the project has Robolectric (preferred for unit-testable Room migrations):

```kotlin
package com.androdr.data.db

import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.room.Room
import androidx.room.testing.MigrationTestHelper
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull

@RunWith(AndroidJUnit4::class)
class Migration14To15Test {
    private val testDbName = "migration-test-14-15.db"

    @get:Rule
    val helper: MigrationTestHelper = MigrationTestHelper(
        androidx.test.platform.app.InstrumentationRegistry.getInstrumentation(),
        AppDatabase::class.java,
    )

    @Test
    fun `migration 14 to 15 consolidates booleans into telemetrySource`() {
        // Create the v14 database with one row representing isFromBugreport=1
        // and one row representing isFromRuntime=1.
        helper.createDatabase(testDbName, 14).use { db ->
            db.execSQL("""
                INSERT INTO forensic_timeline (
                    startTimestamp, kind, timestampPrecision, source, category,
                    description, details, severity, packageName, appName,
                    processUid, iocIndicator, iocType, iocSource, campaignName,
                    apkHash, correlationId, ruleId, scanResultId, attackTechniqueId,
                    isFromBugreport, isFromRuntime, createdAt
                ) VALUES (
                    1000, 'event', 'exact', 'bugreport_parser', 'package_install',
                    'bugreport row', '', 'medium', 'com.example.test', 'Test',
                    -1, '', '', '', '', '', '', '', -1, '',
                    1, 0, 2000
                )
            """.trimIndent())
            db.execSQL("""
                INSERT INTO forensic_timeline (
                    startTimestamp, kind, timestampPrecision, source, category,
                    description, details, severity, packageName, appName,
                    processUid, iocIndicator, iocType, iocSource, campaignName,
                    apkHash, correlationId, ruleId, scanResultId, attackTechniqueId,
                    isFromBugreport, isFromRuntime, createdAt
                ) VALUES (
                    3000, 'event', 'exact', 'usage_stats', 'app_foreground',
                    'runtime row', '', 'informational', 'com.example.runtime', 'Runtime',
                    -1, '', '', '', '', '', '', '', -1, '',
                    0, 1, 4000
                )
            """.trimIndent())
        }

        // Run the migration.
        helper.runMigrationsAndValidate(
            testDbName, 15, true, MIGRATION_14_15
        ).use { db ->
            // Verify both rows survive and have the correct telemetrySource.
            val cursor = db.query("SELECT startTimestamp, telemetrySource FROM forensic_timeline ORDER BY startTimestamp")
            assertEquals(2, cursor.count)

            cursor.moveToFirst()
            assertEquals(1000L, cursor.getLong(0))
            assertEquals("BUGREPORT_IMPORT", cursor.getString(1))

            cursor.moveToNext()
            assertEquals(3000L, cursor.getLong(0))
            assertEquals("LIVE_SCAN", cursor.getString(1))

            cursor.close()
        }
    }
}
```

If the project does NOT have Robolectric set up for migration tests, use a simplified unit test that calls the migration block manually against a manually-constructed `SupportSQLiteDatabase` mock, OR add a simple smoke test that validates the migration SQL syntax by running it against a fresh SQLite in-memory database via JDBC (if sqlite-jdbc is a test dependency).

If neither is feasible without adding new test dependencies, create the test as an instrumentation test under `app/src/androidTest/java/...` and run it with `./gradlew connectedDebugAndroidTest` (skip if no emulator is available in the execution environment; document that as a known limitation).

Whatever approach works — prioritize getting the migration covered by *some* test over a perfect test.

- [ ] **Step 3: Run the migration test**

If unit test: `./gradlew testDebugUnitTest --tests "com.androdr.data.db.Migration14To15Test"`
If instrumentation: document that it requires a device/emulator and skip execution in this plan unless one is available.

Expected: test passes, or test skips with a clear reason (no emulator).

- [ ] **Step 4: Run the full unit test suite to check for regressions**

```bash
./gradlew testDebugUnitTest 2>&1 | tail -20
```
Expected: BUILD SUCCESSFUL.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/data/model/ForensicTimelineEvent.kt \
        app/src/main/java/com/androdr/data/db/Migrations.kt \
        app/src/main/java/com/androdr/data/db/AppDatabase.kt \
        app/src/main/java/com/androdr/data/db/Converters.kt \
        app/src/main/java/com/androdr/scanner/UsageStatsScanner.kt \
        app/src/main/java/com/androdr/sigma/SigmaCorrelationEngine.kt \
        app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt
# Add any other files that referenced the legacy booleans
# Add the migration test file
git commit -m "refactor(data): consolidate ForensicTimelineEvent booleans into telemetrySource

ForensicTimelineEvent had two booleans (isFromBugreport, isFromRuntime)
that ad-hoc represented provenance. This refactor consolidates them
into a single telemetrySource: TelemetrySource enum column.

- Room schema bumped v14 → v15
- Migration 14 to 15 preserves existing data: isFromBugreport=1 → BUGREPORT_IMPORT,
  everything else → LIVE_SCAN
- Type converter added for TelemetrySource enum → String round-trip
- All callers updated to read/write telemetrySource instead of the booleans

The Room index on telemetrySource enables efficient source-filtered
queries in plan 3's timeline UI.

Part of #84 (plan 2, phase C)."
```

---

## Phase D: New Telemetry Types

Create 7 empty-shell data classes in `com.androdr.data.model/`. They have no producers yet — plans 5 and 6 wire up bugreport parsers that emit them. Each shell includes the `source: TelemetrySource` required field per the plan 2 invariant.

### Task D1: `PackageInstallHistoryEntry`

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/PackageInstallHistoryEntry.kt`

- [ ] **Step 1: Write the file**

```kotlin
package com.androdr.data.model

/**
 * A single package install or uninstall event with a timestamp.
 *
 * Currently derivable only from bugreport `batterystats --history` output
 * (plan 5's `BatteryDailyParser`). Android's live `PackageManager` API
 * only exposes `firstInstallTime` and `lastUpdateTime` for currently-installed
 * packages, not a full history — this telemetry type fills that gap from
 * bugreport data.
 *
 * Source-agnostic: if a future Android API ever exposes install history,
 * the live scanner can emit the same type without changing rule code.
 *
 * @property packageName fully-qualified package name
 * @property eventType INSTALL, UNINSTALL, or UPDATE
 * @property timestamp epoch milliseconds
 * @property versionCode app version code at the time of the event, if known
 * @property source where this row came from (always BUGREPORT_IMPORT today;
 *                  no runtime producer currently exists)
 * @property capturedAt epoch milliseconds when the scan/import produced this row
 */
data class PackageInstallHistoryEntry(
    val packageName: String,
    val eventType: PackageHistoryEventType,
    val timestamp: Long,
    val versionCode: Long?,
    val source: TelemetrySource,
    val capturedAt: Long,
)

enum class PackageHistoryEventType {
    INSTALL,
    UNINSTALL,
    UPDATE,
}
```

- [ ] **Step 2: Compile**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -5
```
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: No commit yet** — batch all 7 new types into one or two commits.

### Task D2: `BatteryDailyEvent`

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/BatteryDailyEvent.kt`

- [ ] **Step 1: Write the file**

```kotlin
package com.androdr.data.model

/**
 * A single entry from Android's `batterystats --daily` output representing
 * a notable event in the per-day battery history. Currently captured from
 * imported bugreports only.
 *
 * Used by plan 6's new rules to detect anti-forensics patterns (e.g.,
 * package uninstall with known-bad IOC hit, version downgrade).
 *
 * @property dayIndex the day number within the bugreport's battery history
 * @property eventType e.g. "package_uninstall", "version_downgrade"
 * @property packageName affected package, if applicable
 * @property description free-form description from the bugreport entry
 * @property source where this row came from
 * @property capturedAt epoch milliseconds when the scan/import produced this row
 */
data class BatteryDailyEvent(
    val dayIndex: Int,
    val eventType: String,
    val packageName: String?,
    val description: String,
    val source: TelemetrySource,
    val capturedAt: Long,
)
```

### Task D3: `TombstoneEvent`

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/TombstoneEvent.kt`

- [ ] **Step 1: Write the file**

```kotlin
package com.androdr.data.model

/**
 * A parsed Android tombstone record representing a single process crash.
 * Plan 6's new `sigma_androdr_crash_loop_anti_forensics.yml` rule evaluates
 * these via correlation (multiple crashes for the same package within a
 * time window indicate potential exploit-then-crash behavior).
 *
 * Parsed from bugreport `tombstones/` section by plan 5's `TombstoneParser`.
 *
 * @property processName the crashed process name
 * @property packageName the owning package, if derivable
 * @property signalNumber the crash signal (e.g. 11 for SIGSEGV), null for abort
 * @property abortMessage the abort reason for non-signal aborts
 * @property crashTimestamp epoch milliseconds from the tombstone header
 * @property source where this row came from
 * @property capturedAt epoch milliseconds when the scan/import produced this row
 */
data class TombstoneEvent(
    val processName: String,
    val packageName: String?,
    val signalNumber: Int?,
    val abortMessage: String?,
    val crashTimestamp: Long,
    val source: TelemetrySource,
    val capturedAt: Long,
)
```

### Task D4: `WakelockAcquisition`

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/WakelockAcquisition.kt`

- [ ] **Step 1: Write the file**

```kotlin
package com.androdr.data.model

/**
 * A structured wakelock acquisition record parsed from bugreport power
 * sections. Plan 6's new `sigma_androdr_persistent_wakelock.yml` rule
 * evaluates wakelock density over time windows to flag always-on surveillance
 * behavior — though the rule ships disabled-by-default pending UAT
 * threshold calibration (#87).
 *
 * @property packageName the package holding the wakelock
 * @property wakelockTag the tag string identifying the wakelock purpose
 * @property acquiredAt epoch milliseconds when the wakelock was acquired
 * @property durationMillis how long it was held, or null if still held / unknown
 * @property source where this row came from
 * @property capturedAt epoch milliseconds when the scan/import produced this row
 */
data class WakelockAcquisition(
    val packageName: String,
    val wakelockTag: String,
    val acquiredAt: Long,
    val durationMillis: Long?,
    val source: TelemetrySource,
    val capturedAt: Long,
)
```

### Task D5: `PlatformCompatChange`

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/PlatformCompatChange.kt`

- [ ] **Step 1: Write the file**

```kotlin
package com.androdr.data.model

/**
 * A platform-compat framework ChangeId toggle record. Plan 6's
 * anti-analysis detection rule looks for specific ChangeId values
 * (e.g. DOWNSCALED = 168419799) that indicate targeted compatibility
 * overrides applied by an attacker or a debugging session.
 *
 * Parsed from bugreport `dumpsys platform_compat` output.
 *
 * @property changeId the compat ChangeId as a string (large numeric values)
 * @property packageName the affected package
 * @property enabled whether the ChangeId is currently enabled
 * @property source where this row came from
 * @property capturedAt epoch milliseconds when the scan/import produced this row
 */
data class PlatformCompatChange(
    val changeId: String,
    val packageName: String,
    val enabled: Boolean,
    val source: TelemetrySource,
    val capturedAt: Long,
)
```

### Task D6: `SystemPropertySnapshot`

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/SystemPropertySnapshot.kt`

- [ ] **Step 1: Write the file**

```kotlin
package com.androdr.data.model

/**
 * A snapshot of a system property extracted from a bugreport.
 *
 * Enables rules that evaluate `ro.*` and `persist.*` properties (bootloader
 * state, verified boot state, build fingerprint, etc.) to work on imported
 * bugreports the same way they work on live scans via `DeviceAuditor`.
 *
 * @property key the system property key (e.g. `ro.boot.verifiedbootstate`)
 * @property value the system property value at the time of the snapshot
 * @property source where this row came from
 * @property capturedAt epoch milliseconds when the scan/import produced this row
 */
data class SystemPropertySnapshot(
    val key: String,
    val value: String,
    val source: TelemetrySource,
    val capturedAt: Long,
)
```

### Task D7: `DatabasePathObservation`

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/DatabasePathObservation.kt`

- [ ] **Step 1: Write the file**

```kotlin
package com.androdr.data.model

/**
 * An observation that a known-sensitive database path was referenced in a
 * bugreport (e.g. `contacts2.db`, `mmssms.db`, `telephony.db`). Plan 6
 * introduces a rule that flags unusual database access patterns from
 * non-system processes.
 *
 * The sensitive path list lives in a YAML resource (not hardcoded in
 * Kotlin) per the policy that detection data stays in rules.
 *
 * @property filePath the observed database file path
 * @property processName the process that referenced it, if known
 * @property packageName the owning package, if derivable
 * @property observationTimestamp epoch milliseconds of the reference
 * @property source where this row came from
 * @property capturedAt epoch milliseconds when the scan/import produced this row
 */
data class DatabasePathObservation(
    val filePath: String,
    val processName: String?,
    val packageName: String?,
    val observationTimestamp: Long,
    val source: TelemetrySource,
    val capturedAt: Long,
)
```

### Task D8: Batch commit for new telemetry types

- [ ] **Step 1: Verify all 7 files exist and compile**

```bash
ls app/src/main/java/com/androdr/data/model/PackageInstallHistoryEntry.kt \
   app/src/main/java/com/androdr/data/model/BatteryDailyEvent.kt \
   app/src/main/java/com/androdr/data/model/TombstoneEvent.kt \
   app/src/main/java/com/androdr/data/model/WakelockAcquisition.kt \
   app/src/main/java/com/androdr/data/model/PlatformCompatChange.kt \
   app/src/main/java/com/androdr/data/model/SystemPropertySnapshot.kt \
   app/src/main/java/com/androdr/data/model/DatabasePathObservation.kt

./gradlew compileDebugKotlin 2>&1 | tail -5
```
Expected: all 7 files listed, BUILD SUCCESSFUL.

- [ ] **Step 2: Commit all 7 together**

```bash
git add app/src/main/java/com/androdr/data/model/PackageInstallHistoryEntry.kt \
        app/src/main/java/com/androdr/data/model/BatteryDailyEvent.kt \
        app/src/main/java/com/androdr/data/model/TombstoneEvent.kt \
        app/src/main/java/com/androdr/data/model/WakelockAcquisition.kt \
        app/src/main/java/com/androdr/data/model/PlatformCompatChange.kt \
        app/src/main/java/com/androdr/data/model/SystemPropertySnapshot.kt \
        app/src/main/java/com/androdr/data/model/DatabasePathObservation.kt
git commit -m "refactor(telemetry): add 7 new telemetry shell types

Seven new data classes in com.androdr.data.model, each with a required
source: TelemetrySource field. No producers yet — plans 5 and 6 wire
up bugreport parsers that emit them.

- PackageInstallHistoryEntry: install/uninstall events with timestamps
- BatteryDailyEvent: per-day battery history entries
- TombstoneEvent: parsed process crash records
- WakelockAcquisition: structured wakelock acquisition records
- PlatformCompatChange: ChangeId toggle records
- SystemPropertySnapshot: system property key/value snapshots
- DatabasePathObservation: sensitive database path observations

All named after facts, not sources (no BugReport prefix). Source-agnostic
per spec §4 — future runtime producers can emit the same types without
rule changes.

Part of #84 (plan 2, phase D)."
```

---

## Phase E: Plan 1 Follow-ups

Address the five items flagged during plan 1 execution.

### Task E1: KDoc additions (items 3 and 5)

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/CorrelationRule.kt`
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt`

- [ ] **Step 1: Add KDoc to `CorrelationRule` noting that category is derived, never stored**

Open `CorrelationRule.kt`. Add a class-level KDoc comment above the `CorrelationRule` data class:

```kotlin
/**
 * A parsed SIGMA correlation rule.
 *
 * Unlike [SigmaRule] (detection/atom rules), `CorrelationRule` does NOT
 * declare a [RuleCategory] field. The effective category of a correlation
 * is **derived at evaluation time** from its member rule categories via
 * [SigmaCorrelationEngine.computeEffectiveCategory]: if any member rule
 * is [RuleCategory.INCIDENT], the correlation is INCIDENT; otherwise
 * DEVICE_POSTURE. See spec §6 for the propagation rule.
 *
 * Category is never stored on this class because it would diverge from
 * member rule categories if they changed independently.
 */
data class CorrelationRule(
    // ... existing body unchanged ...
```

- [ ] **Step 2: Add KDoc to `SigmaRuleEngine.ruleCount()`**

Open `SigmaRuleEngine.kt`. Find `ruleCount()` (around line 210 per plan 1 review). Add:

```kotlin
/**
 * Returns the total number of loaded rules, **including rules with
 * `enabled: false`**. Callers wanting the count of active (evaluable)
 * rules should filter separately:
 *
 *     getRules().count { it.enabled }
 *
 * This method does NOT use [effectiveRules] because UI and debug paths
 * may want to show "X total, Y disabled" — the distinction is the
 * caller's responsibility.
 */
fun ruleCount(): Int = rules.size
```

- [ ] **Step 3: Compile**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -5
```

### Task E2: Fix disabled-rule asymmetry (item 1)

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt`

- [ ] **Step 1: Find the two `atomRulesById` construction sites**

```bash
grep -n "atomRulesById" app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt
```

Expected: two lines around 367 and 517 that build `sigmaRuleEngine.getRules().associateBy { it.id }`.

- [ ] **Step 2: Filter by `enabled`**

Replace `sigmaRuleEngine.getRules().associateBy { it.id }` with `sigmaRuleEngine.getRules().filter { it.enabled }.associateBy { it.id }` at both sites.

Add a brief comment above the first occurrence explaining why:

```kotlin
// Only enabled rules contribute to correlation category propagation.
// Including disabled rules here would let their category influence
// correlation classifications even though they produce no bindings.
val atomRulesById = sigmaRuleEngine.getRules().filter { it.enabled }.associateBy { it.id }
```

The second occurrence can just use the filter without the comment (reference the first site in the commit message).

- [ ] **Step 3: Compile and run sigma tests**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -5
./gradlew testDebugUnitTest --tests "com.androdr.sigma.*" 2>&1 | tail -10
```
Expected: BUILD SUCCESSFUL. No regressions.

### Task E3: Reduce `getRules()` footgun (item 2)

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt`

The reviewer suggested either reducing visibility or adding a `getEnabledRules()` alias. Reducing visibility is risky (might break callers). Adding an alias is additive and less invasive.

- [ ] **Step 1: Add a public `getEnabledRules()` method**

In `SigmaRuleEngine.kt`, below `getRules()` and `effectiveRules()`, add:

```kotlin
/**
 * Returns all rules with `enabled: true`. Use this for evaluation-path
 * code that must not include disabled rules (e.g. correlation lookups,
 * rule-count displays for "active rules").
 *
 * [getRules] returns ALL rules including disabled ones for diagnostic
 * and UI purposes. If a caller cannot tolerate disabled rules in its
 * iteration, it must use this method instead of [getRules].
 *
 * This is a thin public wrapper over the internal [effectiveRules];
 * it exists to give external callers a discoverable API for the
 * enabled-only rule set.
 */
fun getEnabledRules(): List<SigmaRule> = effectiveRules()
```

- [ ] **Step 2: Update `ScanOrchestrator` to use `getEnabledRules()` instead of the inline filter**

Go back to the two sites from E2 and replace:

```kotlin
sigmaRuleEngine.getRules().filter { it.enabled }.associateBy { it.id }
```

with:

```kotlin
sigmaRuleEngine.getEnabledRules().associateBy { it.id }
```

This makes the intent clearer and keeps the filter in one place.

- [ ] **Step 3: Add a KDoc cross-reference on `getRules()`**

In `SigmaRuleEngine.kt`, find `getRules()` (the existing public method) and add:

```kotlin
/**
 * Returns ALL rules, including rules with `enabled: false`.
 *
 * Prefer [getEnabledRules] when iterating for evaluation. This method
 * is intended for diagnostics, UI displays that show "X of Y rules
 * active", and any code path that must account for disabled rules.
 *
 * Callers that iterate this list to produce findings or correlation
 * bindings must filter by `enabled` themselves or use [getEnabledRules].
 */
fun getRules(): List<SigmaRule> = rules
```

- [ ] **Step 4: Compile and run tests**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -5
./gradlew testDebugUnitTest --tests "com.androdr.sigma.*" 2>&1 | tail -10
```

### Task E4: `Finding` factory KDoc warning (item 4)

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt` (where `Finding` is defined)

- [ ] **Step 1: Find the `Finding` data class declaration**

Per the plan 1 audit, `Finding` is declared near the top of `SigmaRuleEvaluator.kt`. Locate it.

- [ ] **Step 2: Add a class-level KDoc warning against direct construction**

```kotlin
/**
 * A rule-produced finding with a rule-sourced severity.
 *
 * **Construction policy:** production code should never construct `Finding`
 * directly. The [SigmaRuleEvaluator.buildFinding] method is the only
 * sanctioned factory: it applies [SeverityCapPolicy.applyCap] automatically
 * and ensures the finding's [level] respects the rule's category cap.
 *
 * Bypassing `buildFinding` risks shipping a finding whose severity exceeds
 * the cap for its category (e.g. a device_posture finding at CRITICAL),
 * which violates the spec §6 invariant.
 *
 * Test code may construct [Finding] directly with any [level], but such
 * tests must NOT be used to exercise the cap policy (the cap is in
 * `buildFinding`, not in the data class).
 *
 * See spec §6 and [SeverityCapPolicy] for the full rationale.
 */
@kotlinx.serialization.Serializable
data class Finding(
    // ... existing body unchanged ...
```

- [ ] **Step 3: Compile**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -5
```

### Task E5: Commit all plan 1 follow-ups together

- [ ] **Step 1: Stage and commit**

```bash
git add app/src/main/java/com/androdr/sigma/CorrelationRule.kt \
        app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt \
        app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt \
        app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt
git commit -m "refactor(sigma): address plan 1 follow-ups (#84)

Five items flagged during plan 1 execution:

1. Disabled rule asymmetry fixed: ScanOrchestrator now builds
   atomRulesById from getEnabledRules() instead of getRules(), so
   disabled atom rules no longer influence correlation category
   propagation.

2. getRules() footgun reduced: added public getEnabledRules() alias
   over the internal effectiveRules() helper. KDoc on getRules()
   explains when to use each.

3. CorrelationRule KDoc now explicitly notes 'category is derived,
   never stored' — preventing future contributors from adding a
   category field that would diverge from member rule categories.

4. Finding class KDoc now warns against direct construction,
   pointing callers at SigmaRuleEvaluator.buildFinding as the
   sanctioned factory that applies SeverityCapPolicy automatically.

5. ruleCount() KDoc clarifies that the count includes disabled
   rules, with an example of how to filter.

None of these are behavior changes to production code paths except
#1 (disabled-rule asymmetry fix), which has no observable effect
today because no atom rules currently ship disabled.

Part of #84 (plan 2, phase E)."
```

---

## Phase F: Final Verification

### Task F1: Run the full check suite

- [ ] **Step 1: Unit tests**

```bash
cd /home/yasir/AndroDR && ./gradlew testDebugUnitTest 2>&1 | tail -20
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
Expected: BUILD SUCCESSFUL.

If any check fails, report the failure and STOP. Do not proceed.

### Task F2: Verify invariants

- [ ] **Step 1: TelemetrySource is required on every affected data class**

```bash
for f in AppTelemetry AppOpsTelemetry ReceiverTelemetry AccessibilityTelemetry \
         DeviceTelemetry ProcessTelemetry FileArtifactTelemetry \
         PackageInstallHistoryEntry BatteryDailyEvent TombstoneEvent \
         WakelockAcquisition PlatformCompatChange SystemPropertySnapshot \
         DatabasePathObservation; do
    grep -l "val source: TelemetrySource" "app/src/main/java/com/androdr/data/model/$f.kt" \
        && echo "$f: has source field" \
        || echo "$f: MISSING source field"
done
```
Expected: every line says "has source field".

- [ ] **Step 2: No runtime scanner omits `source = TelemetrySource.LIVE_SCAN`**

```bash
for scanner in AppScanner DeviceAuditor ReceiverAuditScanner AccessibilityAuditScanner \
               AppOpsScanner FileArtifactScanner ProcessScanner; do
    grep -c "source = TelemetrySource.LIVE_SCAN" "app/src/main/java/com/androdr/scanner/$scanner.kt" \
        && echo "$scanner: sets source" \
        || echo "$scanner: MISSING explicit source set"
done
```
Expected: every scanner has at least one matching line.

- [ ] **Step 3: Legacy booleans are gone from `ForensicTimelineEvent`**

```bash
grep -c "isFromBugreport\|isFromRuntime" app/src/main/java/com/androdr/data/model/ForensicTimelineEvent.kt
```
Expected: 0.

- [ ] **Step 4: `MIGRATION_14_15` is registered**

```bash
grep -rn "MIGRATION_14_15" app/src/main/java/
```
Expected: at least 2 matches (the definition in Migrations.kt and the registration in AppDatabase.kt or the Hilt module).

### Task F3: Plan 2 completion commit

- [ ] **Step 1: Verify working tree is clean**

```bash
git status
```
Expected: `nothing to commit, working tree clean`.

- [ ] **Step 2: Commit log**

```bash
git log 8b3d465..HEAD --oneline
```

Expected: ~12-15 commits for plan 2.

- [ ] **Step 3: Report completion**

Plan 2 is complete. Plan 3 is written next.

---

## Plan 2 Retrospective Checklist

- [ ] `TelemetrySource` enum exists with `LIVE_SCAN` and `BUGREPORT_IMPORT`
- [ ] All 7 existing runtime telemetry types have required `source: TelemetrySource`
- [ ] All 7 runtime scanners set `source = TelemetrySource.LIVE_SCAN` explicitly
- [ ] 7 new telemetry shell types exist with required `source: TelemetrySource`
- [ ] `ForensicTimelineEvent` has `telemetrySource: TelemetrySource`, no `isFromBugreport`/`isFromRuntime`
- [ ] Room `MIGRATION_14_15` preserves existing data correctly (tested)
- [ ] Room `AppDatabase.version = 15` and `MIGRATION_14_15` is registered
- [ ] `TelemetrySource` Room type converter exists
- [ ] `UsageStatsScanner` sets `telemetrySource = LIVE_SCAN` on `ForensicTimelineEvent`
- [ ] Plan 1 follow-ups 1-5 addressed (disabled-rule asymmetry, getRules/getEnabledRules, CorrelationRule KDoc, Finding factory KDoc, ruleCount KDoc)
- [ ] `./gradlew testDebugUnitTest lintDebug assembleDebug detekt` all pass
- [ ] No rule YAML modified
- [ ] `Evidence.kt`, `SeverityCapPolicy.kt`, `SigmaRuleParser.kt`, `RuleCategory.kt`, UI code, rule files — untouched
- [ ] Branch unchanged

---

**End of plan 2.**

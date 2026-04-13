# Refactor Plan 5: Bugreport Parser Ports

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Parent refactor:** Unified telemetry/findings architecture (#84). Spec: `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`, §7.

**Plan order:** Plan 5 of 7. Starts after plan 4's final commit. Serialized execution on `claude/unified-telemetry-findings-refactor`.

**Goal:** Convert each bugreport module from a hardcoded finding-producer into a telemetry producer. Each module reads its section of the bugreport via the shared parser, emits canonical telemetry types (from plans 1-2), and **stops creating `BugReportFinding` objects directly**. The finding production happens downstream when `BugReportAnalyzer` invokes `SigmaRuleEngine` on the new telemetry. Also create two new parsers (`TombstoneParser`, `WakelockParser`) to feed the telemetry shell types created in plan 2.

**Plan 5 does NOT**:
- Delete `LegacyScanModule` (plan 6)
- Delete `BugReportFinding` type (plan 6)
- Modify sigma rules or rule YAML
- Touch UI code (plans 3 already done)

**Architecture:**
- Each bugreport module (`AppOpsModule`, `ReceiverModule`, `ActivityModule`, `AccessibilityModule`, `BatteryDailyModule`, `PlatformCompatModule`, `DbInfoModule`) is refactored per-commit to emit telemetry instead of findings.
- Each module's hardcoded Kotlin constants (`dangerousOps`, `sensitiveIntents`, `sensitiveSchemes`, `sensitiveDbPaths`, three copies of `systemPackagePrefixes`) are deleted. Package filtering uses `OemPrefixResolver` (already exists). Intent / scheme / ops filtering is moved into the rules that evaluate the telemetry (or just emits everything and lets the rule filter).
- `TombstoneParser` (new): parses the tombstone section of a bugreport into `TombstoneEvent` telemetry.
- `WakelockParser` (new): parses the power/wakelock section into `WakelockAcquisition` telemetry.
- `BugReportAnalyzer` gains a dispatch path for new-style (telemetry-producing) modules alongside its existing dispatch path for old-style modules. `LegacyScanModule` remains on the old path until plan 6 deletes it.

**Tech Stack:** Kotlin, Hilt, snakeyaml (for any YAML-driven configuration), JUnit 4 + MockK.

**Acceptance criteria:**
- Seven bugreport modules emit telemetry objects (`AppOpsTelemetry`, `ReceiverTelemetry`, `ForensicTimelineEvent` + new telemetry types, `AccessibilityTelemetry`, `BatteryDailyEvent` + `PackageInstallHistoryEntry`, `PlatformCompatChange`, `DatabasePathObservation`) with `source = TelemetrySource.BUGREPORT_IMPORT`.
- Each module's hardcoded Kotlin lists (`sensitiveIntents`, `sensitiveSchemes`, `sensitiveDbPaths`, `dangerousOps`, `systemPackagePrefixes`) are deleted. Filtering moves to `OemPrefixResolver` or to the rules.
- `TombstoneParser` and `WakelockParser` exist and emit telemetry.
- `BugReportAnalyzer` routes new-style modules' telemetry into `SigmaRuleEngine` evaluation alongside the existing hardcoded path.
- `LegacyScanModule` still exists (untouched) — plan 6 deletes it.
- `BugReportFinding` type still exists (will be deleted in plan 6 once all consumers are migrated).
- All gradle checks pass.
- Existing test fixtures updated where needed.
- No sigma package code, no UI code, no rule YAML (except consumption of existing rules) touched.

---

## Scope note: what this plan does NOT solve

Plan 5 leaves two remaining coexistence points that plan 6 fully resolves:

1. **`LegacyScanModule`** still runs and produces `BugReportFinding`. It contains the 5 heuristics (graphite keyword, base64 blob, C2 beacon, crash loop, wakelock density) that plan 6 teardown handles.

2. **`BugReportFinding` type still exists** because `LegacyScanModule` still uses it. Plan 6 deletes both.

During plan 5 execution, `BugReportAnalyzer` has two parallel dispatch paths: new-style modules (telemetry → rule engine) and old-style modules (still emitting `BugReportFinding`). The paths produce disjoint findings — no duplication risk.

---

## File Structure

### Created

- `app/src/main/java/com/androdr/scanner/bugreport/BugReportParser.kt` — shared tokenizer interface + default implementation
- `app/src/main/java/com/androdr/scanner/bugreport/TombstoneParser.kt` — parses tombstone section into `TombstoneEvent` telemetry
- `app/src/main/java/com/androdr/scanner/bugreport/WakelockParser.kt` — parses power section into `WakelockAcquisition` telemetry
- Unit tests for the new parsers

### Modified (per-module ports)

- `app/src/main/java/com/androdr/scanner/bugreport/AppOpsModule.kt` — emit `AppOpsTelemetry`, delete `dangerousOps`, delete severity ternary
- `app/src/main/java/com/androdr/scanner/bugreport/ReceiverModule.kt` — emit `ReceiverTelemetry`, delete `sensitiveIntents`, delete `systemPackagePrefixes`
- `app/src/main/java/com/androdr/scanner/bugreport/ActivityModule.kt` — emit `ForensicTimelineEvent` + any new `IntentObservation` shell, delete `sensitiveSchemes`, delete `systemPackagePrefixes`
- `app/src/main/java/com/androdr/scanner/bugreport/AccessibilityModule.kt` — emit `AccessibilityTelemetry`, delete `systemPackagePrefixes`
- `app/src/main/java/com/androdr/scanner/bugreport/BatteryDailyModule.kt` — emit `BatteryDailyEvent` + `PackageInstallHistoryEntry`, delete hardcoded `severity = "HIGH"` literals
- `app/src/main/java/com/androdr/scanner/bugreport/PlatformCompatModule.kt` — emit `PlatformCompatChange`, delete `CHANGE_ID_DOWNSCALED` constant
- `app/src/main/java/com/androdr/scanner/bugreport/DbInfoModule.kt` — emit `DatabasePathObservation`, delete `sensitiveDbPaths`
- `app/src/main/java/com/androdr/scanner/bugreport/BugReportAnalyzer.kt` — add dispatch for new-style modules; invoke SigmaRuleEngine on their telemetry

### Not touched

- `LegacyScanModule.kt` (plan 6)
- `BugReportFinding` type (plan 6)
- Any sigma package file
- Any rule YAML
- Any UI or reporting code
- Any data model file (telemetry types established in plan 2)

---

## Phase A: Shared `BugReportParser` + New Parsers

### Task A1: Audit existing bugreport infrastructure

- [ ] **Step 1: Read each bugreport module to understand the current state**

```bash
cd /home/yasir/AndroDR
ls app/src/main/java/com/androdr/scanner/bugreport/
for f in app/src/main/java/com/androdr/scanner/bugreport/*.kt; do
    echo "=== $f ==="
    wc -l "$f"
done
```

Note:
- Which files exist today
- Line counts (to gauge complexity)
- Any shared infrastructure already present (e.g. a `BugReportSectionParser` or similar)

- [ ] **Step 2: Read `BugReportAnalyzer.kt` in full**

```bash
cat app/src/main/java/com/androdr/scanner/bugreport/BugReportAnalyzer.kt
```

Understand:
- How modules are dispatched (a list, a Hilt multibind, a manual sequence)
- What type the current modules return (`ModuleResult`, `BugReportFinding`, timeline events, or a mix)
- The flow from parse → dispatch → collect → return

This is the file that will be modified to add the new-style dispatch path in phase C.

- [ ] **Step 3: Check for existing tokenization**

The modules probably each have their own parsing logic. Check if there's a shared line-by-line or section-based helper already:

```bash
grep -rn "bufferedReader\|readLines\|BufferedReader" app/src/main/java/com/androdr/scanner/bugreport/
```

If a shared tokenizer already exists, adapt the plan to use it. If not, create a minimal one in task A2.

### Task A2: Create shared `BugReportParser` (if not already present)

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/bugreport/BugReportParser.kt` — if and only if no shared parser exists

- [ ] **Step 1: Decide whether to create it**

If the existing modules each use their own parsing and there's no clear shared infrastructure, create a minimal interface:

```kotlin
package com.androdr.scanner.bugreport

import java.io.BufferedReader

/**
 * Shared line-level tokenizer for bugreport text files. Each bugreport
 * module receives a Sequence of lines or a reader to consume its section.
 *
 * This is intentionally minimal — the main job is avoiding per-module
 * re-reads of the same file. Section-level boundaries are identified
 * by each consuming module because Android bugreport section headers
 * vary by Android version.
 */
interface BugReportParser {
    /**
     * Returns a sequence over the full bugreport file. Callers should
     * filter to their section of interest (e.g. via `dropWhile` + `takeWhile`
     * on section markers).
     */
    fun lines(): Sequence<String>
}
```

With a default implementation that wraps a file/reader:

```kotlin
class BufferedBugReportParser(
    private val readerFactory: () -> BufferedReader,
) : BugReportParser {
    override fun lines(): Sequence<String> = sequence {
        readerFactory().useLines { seq -> seq.forEach { yield(it) } }
    }
}
```

If, however, the existing `BugReportAnalyzer.kt` already handles file reading and passes parsed sections to each module, DO NOT create a new parser — the infrastructure is already good enough. Just use what's there.

- [ ] **Step 2: Don't commit yet** — commit alongside the first module port or the new parsers.

### Task A3: Create `TombstoneParser`

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/bugreport/TombstoneParser.kt`
- Create: `app/src/test/java/com/androdr/scanner/bugreport/TombstoneParserTest.kt`

- [ ] **Step 1: Understand tombstone format**

Android bugreport tombstone sections look like:

```
*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
Build fingerprint: 'google/blueline/blueline:10/QQ1A.200205.002/6084886:user/release-keys'
Revision: 'MP1.0'
ABI: 'arm64'
Timestamp: 2020-02-14 09:23:45+0000
pid: 1234, tid: 1234, name: com.example.app  >>> com.example.app <<<
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x1234
...
```

Key fields: timestamp, pid, process name (from `name:` or `>>> ... <<<`), signal number, package name.

- [ ] **Step 2: Write the parser**

```kotlin
package com.androdr.scanner.bugreport

import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TombstoneEvent
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Parses the tombstone section of an Android bugreport into [TombstoneEvent]
 * telemetry. A tombstone is a process crash record; multiple crashes for the
 * same package within a time window indicate potential exploit-then-crash
 * behavior (evaluated by plan 6's crash-loop rule).
 *
 * Tombstone format (typical):
 *   Timestamp: 2020-02-14 09:23:45+0000
 *   pid: 1234, tid: 1234, name: com.example.app  >>> com.example.app <<<
 *   signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x1234
 *
 * Abort messages may appear for non-signal tombstones via an `Abort message:` line.
 */
@Singleton
class TombstoneParser @Inject constructor() {

    private val timestampFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ", Locale.US).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }

    /**
     * Parses tombstone records from a sequence of bugreport lines. Each
     * record begins with a `Timestamp:` line and contains subsequent fields
     * until the next Timestamp or section boundary.
     *
     * @param lines the full bugreport line sequence, or a pre-filtered slice
     *              containing only tombstone section lines
     * @param capturedAt epoch milliseconds to set on emitted telemetry rows
     * @return list of parsed tombstone events (empty if none found)
     */
    fun parse(lines: Sequence<String>, capturedAt: Long): List<TombstoneEvent> {
        val events = mutableListOf<TombstoneEvent>()
        var currentTimestamp: Long? = null
        var currentProcessName: String? = null
        var currentPackageName: String? = null
        var currentSignal: Int? = null
        var currentAbort: String? = null

        fun flush() {
            val ts = currentTimestamp ?: return
            val process = currentProcessName ?: return
            events += TombstoneEvent(
                processName = process,
                packageName = currentPackageName,
                signalNumber = currentSignal,
                abortMessage = currentAbort,
                crashTimestamp = ts,
                source = TelemetrySource.BUGREPORT_IMPORT,
                capturedAt = capturedAt,
            )
            currentTimestamp = null
            currentProcessName = null
            currentPackageName = null
            currentSignal = null
            currentAbort = null
        }

        for (line in lines) {
            when {
                line.startsWith("Timestamp:") -> {
                    // New record — flush any pending one first.
                    flush()
                    val tsStr = line.removePrefix("Timestamp:").trim()
                    currentTimestamp = runCatching { timestampFormat.parse(tsStr)?.time }.getOrNull()
                }
                line.startsWith("pid:") -> {
                    // Example: "pid: 1234, tid: 1234, name: com.example.app  >>> com.example.app <<<"
                    val nameMarker = ">>>"
                    if (line.contains(nameMarker)) {
                        currentPackageName = line.substringAfter(nameMarker).substringBefore("<<<").trim()
                    }
                    val nameField = Regex("name: ([^\\s]+)").find(line)
                    currentProcessName = nameField?.groupValues?.get(1)
                }
                line.startsWith("signal ") -> {
                    val signalMatch = Regex("^signal (\\d+)").find(line)
                    currentSignal = signalMatch?.groupValues?.get(1)?.toIntOrNull()
                }
                line.startsWith("Abort message:") -> {
                    currentAbort = line.removePrefix("Abort message:").trim().trim('\'', '"')
                }
            }
        }
        flush()
        return events
    }
}
```

- [ ] **Step 3: Write unit tests**

```kotlin
package com.androdr.scanner.bugreport

import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class TombstoneParserTest {

    private val parser = TombstoneParser()

    @Test
    fun `parses a single tombstone record with signal`() {
        val lines = """
            Build fingerprint: test
            Timestamp: 2020-02-14 09:23:45+0000
            pid: 1234, tid: 1234, name: com.example.app  >>> com.example.app <<<
            signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x1234
        """.trimIndent().lines().asSequence()

        val events = parser.parse(lines, capturedAt = 5000L)

        assertEquals(1, events.size)
        val e = events.first()
        assertEquals("com.example.app", e.processName)
        assertEquals("com.example.app", e.packageName)
        assertEquals(11, e.signalNumber)
        assertNull(e.abortMessage)
        assertNotNull(e.crashTimestamp)
        assertEquals(TelemetrySource.BUGREPORT_IMPORT, e.source)
        assertEquals(5000L, e.capturedAt)
    }

    @Test
    fun `parses an abort-style tombstone without signal`() {
        val lines = """
            Timestamp: 2020-02-14 09:23:45+0000
            pid: 5678, tid: 5678, name: com.example.crash  >>> com.example.crash <<<
            Abort message: 'assertion failed'
        """.trimIndent().lines().asSequence()

        val events = parser.parse(lines, capturedAt = 1000L)

        assertEquals(1, events.size)
        val e = events.first()
        assertEquals("com.example.crash", e.processName)
        assertEquals("assertion failed", e.abortMessage)
        assertNull(e.signalNumber)
    }

    @Test
    fun `parses multiple records separated by timestamps`() {
        val lines = """
            Timestamp: 2020-02-14 09:23:45+0000
            pid: 1, tid: 1, name: com.app.one  >>> com.app.one <<<
            signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x1
            Timestamp: 2020-02-14 09:25:00+0000
            pid: 2, tid: 2, name: com.app.two  >>> com.app.two <<<
            signal 6 (SIGABRT), code -6 (SI_TKILL), fault addr --------
        """.trimIndent().lines().asSequence()

        val events = parser.parse(lines, capturedAt = 0L)

        assertEquals(2, events.size)
        assertEquals("com.app.one", events[0].processName)
        assertEquals(11, events[0].signalNumber)
        assertEquals("com.app.two", events[1].processName)
        assertEquals(6, events[1].signalNumber)
    }

    @Test
    fun `returns empty list when no tombstones present`() {
        val lines = "some unrelated bugreport text\nno tombstones here".lines().asSequence()
        assertEquals(0, parser.parse(lines, capturedAt = 0L).size)
    }
}
```

### Task A4: Create `WakelockParser`

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/bugreport/WakelockParser.kt`
- Create: `app/src/test/java/com/androdr/scanner/bugreport/WakelockParserTest.kt`

- [ ] **Step 1: Understand wakelock format**

Bugreport `dumpsys power` output shows wakelocks like:

```
Wake Locks: size=3
  PARTIAL_WAKE_LOCK      'WakeLockSync'      ACQ=-2h15m30s TAG=com.example (uid=10123)
  PARTIAL_WAKE_LOCK      'BackgroundTask'    ACQ=-1h5m12s TAG=com.example (uid=10123)
```

Or via `batterystats --history`:

```
  +1m23s456ms (1) 100 wake_lock=com.example/*wakelock* timeOnBattery=1234
```

- [ ] **Step 2: Write the parser**

Since the exact format varies by Android version and the plan 6 wakelock rule ships disabled-by-default, the parser can be best-effort. Aim for a robust parser that handles the `Wake Locks:` section of `dumpsys power`:

```kotlin
package com.androdr.scanner.bugreport

import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.WakelockAcquisition
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Parses wakelock acquisitions from a bugreport's `dumpsys power` section.
 * Used by plan 6's `sigma_androdr_persistent_wakelock.yml` rule to detect
 * always-on surveillance behavior — though the rule ships disabled pending
 * UAT threshold calibration (#87).
 *
 * Format (typical `dumpsys power`):
 *   Wake Locks: size=3
 *     PARTIAL_WAKE_LOCK   'tag'   ACQ=-2h15m30s TAG=com.example (uid=10123)
 *
 * The `ACQ=-Xh Ym Zs` field indicates how long ago the lock was acquired
 * relative to the bugreport timestamp.
 */
@Singleton
class WakelockParser @Inject constructor() {

    /**
     * Parses wakelock acquisitions from a sequence of bugreport lines.
     *
     * @param lines the full bugreport line sequence, or a pre-filtered slice
     * @param bugreportTimestamp epoch milliseconds of the bugreport capture,
     *        used to compute absolute `acquiredAt` from the relative `ACQ=` offsets
     * @param capturedAt epoch milliseconds to set on emitted telemetry rows
     */
    fun parse(
        lines: Sequence<String>,
        bugreportTimestamp: Long,
        capturedAt: Long,
    ): List<WakelockAcquisition> {
        val events = mutableListOf<WakelockAcquisition>()
        var inWakelockSection = false

        for (line in lines) {
            val trimmed = line.trim()
            when {
                trimmed.startsWith("Wake Locks:") -> {
                    inWakelockSection = true
                    continue
                }
                inWakelockSection && trimmed.isBlank() -> {
                    inWakelockSection = false
                    continue
                }
                inWakelockSection -> {
                    val wakelock = parseWakelockLine(trimmed, bugreportTimestamp, capturedAt)
                    if (wakelock != null) events += wakelock
                }
            }
        }
        return events
    }

    private fun parseWakelockLine(
        line: String,
        bugreportTimestamp: Long,
        capturedAt: Long,
    ): WakelockAcquisition? {
        // Example: PARTIAL_WAKE_LOCK 'tag' ACQ=-2h15m30s TAG=com.example (uid=10123)
        val tagMatch = Regex("'([^']+)'").find(line) ?: return null
        val tag = tagMatch.groupValues[1]

        val pkgMatch = Regex("TAG=([^\\s]+)").find(line)
        val packageName = pkgMatch?.groupValues?.get(1) ?: return null

        val acqMatch = Regex("ACQ=-?(\\d+h)?(\\d+m)?(\\d+s)?(\\d+ms)?").find(line)
        val acqOffsetMillis = acqMatch?.let { parseOffset(it.groupValues) } ?: 0L

        return WakelockAcquisition(
            packageName = packageName,
            wakelockTag = tag,
            acquiredAt = bugreportTimestamp - acqOffsetMillis,
            durationMillis = null, // not directly available from dumpsys power
            source = TelemetrySource.BUGREPORT_IMPORT,
            capturedAt = capturedAt,
        )
    }

    private fun parseOffset(groups: List<String>): Long {
        // groups: [full, h, m, s, ms]
        var millis = 0L
        if (groups.size > 1 && groups[1].isNotEmpty()) {
            millis += groups[1].removeSuffix("h").toLong() * 3_600_000
        }
        if (groups.size > 2 && groups[2].isNotEmpty()) {
            millis += groups[2].removeSuffix("m").toLong() * 60_000
        }
        if (groups.size > 3 && groups[3].isNotEmpty()) {
            millis += groups[3].removeSuffix("s").toLong() * 1_000
        }
        if (groups.size > 4 && groups[4].isNotEmpty()) {
            millis += groups[4].removeSuffix("ms").toLong()
        }
        return millis
    }
}
```

- [ ] **Step 3: Write unit tests**

Test for parsing a simple `Wake Locks:` section with multiple entries. Similar structure to `TombstoneParserTest`. Three tests minimum: single entry, multiple entries, empty / no section.

### Task A5: Commit phase A

```bash
git add app/src/main/java/com/androdr/scanner/bugreport/BugReportParser.kt \
        app/src/main/java/com/androdr/scanner/bugreport/TombstoneParser.kt \
        app/src/main/java/com/androdr/scanner/bugreport/WakelockParser.kt \
        app/src/test/java/com/androdr/scanner/bugreport/TombstoneParserTest.kt \
        app/src/test/java/com/androdr/scanner/bugreport/WakelockParserTest.kt
# Omit BugReportParser.kt from the add if you didn't create it
git commit -m "feat(bugreport): TombstoneParser and WakelockParser for plan 6 rules (#84)

Two new parsers emit telemetry types from plan 2:
- TombstoneParser → TombstoneEvent (process crash records)
- WakelockParser → WakelockAcquisition (wakelock hold records)

Both emit source = TelemetrySource.BUGREPORT_IMPORT. No consumers yet
in this commit — plan 6 wires them into BugReportAnalyzer and adds
the corresponding SIGMA rules (crash_loop_anti_forensics,
persistent_wakelock).

Tombstone format parsed: Timestamp, pid/tid/name, signal, Abort message.
Wakelock format parsed: dumpsys power 'Wake Locks:' block with ACQ= offsets.

Part of #84 (plan 5, phase A)."
```

---

## Phase B: Per-Module Ports

Each module port follows the same pattern:

1. **Read the current module** and understand what it does.
2. **Identify hardcoded lists** (`dangerousOps`, `sensitiveIntents`, etc.).
3. **Identify hardcoded severity** (`severity = "HIGH"`, `severity = "INFO"`, etc.).
4. **Delete the hardcoded lists and severity literals**.
5. **Emit canonical telemetry** via whatever telemetry type the spec §7 migration table specifies.
6. **Set source = TelemetrySource.BUGREPORT_IMPORT** on every emitted row.
7. **Run compile + tests**.
8. **Commit** with a per-module message.

Each port is its own commit, in its own sub-task, so history is bisectable.

### Task B1: `AppOpsModule`

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/bugreport/AppOpsModule.kt`

- [ ] **Step 1: Read the current file**

Find the hardcoded `dangerousOps` set and the severity ternary (spec §7: "severity = if (op == \"REQUEST_INSTALL_PACKAGES\") \"HIGH\" else \"INFO\"").

- [ ] **Step 2: Delete hardcoded constants and severity**

Remove the `dangerousOps` set. Remove any severity assignment from the emitted data.

- [ ] **Step 3: Emit `AppOpsTelemetry` with BUGREPORT_IMPORT source**

Change the module to emit `List<AppOpsTelemetry>` (same type as `AppOpsScanner` produces). Each row is constructed with `source = TelemetrySource.BUGREPORT_IMPORT`.

- [ ] **Step 4: Update the module's return type**

If the module currently returns `ModuleResult` or `List<BugReportFinding>`, change it to return `AppOpsModuleResult` (new shape) or directly `List<AppOpsTelemetry>`. The exact type depends on how `BugReportAnalyzer` dispatches — we'll unify dispatch in phase C.

For now, add a new method `fun parseTelemetry(...): List<AppOpsTelemetry>` alongside the existing finding-producing method. The existing method can be marked `@Deprecated` and left for plan 6 to delete.

- [ ] **Step 5: Compile**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -10
```

- [ ] **Step 6: Update or add module test**

Any existing `AppOpsModuleTest` should be updated to test the new telemetry output. If creating a new test method:

```kotlin
@Test
fun `module emits AppOpsTelemetry with BUGREPORT_IMPORT source`() {
    val lines = """
        // realistic dumpsys appops output
    """.trimIndent().lines().asSequence()
    val result = module.parseTelemetry(lines, capturedAt = 1000L)
    assertTrue(result.isNotEmpty())
    assertTrue(result.all { it.source == TelemetrySource.BUGREPORT_IMPORT })
}
```

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/bugreport/AppOpsModule.kt \
        app/src/test/java/com/androdr/scanner/bugreport/AppOpsModuleTest.kt
git commit -m "refactor(bugreport): AppOpsModule emits AppOpsTelemetry (#84)

AppOpsModule now emits AppOpsTelemetry with BUGREPORT_IMPORT source,
not BugReportFinding objects with hardcoded severity. The deprecated
dangerousOps set and severity ternary are deleted.

Rules sigma_androdr_063_appops_microphone, 064_appops_camera, and
065_appops_install_packages continue to evaluate the telemetry
unchanged — they already worked on telemetry from AppOpsScanner.

Part of #84 (plan 5, phase B, step 1 of 7)."
```

### Task B2: `ReceiverModule`

Same pattern. Delete `sensitiveIntents` and `systemPackagePrefixes`. Emit `ReceiverTelemetry` with `source = BUGREPORT_IMPORT`. Use `OemPrefixResolver` for OEM filtering (plan 1 already has this).

The existing rules `sigma_androdr_061_sms_receiver` and `sigma_androdr_062_call_receiver` continue to evaluate the telemetry.

Commit message: "refactor(bugreport): ReceiverModule emits ReceiverTelemetry (#84) ... Part of #84 (plan 5, phase B, step 2 of 7)."

### Task B3: `ActivityModule`

Delete `sensitiveSchemes` and `systemPackagePrefixes`. Emit `ForensicTimelineEvent` entries for activity transitions. If `IntentObservation` is needed as a new telemetry type (wasn't created in plan 2), defer it — see if the existing `ForensicTimelineEvent` with appropriate `category` and `details` suffices.

Commit: "Part of #84 (plan 5, phase B, step 3 of 7)."

### Task B4: `AccessibilityModule`

Delete `systemPackagePrefixes`. Emit `AccessibilityTelemetry` with `source = BUGREPORT_IMPORT`. Same type `AccessibilityAuditScanner` produces.

Commit: "Part of #84 (plan 5, phase B, step 4 of 7)."

### Task B5: `BatteryDailyModule`

Delete `severity = "HIGH"` hardcoded literals at lines 64 and 105 (per spec §7). Emit `BatteryDailyEvent` and `PackageInstallHistoryEntry`. The plan 6 rule for package-uninstall-with-IOC will evaluate the telemetry.

Commit: "Part of #84 (plan 5, phase B, step 5 of 7)."

### Task B6: `PlatformCompatModule`

Delete `CHANGE_ID_DOWNSCALED` constant. Emit `PlatformCompatChange` per ChangeId toggle. Plan 6 adds the rule that evaluates it.

Commit: "Part of #84 (plan 5, phase B, step 6 of 7)."

### Task B7: `DbInfoModule`

Delete `sensitiveDbPaths`. Emit `DatabasePathObservation` per observation. The list of "which DBs are sensitive" moves to the rule or a YAML resource — for now, emit all DB path observations and let the future rule filter.

Commit: "Part of #84 (plan 5, phase B, step 7 of 7)."

---

## Phase C: `BugReportAnalyzer` Dispatch Update

### Task C1: Add new-style dispatch path

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/bugreport/BugReportAnalyzer.kt`

- [ ] **Step 1: Read the current analyzer**

Understand the existing dispatch. It probably has something like:

```kotlin
val results = modules.flatMap { it.analyze(bugreport) }
// return as findings
```

- [ ] **Step 2: Add telemetry collection**

The new flow:

```kotlin
// Collect telemetry from new-style modules
val telemetryBundle = TelemetryBundle(
    appOps = appOpsModule.parseTelemetry(lines, capturedAt),
    receivers = receiverModule.parseTelemetry(lines, capturedAt),
    accessibility = accessibilityModule.parseTelemetry(lines, capturedAt),
    batteryDaily = batteryDailyModule.parseTelemetry(lines, capturedAt),
    packageHistory = batteryDailyModule.parseInstallHistory(lines, capturedAt),
    platformCompat = platformCompatModule.parseTelemetry(lines, capturedAt),
    dbPathObservations = dbInfoModule.parseTelemetry(lines, capturedAt),
    tombstones = tombstoneParser.parse(lines, capturedAt),
    wakelocks = wakelockParser.parse(lines, bugreportTimestamp, capturedAt),
    forensicEvents = activityModule.parseTimelineEvents(lines, capturedAt),
)

// Feed telemetry to SigmaRuleEngine
val findings = mutableListOf<Finding>()
findings += sigmaRuleEngine.evaluateAppOps(telemetryBundle.appOps)
findings += sigmaRuleEngine.evaluateReceivers(telemetryBundle.receivers)
findings += sigmaRuleEngine.evaluateAccessibility(telemetryBundle.accessibility)
// ... for each telemetry type

// LegacyScanModule still runs on the old path — plan 6 deletes it
val legacyFindings = legacyScanModule.analyze(bugreport) // still emits BugReportFinding

return BugReportAnalysisResult(
    telemetry = telemetryBundle,
    findings = findings,
    legacyFindings = legacyFindings,  // deleted in plan 6
)
```

The exact shapes depend on the current code — adapt to what's there.

- [ ] **Step 3: Wire SigmaRuleEngine correctly**

Make sure the analyzer has access to `SigmaRuleEngine` via Hilt injection. If it doesn't already, add it to the constructor.

- [ ] **Step 4: Compile + run tests**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -5
./gradlew testDebugUnitTest 2>&1 | tail -15
```

Both must pass.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/bugreport/BugReportAnalyzer.kt
git commit -m "refactor(bugreport): BugReportAnalyzer invokes SigmaRuleEngine on telemetry (#84)

BugReportAnalyzer now collects telemetry from the ported modules
(AppOps, Receiver, Activity, Accessibility, BatteryDaily,
PlatformCompat, DbInfo, Tombstone, Wakelock) and feeds it through
SigmaRuleEngine.evaluateXxx() for each telemetry type. The produced
Finding objects join the legacy BugReportFinding objects until
plan 6 deletes LegacyScanModule and BugReportFinding.

This completes plan 5: every bugreport module except LegacyScanModule
is telemetry-only.

Part of #84 (plan 5, phase C)."
```

---

## Phase D: Final Verification

### Task D1: Run all gradle checks

```bash
cd /home/yasir/AndroDR
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
./gradlew testDebugUnitTest 2>&1 | tail -20
./gradlew lintDebug 2>&1 | tail -10
./gradlew assembleDebug 2>&1 | tail -5
./gradlew detekt 2>&1 | tail -10
```
All four must be BUILD SUCCESSFUL.

### Task D2: Invariant checks

- [ ] **Check 1: Hardcoded lists removed from ported modules**

```bash
grep -n "dangerousOps\|sensitiveIntents\|sensitiveSchemes\|sensitiveDbPaths\|systemPackagePrefixes\|CHANGE_ID_DOWNSCALED" \
    app/src/main/java/com/androdr/scanner/bugreport/AppOpsModule.kt \
    app/src/main/java/com/androdr/scanner/bugreport/ReceiverModule.kt \
    app/src/main/java/com/androdr/scanner/bugreport/ActivityModule.kt \
    app/src/main/java/com/androdr/scanner/bugreport/AccessibilityModule.kt \
    app/src/main/java/com/androdr/scanner/bugreport/BatteryDailyModule.kt \
    app/src/main/java/com/androdr/scanner/bugreport/PlatformCompatModule.kt \
    app/src/main/java/com/androdr/scanner/bugreport/DbInfoModule.kt
```
Expected: zero hits.

- [ ] **Check 2: Each ported module sets source = BUGREPORT_IMPORT**

```bash
grep -rn "source = TelemetrySource.BUGREPORT_IMPORT" app/src/main/java/com/androdr/scanner/bugreport/
```
Expected: multiple hits across the 7 ported modules plus Tombstone/Wakelock parsers.

- [ ] **Check 3: `LegacyScanModule` is untouched**

```bash
git diff 1718a85..HEAD -- app/src/main/java/com/androdr/scanner/bugreport/LegacyScanModule.kt
```
Expected: empty.

- [ ] **Check 4: `BugReportFinding` type still exists**

```bash
grep -rn "class BugReportFinding\|data class BugReportFinding" app/src/main/java/
```
Expected: one match (the definition). Plan 6 deletes it.

- [ ] **Check 5: No sigma package changes**

```bash
git diff 1718a85..HEAD -- app/src/main/java/com/androdr/sigma/
```
Expected: empty.

- [ ] **Check 6: No rule YAML changes**

```bash
git diff 1718a85..HEAD -- 'app/src/main/res/raw/sigma_androdr_*.yml'
```
Expected: empty.

### Task D3: Working tree clean + commit log

```bash
git status
git log 1718a85..HEAD --oneline
```
Expected: clean tree, 9-12 commits for plan 5 (1 phase A + 7 module ports + 1 phase C + possibly some fixes).

---

## Plan 5 Retrospective Checklist

- [ ] `TombstoneParser` and `WakelockParser` exist and emit telemetry with BUGREPORT_IMPORT source
- [ ] 7 bugreport modules ported to emit telemetry instead of BugReportFinding
- [ ] All hardcoded lists (`dangerousOps`, `sensitiveIntents`, `sensitiveSchemes`, `sensitiveDbPaths`, `systemPackagePrefixes`, `CHANGE_ID_DOWNSCALED`) deleted from ported modules
- [ ] All hardcoded severity literals (`severity = "HIGH"`, etc.) deleted from ported modules
- [ ] `BugReportAnalyzer` invokes `SigmaRuleEngine.evaluateXxx()` on the new telemetry
- [ ] `LegacyScanModule` untouched (plan 6 deletes it)
- [ ] `BugReportFinding` type untouched (plan 6 deletes it)
- [ ] No sigma package changes
- [ ] No rule YAML changes
- [ ] No UI code changes
- [ ] All gradle checks pass

---

**End of plan 5.**

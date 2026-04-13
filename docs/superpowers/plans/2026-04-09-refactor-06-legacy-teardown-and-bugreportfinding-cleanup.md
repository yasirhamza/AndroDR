# Refactor Plan 6: LegacyScanModule Teardown + BugReportFinding Cleanup

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Parent refactor:** Unified telemetry/findings architecture (#84). Spec: `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`, §8.

**Plan order:** Plan 6 of 7. Starts after plan 5's final commit. Serialized execution on `claude/unified-telemetry-findings-refactor`.

**Goal:** Delete `LegacyScanModule.kt` with tombstone commits for the 3 deleted heuristics (graphite keyword, base64 blob, C2 beacon). Author two new rules (`sigma_androdr_crash_loop_anti_forensics.yml` MEDIUM incident, `sigma_androdr_persistent_wakelock.yml` LOW incident disabled-by-default). Wire `TombstoneParser`/`WakelockParser` (from plan 5) into `BugReportAnalyzer`. Add minimal new rules for the other telemetry types plan 5 surfaces (`BatteryDailyEvent`, `PlatformCompatChange`, `DatabasePathObservation`). Delete `BugReportFinding` type after migrating all consumers. Delete `ModuleResult` hardcoded-finding shape.

**Architecture:**
- `LegacyScanModule.kt` deleted entirely. Three separate commits for the deleted heuristics (documentation trail).
- `SigmaRuleEngine` gains new typed evaluate methods for the new telemetry types (relaxing the plan 5 "don't touch sigma" restriction for this plan only).
- New rule YAML files for crash loop, persistent wakelock, and at least minimal coverage for BatteryDaily / PlatformCompat / DbPath.
- `BugReportAnalyzer` populates the `TelemetryBundle` (added in plan 5) from the new parsers and invokes the new typed evaluate methods on the bundle.
- `BugReportFinding` type deleted. Every consumer migrated to use the unified `Finding` type from `sigma` package.
- `ModuleResult` with its `findings: List<BugReportFinding>` field collapses into a telemetry-only return shape.

**Tech Stack:** Kotlin, Hilt, YAML (SIGMA rules), JUnit 4 + MockK.

**Acceptance criteria:**
- `app/src/main/java/com/androdr/scanner/bugreport/LegacyScanModule.kt` deleted.
- Three tombstone commits document the deleted heuristics with the specific commit messages from spec §8.
- `sigma_androdr_crash_loop_anti_forensics.yml` exists, declares `category: incident`, `level: medium`, evaluates `TombstoneEvent` telemetry.
- `sigma_androdr_persistent_wakelock.yml` exists, declares `category: incident`, `level: low`, declares `enabled: false` (ships disabled per the unit 7 mechanism).
- At least one new rule exists for each of `BatteryDailyEvent`, `PlatformCompatChange`, `DatabasePathObservation` (or a documented decision to defer them).
- `BugReportAnalyzer` populates `TelemetryBundle` with output from `TombstoneParser` and `WakelockParser`.
- `SigmaRuleEngine` has new typed evaluate methods for `TombstoneEvent`, `WakelockAcquisition`, `BatteryDailyEvent`, `PlatformCompatChange`, `DatabasePathObservation` (plus any others plan 2 created that need rule-engine invocation).
- `BugReportFinding` type and `ModuleResult` type deleted.
- Every downstream consumer (`ReportExporter`, `ReportFormatter`, `ReportCsvWriter`, `HistoryViewModel`, `DashboardViewModel`, `AppsViewModel`, any other discovered by grep) migrated to unified `Finding`.
- `AllRulesHaveCategoryTest` still passes (new rules have category).
- `AllCorrelationRulesFireTest` still passes.
- All gradle checks pass.
- All existing SIGMA rule tests pass.
- No rule YAML beyond additions for new rules (existing rules untouched).

---

## Phase A: Delete `LegacyScanModule` (3 tombstone commits)

Per spec §8, each deleted heuristic gets its own commit with a specific tombstone message explaining why it was removed. The goal is to create a searchable record so future contributors don't re-invent the broken heuristic.

### Task A1: Remove the "graphite" keyword match

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/bugreport/LegacyScanModule.kt`

- [ ] **Step 1: Read the current `LegacyScanModule.kt`**

```bash
cd /home/yasir/AndroDR
cat app/src/main/java/com/androdr/scanner/bugreport/LegacyScanModule.kt
```

Find the `spywareProcessRegex` constant (around line 27-30 per plan 1 audit) and the code that emits a CRITICAL finding when it matches (around line 132-143).

- [ ] **Step 2: Delete the regex constant and its usage**

Remove:
- The `spywareProcessRegex` property (or whatever the exact constant name is)
- The block that iterates bugreport lines and emits a `BugReportFinding` with `severity = "CRITICAL"` and `category = "KnownMalware"` based on the match

Leave everything else in `LegacyScanModule.kt` intact for this commit.

- [ ] **Step 3: Compile**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -5
```
Expected: BUILD SUCCESSFUL. If tests that depended on the keyword behavior fail, update or delete them (with a note in the commit message).

- [ ] **Step 4: Commit with the exact tombstone message**

```bash
git add app/src/main/java/com/androdr/scanner/bugreport/LegacyScanModule.kt
# Plus any tests that had to be deleted/updated
git commit -m "removed(bugreport): naive 'graphite' substring match (#84)

Produced CRITICAL false positives on every device with Skia Graphite
render engine (AOSP feature flag graphite_renderengine). Real
Graphite/Paragon detection lives in androdr-005 and the graphite/
pegasus/predator CVE rules. The keyword regex had no word boundaries
and no context exclusions; there is no version of a substring match
on security vendor names that produces signal without noise.

This is the root cause of the tester's false-positive report that
motivated the entire refactor. See spec §8 for the full tombstone.

Part of #84 (plan 6, phase A, step 1 of 3)."
```

### Task A2: Remove the base64 blob heuristic

- [ ] **Step 1: Remove the base64 regex and its usage**

Find `base64BlobRegex` (around line 32-35) and the HIGH-finding emission block (around line 147-157). Delete both.

- [ ] **Step 2: Compile + test**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -5
```

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/bugreport/LegacyScanModule.kt
# Plus any affected tests
git commit -m "removed(bugreport): base64 length heuristic (#84)

The 100-char base64 blob regex produced 100+ HIGH false positives
per clean-device report because bugreports contain protobuf dumps,
keys, and serialized state as base64 by design. Exfiltration
detection belongs in DNS/network telemetry (DnsEvent evaluation
against domain IOC feeds), not in bugreport text scanning.

The heuristic was asking the wrong question: 'does this look like
base64' does not imply 'this is exfiltrated data' on a system that
uses base64 as a transport format.

Part of #84 (plan 6, phase A, step 2 of 3)."
```

### Task A3: Remove the C2 beacon regex

- [ ] **Step 1: Remove the C2 beacon regex and its usage**

Find `c2BeaconRegex` (around line 37-41) and the CRITICAL-finding emission block (around line 160-169). Delete both.

- [ ] **Step 2: Compile + test**

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/bugreport/LegacyScanModule.kt
# Plus any affected tests
git commit -m "removed(bugreport): 'HTTP POST every N' C2 beacon regex (#84)

The regex was a proxy for real C2 detection. Actual C2 signal comes
from DNS events evaluated against domain IOC feeds (androdr-003).
The regex produced CRITICAL false positives on code comments and
documentation embedded in tombstones (e.g. '// POST every 5
minutes' in developer commentary, or README text captured by
bugreport).

Part of #84 (plan 6, phase A, step 3 of 3)."
```

### Task A4: Delete the `LegacyScanModule.kt` file entirely

After the three heuristics are removed, the file may still contain the crash-loop and wakelock-density heuristics (tasks for plan 6 phase B), plus other infrastructure. Those get ported as proper rules in phase B. In this task, check:

- [ ] **Step 1: Is the file still doing anything useful?**

```bash
cat app/src/main/java/com/androdr/scanner/bugreport/LegacyScanModule.kt
```

If only the crash-loop + wakelock-density heuristics remain, and they're about to be ported in phase B, you can:
- Option A: leave the file in place for phase B to port from, then delete at the end
- Option B: delete the file now and rebuild the crash-loop / wakelock logic from scratch in phase B

**Recommended: Option A** — leave the file until phase B ports the last two heuristics, then delete in phase B's final commit. This way the old code is available as reference during the port.

If the file only contains the 3 deleted heuristics and nothing else, it's a compile error now — delete it and update `BugReportAnalyzer` to stop dispatching to it.

Skip commit if option A; commit the deletion if option B.

---

## Phase B: Port crash-loop and wakelock as SIGMA rules

### Task B1: Add new typed evaluate methods to `SigmaRuleEngine`

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt`

**Note:** This is the ONE place in plan 6 where sigma package files are touched (unlike plan 5 which forbade it). The additions are purely new methods — no modifications to existing ones.

- [ ] **Step 1: Read the existing evaluate methods**

```bash
grep -n "fun evaluate" app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt
```

Understand the pattern used by existing methods like `evaluateAppOps(List<AppOpsTelemetry>): List<Finding>`. Each calls `evaluate(rules, telemetry, service)` internally with a service string that matches the rule YAML `logsource.service` field.

- [ ] **Step 2: Add new typed evaluate methods**

For each new telemetry type added in plan 2 that plan 6's rules will evaluate, add a corresponding method. Minimal set:

```kotlin
fun evaluateTombstones(telemetry: List<TombstoneEvent>): List<Finding> {
    return evaluate(effectiveRules(), telemetry.map { it.toMap() }, "tombstone_parser")
}

fun evaluateWakelocks(telemetry: List<WakelockAcquisition>): List<Finding> {
    return evaluate(effectiveRules(), telemetry.map { it.toMap() }, "wakelock_parser")
}

fun evaluateBatteryDaily(telemetry: List<BatteryDailyEvent>): List<Finding> {
    return evaluate(effectiveRules(), telemetry.map { it.toMap() }, "battery_daily")
}

fun evaluatePackageInstallHistory(telemetry: List<PackageInstallHistoryEntry>): List<Finding> {
    return evaluate(effectiveRules(), telemetry.map { it.toMap() }, "package_install_history")
}

fun evaluatePlatformCompat(telemetry: List<PlatformCompatChange>): List<Finding> {
    return evaluate(effectiveRules(), telemetry.map { it.toMap() }, "platform_compat")
}

fun evaluateDatabasePathObservations(telemetry: List<DatabasePathObservation>): List<Finding> {
    return evaluate(effectiveRules(), telemetry.map { it.toMap() }, "db_info")
}
```

Each method:
- Filters enabled rules via `effectiveRules()` (the helper added in unit 7)
- Converts typed telemetry to `Map<String, Any?>` via a `.toMap()` extension (if one doesn't exist, add a simple one in the same file or in the data class)
- Invokes the internal `evaluate(...)` with a service name that matches the `logsource.service` in the new rule YAML files

Adapt to the actual `evaluate` method signature in the current engine — it may take different parameters than the stub above.

- [ ] **Step 3: Implement `toMap()` extensions** (if needed)

For each new telemetry type, add a simple `toMap()` extension either in the data class file or in the sigma package:

```kotlin
fun TombstoneEvent.toMap(): Map<String, Any?> = mapOf(
    "process_name" to processName,
    "package_name" to packageName,
    "signal_number" to signalNumber,
    "abort_message" to abortMessage,
    "crash_timestamp" to crashTimestamp,
    "source" to source.name,
)

fun WakelockAcquisition.toMap(): Map<String, Any?> = mapOf(
    "package_name" to packageName,
    "wakelock_tag" to wakelockTag,
    "acquired_at" to acquiredAt,
    "duration_millis" to durationMillis,
    "source" to source.name,
)

// etc.
```

The field names in the map should match what the rule YAML files reference (e.g. `package_name|contains: "stalker"` requires the map key `package_name`). Use snake_case for consistency with SIGMA conventions.

- [ ] **Step 4: Compile**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -5
```
Expected: BUILD SUCCESSFUL.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt
# Plus any new toMap extensions
git commit -m "refactor(sigma): typed evaluate methods for new telemetry types (#84)

Adds six new typed evaluate methods to SigmaRuleEngine for the
telemetry types introduced in plan 2:

- evaluateTombstones(List<TombstoneEvent>)
- evaluateWakelocks(List<WakelockAcquisition>)
- evaluateBatteryDaily(List<BatteryDailyEvent>)
- evaluatePackageInstallHistory(List<PackageInstallHistoryEntry>)
- evaluatePlatformCompat(List<PlatformCompatChange>)
- evaluateDatabasePathObservations(List<DatabasePathObservation>)

Each routes through the existing evaluate() infrastructure and uses
a service name that matches the corresponding rule YAML logsource.service.
Each applies the enabled filter via effectiveRules().

toMap() extensions added for each telemetry type to convert them into
the Map<String, Any?> shape the evaluator expects. Field names use
snake_case matching SIGMA rule convention.

Part of #84 (plan 6, phase B, step 1 of N)."
```

### Task B2: Create crash-loop rule YAML

**Files:**
- Create: `app/src/main/res/raw/sigma_androdr_071_crash_loop_anti_forensics.yml` (or whatever next-available rule ID is — check)

- [ ] **Step 1: Check the next available rule ID**

```bash
ls app/src/main/res/raw/sigma_androdr_0*.yml | sort | tail -20
```

Find the highest ID in the 0XX detection rule range. Use the next available slot (e.g. 071 if 070 isn't taken).

- [ ] **Step 2: Write the rule**

```yaml
title: Process crash loop indicating anti-forensics or failed exploitation
id: androdr-071
status: experimental
description: >
    Multiple crash events for the same package within a short time window
    can indicate anti-forensics behavior (deliberate crashes to corrupt
    state) or failed exploit attempts that consistently crash the target
    process. Legitimate crash loops do happen during development or OOM
    conditions — this rule fires at MEDIUM severity to prompt review,
    not automatic escalation.
author: AndroDR
date: 2026-04-09
tags:
    - attack.t1562
logsource:
    product: androdr
    service: tombstone_parser
detection:
    selection:
        # Any tombstone event counts as a crash; the count-based aggregation
        # happens at rule engine level via a count threshold (if supported)
        # or at the bugreport analyzer level which groups by package
        package_name|exists: true
    condition: selection
category: incident
level: medium
display:
    category: device_posture  # For UI display only; RuleCategory is above
    icon: bug_report
    triggered_title: "Repeated crash pattern detected"
    safe_title: "No crash patterns"
    evidence_type: none
remediation:
    - "Review the repeatedly crashing package for legitimate bugs vs exploit attempts."
    - "If the package is suspect, uninstall it and scan for related artifacts."
```

**Note:** The detection logic is intentionally simple because implementing a count-over-time correlation requires either (a) a correlation rule that references an atom, or (b) engine-level grouping support. For now, this rule fires on any tombstone telemetry present — plan 7 or later sprints can add proper thresholding.

If the existing rule engine supports a `count:` or `aggregation:` section, use it. Otherwise ship the simple version with a TODO comment.

- [ ] **Step 3: Verify the `AllRulesHaveCategoryTest` still passes**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.AllRulesHaveCategoryTest" 2>&1 | tail -5
```
Expected: BUILD SUCCESSFUL. The new rule has `category: incident` so the test should accept it.

- [ ] **Step 4: Commit** with a dedicated message.

### Task B3: Create persistent-wakelock rule YAML

**Files:**
- Create: `app/src/main/res/raw/sigma_androdr_072_persistent_wakelock.yml` (or next available ID)

- [ ] **Step 1: Write the rule**

```yaml
title: Persistent wakelock indicating always-on surveillance
id: androdr-072
status: experimental
description: >
    An app holding wakelocks persistently (long durations, high density)
    can indicate stalkerware behavior. This rule ships disabled by default
    pending UAT threshold calibration because the heuristic tends to
    false-positive on fitness apps, navigation, and legitimate background
    services. See issue #87 for calibration tracking.
author: AndroDR
date: 2026-04-09
tags:
    - attack.t1437
logsource:
    product: androdr
    service: wakelock_parser
detection:
    selection:
        package_name|exists: true
    condition: selection
enabled: false
category: incident
level: low
display:
    category: device_posture
    icon: battery_alert
    triggered_title: "Persistent wakelock activity"
    safe_title: "No persistent wakelock patterns"
    evidence_type: none
remediation:
    - "Review the package holding persistent wakelocks for legitimate background-service behavior."
    - "If not recognized, uninstall and investigate."
```

Key points:
- `enabled: false` — this is the plan 1 mechanism. The rule is loaded, parsed, and visible in the rule list, but `effectiveRules()` filters it out so it doesn't produce findings.
- `category: incident` (stalkerware behavior is an incident category conceptually, even at LOW severity).
- `level: low` — even if the rule were enabled, it would fire at LOW, reflecting the uncertain signal quality.

- [ ] **Step 2: Verify the `AllRulesHaveCategoryTest` and `SigmaRuleEngineDisabledRuleTest` still pass.**

- [ ] **Step 3: Commit** — dedicated message.

### Task B4: Create minimal rules for BatteryDaily / PlatformCompat / DbPath / PackageInstallHistory

**Files:**
- Create (4 files): `sigma_androdr_0XX_*.yml` for each new telemetry type

- [ ] **Step 1: Write minimal rules**

Each rule should be minimally specified but category-correct and rule-engine-loadable. For each of the 4 telemetry types, author a rule that fires on the presence of the telemetry (as a placeholder) but is `enabled: false` by default (same mechanism as the wakelock rule). This ensures:
- The rule engine successfully wires the new telemetry types to rules
- The `AllRulesHaveCategoryTest` catches any category violations
- The evaluate methods from task B1 actually have rules to evaluate
- No new findings are produced without intentional enablement

Templates:

**sigma_androdr_073_battery_daily_pattern.yml:**
```yaml
title: Battery daily event pattern requires further rules
id: androdr-073
status: experimental
description: "Placeholder: BatteryDailyEvent telemetry reaches rule engine but specific detection logic TBD by #87 follow-ups."
author: AndroDR
date: 2026-04-09
logsource:
    product: androdr
    service: battery_daily
detection:
    selection:
        event_type|exists: true
    condition: selection
enabled: false
category: incident
level: low
display:
    category: device_posture
    icon: battery_alert
    triggered_title: "Battery daily event observed"
    evidence_type: none
remediation:
    - "Placeholder rule; no remediation defined."
```

**sigma_androdr_074_package_install_history_pattern.yml:** same shape, service: `package_install_history`, level: low, enabled: false, category: incident.

**sigma_androdr_075_platform_compat_override.yml:** same shape, service: `platform_compat`, level: low, enabled: false, category: incident.

**sigma_androdr_076_database_path_access.yml:** same shape, service: `db_info`, level: low, enabled: false, category: incident.

The intent of these placeholder rules: they exist so the engine has something to match against when `BugReportAnalyzer` calls `evaluateBatteryDaily(...)` etc. in phase C. They produce no output (disabled) so they don't affect user-visible behavior. Future sprints author real detection logic for each telemetry type.

- [ ] **Step 2: Verify tests**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.AllRulesHaveCategoryTest" 2>&1 | tail -5
./gradlew testDebugUnitTest --tests "com.androdr.sigma.SigmaRuleEngineDisabledRuleTest" 2>&1 | tail -5
```

- [ ] **Step 3: Commit** all 4 files in one commit.

### Task B5: Delete remaining `LegacyScanModule` code

- [ ] **Step 1: Read what's left in `LegacyScanModule.kt`**

After phase A deleted 3 heuristics, the file should contain only the crash-loop + wakelock-density legacy heuristics. These are now superseded by the new rules and parsers — time to delete.

- [ ] **Step 2: Delete the file**

```bash
git rm app/src/main/java/com/androdr/scanner/bugreport/LegacyScanModule.kt
# Plus any test files that referenced it
```

- [ ] **Step 3: Update `BugReportAnalyzer` to stop dispatching to `LegacyScanModule`**

Find the dispatch sequence in `BugReportAnalyzer.kt` that calls `LegacyScanModule.analyze(...)` or similar. Remove that call.

Also remove the `legacyFindings: List<BugReportFinding>` field from `BugReportAnalysisResult` (it has no producers anymore).

- [ ] **Step 4: Compile + tests**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -5
./gradlew testDebugUnitTest 2>&1 | tail -20
```

Expected: BUILD SUCCESSFUL. If tests fail because they assert on `legacyFindings` or `LegacyScanModule`, update them (they're testing deleted code).

- [ ] **Step 5: Commit the final teardown**

```bash
git add -A  # Add the file deletion + analyzer update + test updates
git commit -m "refactor(bugreport): delete LegacyScanModule (#84)

With the three hardcoded heuristics (graphite keyword, base64 blob,
C2 beacon) already removed in earlier commits and the crash-loop +
wakelock-density heuristics now ported to proper SIGMA rules
(androdr-071 crash_loop_anti_forensics, androdr-072 persistent_wakelock),
LegacyScanModule has no remaining purpose.

The file is deleted entirely. BugReportAnalyzer's dispatch sequence
no longer references it. BugReportAnalysisResult.legacyFindings is
also deleted since it has no producers.

BugReportFinding type is still referenced by downstream consumers —
deleted in phase D of this plan.

Part of #84 (plan 6, phase B, step 5 of 5)."
```

---

## Phase C: Wire `TombstoneParser` and `WakelockParser` into `BugReportAnalyzer`

### Task C1: Populate `TelemetryBundle` from the new parsers

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/BugReportAnalyzer.kt`

- [ ] **Step 1: Inject `TombstoneParser` and `WakelockParser`**

Both already exist (plan 5). Add them to `BugReportAnalyzer`'s constructor.

- [ ] **Step 2: Populate the `TelemetryBundle`**

The bundle was added in plan 5 with empty defaults. Wire the new parsers:

```kotlin
val tombstones = tombstoneParser.parse(bugreportLines, capturedAt = now)
val wakelocks = wakelockParser.parse(bugreportLines, bugreportTimestamp, capturedAt = now)
val bundle = TelemetryBundle(
    tombstones = tombstones,
    wakelocks = wakelocks,
    // plus any others that modules populate
)
```

The exact shape depends on how the analyzer currently dispatches. The line sequence (`bugreportLines`) needs to be available.

- [ ] **Step 3: Invoke the new typed evaluate methods**

```kotlin
val findings = mutableListOf<Finding>()
findings += sigmaRuleEngine.evaluateTombstones(bundle.tombstones)
findings += sigmaRuleEngine.evaluateWakelocks(bundle.wakelocks)
findings += sigmaRuleEngine.evaluateBatteryDaily(bundle.batteryDaily)
findings += sigmaRuleEngine.evaluatePackageInstallHistory(bundle.packageInstallHistory)
findings += sigmaRuleEngine.evaluatePlatformCompat(bundle.platformCompatChanges)
findings += sigmaRuleEngine.evaluateDatabasePathObservations(bundle.databasePathObservations)
```

- [ ] **Step 4: Compile + tests**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -5
./gradlew testDebugUnitTest 2>&1 | tail -15
```

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/BugReportAnalyzer.kt
git commit -m "refactor(bugreport): wire new parsers + evaluate methods into BugReportAnalyzer (#84)

BugReportAnalyzer now:
- Parses tombstones via TombstoneParser → TombstoneEvent telemetry
- Parses wakelocks via WakelockParser → WakelockAcquisition telemetry
- Populates TelemetryBundle with both (and the existing typed outputs
  from the ported modules)
- Invokes new typed SigmaRuleEngine.evaluateXxx() methods on each
  telemetry type to produce findings

The new rules (androdr-071 crash loop, androdr-072 wakelock) are
declared in this plan. The wakelock rule ships disabled-by-default
pending UAT tuning (#87).

Part of #84 (plan 6, phase C)."
```

---

## Phase D: Delete `BugReportFinding` and Migrate Consumers

### Task D1: Inventory consumers

- [ ] **Step 1: Find every reference**

```bash
grep -rn "BugReportFinding" app/src/ --include="*.kt"
```

Expected hits (from earlier audits):
- The type definition (one place — probably `BugReportAnalyzer.kt` or a sibling file)
- `ReportExporter.kt`
- `ReportFormatter.kt`
- `ReportCsvWriter.kt`
- `HistoryViewModel.kt`
- `DashboardViewModel.kt`
- `AppsViewModel.kt`
- Possibly others surfaced by grep

Document every file and roughly what it does with `BugReportFinding`.

### Task D2: Migrate each consumer to unified `Finding`

For each consumer from the inventory:

- [ ] **Step 1: Read the file**

Understand how it uses `BugReportFinding` — what fields does it read? What does it do with them?

- [ ] **Step 2: Replace with `Finding`**

The unified `Finding` type has: `ruleId`, `title`, `description`, `level`, `category` (FindingCategory, display), evidence, remediation, etc. Map each usage:
- `bugReportFinding.severity` → `finding.level`
- `bugReportFinding.category` → `finding.category.name.lowercase()` (or whatever string representation is needed)
- `bugReportFinding.title` → `finding.title`
- `bugReportFinding.description` → `finding.description`

- [ ] **Step 3: Update signatures**

Any method with `List<BugReportFinding>` parameters becomes `List<Finding>`.

- [ ] **Step 4: Run tests after each file to catch regressions early**

```bash
./gradlew testDebugUnitTest --tests "*<FileNameTest>*" 2>&1 | tail -10
```

- [ ] **Step 5: Commit each major consumer migration separately**

One commit per consumer file (or cluster of related files) to keep the history bisectable.

### Task D3: Delete `BugReportFinding` type

**Files:**
- Delete or modify the file that contains the `data class BugReportFinding` definition

- [ ] **Step 1: Delete the type definition**

- [ ] **Step 2: Delete `ModuleResult` if it only held `findings: List<BugReportFinding>`**

If `ModuleResult` is still used to carry the typed telemetry output from ported modules, refactor it to remove the `findings` field but keep the `telemetry` field.

- [ ] **Step 3: Compile + tests**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -5
./gradlew testDebugUnitTest 2>&1 | tail -20
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: delete BugReportFinding type (#84)

Every consumer has been migrated to the unified Finding type from
the sigma package (previous commits in this plan). With no remaining
producers or consumers, BugReportFinding is deleted.

ModuleResult is also cleaned up — it now holds only telemetry,
matching the telemetry-only return shape introduced in plan 5.

The unified refactor reaches spec §1's goal: one finding type across
the whole codebase, produced exclusively by SigmaRuleEngine, with
severity sourced from rule metadata.

Part of #84 (plan 6, phase D)."
```

---

## Phase E: Final Verification

### Task E1: Run all gradle checks

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
cd /home/yasir/AndroDR
./gradlew testDebugUnitTest 2>&1 | tail -20
./gradlew lintDebug 2>&1 | tail -10
./gradlew assembleDebug 2>&1 | tail -5
./gradlew detekt 2>&1 | tail -10
```
All four must be BUILD SUCCESSFUL.

### Task E2: Invariant checks

- [ ] **Check 1: `LegacyScanModule.kt` deleted**
```bash
test ! -f app/src/main/java/com/androdr/scanner/bugreport/LegacyScanModule.kt && echo "deleted" || echo "still exists"
```

- [ ] **Check 2: `BugReportFinding` deleted**
```bash
grep -rn "data class BugReportFinding\|class BugReportFinding" app/src/main/java/
```
Expected: zero hits.

- [ ] **Check 3: New rules exist**
```bash
ls app/src/main/res/raw/sigma_androdr_07*.yml
```
Expected: at least 6 new rules (071-076).

- [ ] **Check 4: Crash loop rule has correct metadata**
```bash
grep -A 2 "id: androdr-071" app/src/main/res/raw/sigma_androdr_071_*.yml
grep "category: incident\|level: medium" app/src/main/res/raw/sigma_androdr_071_*.yml
```

- [ ] **Check 5: Wakelock rule ships disabled**
```bash
grep "enabled: false" app/src/main/res/raw/sigma_androdr_072_*.yml
```

- [ ] **Check 6: `SigmaRuleEngine` has new typed evaluate methods**
```bash
grep -n "fun evaluate" app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt
```
Expected: original methods + 6 new ones.

- [ ] **Check 7: `AllRulesHaveCategoryTest` passes (all 6 new rules have category)**
```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.AllRulesHaveCategoryTest" 2>&1 | tail -10
```

- [ ] **Check 8: No stray references to `BugReportFinding` or `LegacyScanModule`**
```bash
grep -rn "BugReportFinding\|LegacyScanModule" app/src/
```
Expected: zero hits (except possibly in comments/docs).

### Task E3: Working tree clean + commit log

```bash
git status
git log c3c529b..HEAD --oneline
```
Expected: clean tree, 10-15 commits for plan 6.

---

## Plan 6 Retrospective Checklist

- [ ] `LegacyScanModule.kt` deleted with 3 tombstone commits + 1 final deletion commit
- [ ] `sigma_androdr_071_crash_loop_anti_forensics.yml` exists (incident, medium)
- [ ] `sigma_androdr_072_persistent_wakelock.yml` exists (incident, low, disabled)
- [ ] 4 minimal rules for BatteryDaily / PackageInstallHistory / PlatformCompat / DbPath (all disabled)
- [ ] `SigmaRuleEngine` has 6 new typed evaluate methods
- [ ] `TombstoneParser` and `WakelockParser` wired into `BugReportAnalyzer`
- [ ] `BugReportFinding` type deleted
- [ ] `ModuleResult` cleaned up
- [ ] All consumers migrated to unified `Finding`
- [ ] All gradle checks pass
- [ ] `AllRulesHaveCategoryTest` still passes with new rules
- [ ] No `LegacyScanModule` or `BugReportFinding` references remain

---

**End of plan 6.**

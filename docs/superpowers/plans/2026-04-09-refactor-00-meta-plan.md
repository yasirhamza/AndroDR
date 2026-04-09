# Unified Telemetry/Findings Refactor — Meta Plan

**Tracking issue:** #84
**Spec:** `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`
**Branch:** `claude/unified-telemetry-findings-refactor`
**Merge model:** Single atomic PR against `main`, opened at end of plan 7.

---

## Purpose of this document

The refactor is decomposed into **7 serialized sub-plans**. Each sub-plan is a standalone document that will be written, reviewed, and executed in sequence. This meta-plan is the table of contents: what each sub-plan does, what it establishes for the next one, and the execution order.

**Execution model:** write plan N → user approves → execute plan N via `superpowers:subagent-driven-development` → plan N's final commit is made → write plan N+1. Later plans are written against the *actual* codebase state after earlier plans execute, not against assumptions.

**Rollback model:** the branch is append-only during the refactor. If a later plan surfaces a design flaw in an earlier plan, we revise the later plan or revert specific commits on the branch — we do not rebase or force-push. The PR opens only once all 7 plans have completed.

---

## Branch status before refactor work begins

- `b37262e` spec (initial)
- `ba947ae` spec scrub (tester device info)
- `7635631` plan 1 (rule engine foundation)
- `79d2702` spec patch (RuleCategory/FindingCategory clarification)

Plan 1 is written and committed but **not yet executed**. Plans 2–7 are not yet written.

---

## Plan inventory

Each row: plan file, status, estimated task count, one-line goal.

| # | Plan | Status | Tasks | Goal |
|---|---|---|---|---|
| 1 | `refactor-01-rule-engine-foundation.md` | **Written** | ~12 (85 steps) | Rule engine layer: `RuleCategory` enum, required `category:` field in rule YAML, `SeverityCapPolicy`, correlation category propagation, disabled-by-default rule mechanism, build-time enforcement test. |
| 2 | `refactor-02-telemetry-foundation.md` | Pending | ~10 | Telemetry layer: `TelemetrySource` enum, new telemetry types (`PackageInstallHistoryEntry`, `BatteryDailyEvent`, `TombstoneEvent`, `WakelockAcquisition`, `PlatformCompatChange`, `SystemPropertySnapshot`, `DatabasePathObservation`), `source = LIVE_SCAN` field set explicitly by every runtime scanner, `ForensicTimelineEvent` provenance reconciliation. |
| 3 | `refactor-03-timeline-ui.md` | Pending | ~12 | Timeline UI: remove `ForensicTimelineEvent.severity`, update `UsageStatsScanner` to stop writing it, introduce `TimelineRow` sealed type (`TelemetryRow` / `FindingRow`), visual distinction in `TimelineEventCard`, "Hide informational telemetry" filter toggle (default OFF), export mode selector (telemetry / findings / both), bump export format version. |
| 4 | `refactor-04-oem-allowlist-and-fileartifact-iocs.md` | Pending | ~6 | OEM allowlist: add `com.unisoc.`, `com.sprd.`, `vendor.unisoc.`, `vendor.sprd.` to `known_oem_prefixes.yml`. FileArtifactScanner: extract hardcoded Pegasus/Predator paths to new `known_spyware_artifacts.yml` resource, introduce `KnownSpywareArtifactsResolver`. |
| 5 | `refactor-05-bugreport-parser-ports.md` | Pending | ~15 | Bugreport parser infrastructure: shared `BugReportParser` tokenizer, new `TombstoneParser` and `WakelockParser`, per-module ports (AppOps, Receiver, Activity, Accessibility, BatteryDaily, PlatformCompat, DbInfo) — each module becomes a telemetry producer and loses its hardcoded finding production in the same commit. Delete hardcoded `systemPackagePrefixes` / `sensitiveIntents` / `sensitiveSchemes` / `sensitiveDbPaths` / `dangerousOps` Kotlin constants. `BugReportAnalyzer` dispatches to new-style parsers for new telemetry. |
| 6 | `refactor-06-legacy-teardown-and-bugreportfinding-cleanup.md` | Pending | ~18 | Delete `LegacyScanModule.kt` with three tombstone commit messages (graphite keyword, base64 blob, C2 beacon). Author two new rules: `sigma_androdr_0XX_crash_loop_anti_forensics.yml` (incident, MEDIUM) and `sigma_androdr_0XX_persistent_wakelock.yml` (incident, LOW, disabled via plan 1's mechanism). Inventory (`grep -r BugReportFinding`), migrate all remaining consumers (`ReportExporter`, `ReportFormatter`, `ReportCsvWriter`, `HistoryViewModel`, `DashboardViewModel`, `AppsViewModel`, others). Delete `BugReportFinding` type. Delete obsolete `ModuleResult`. |
| 7 | `refactor-07-integration-and-pr.md` | Pending | ~8 | Redact tester's bugreport per spec R7 (scrub IMEI, phone number, device model, SoC, vendor fingerprints). Check in as test fixture. Write end-to-end regression test asserting: zero findings from deleted heuristics on clean device; zero HIGH/CRITICAL findings on `com.unisoc.*`, `com.sprd.*`, `com.go.browser`, `com.xiaomi.midrop`; every remaining finding traceable to a SIGMA rule by `ruleId`. Run full manual verification. Open PR against `main` with `Fixes #84` trailer. |

**Total estimated work:** ~81 tasks, ~400+ fine-grained steps, spread across 7 sub-plans. Single atomic PR at the end.

---

## Per-plan entry/exit contracts

Each plan begins with a known codebase state and leaves behind a known codebase state. Later plans depend on these contracts.

### Plan 1 — Rule Engine Foundation

**Entry state:** `claude/unified-telemetry-findings-refactor` at commit `79d2702`. Rule engine has inline severity cap at `SigmaRuleEvaluator.kt:126`. No `RuleCategory` enum. Rules don't declare `category:` at top level. Correlation findings have hardcoded category. No disabled-rule mechanism.

**Exit state:**
- `RuleCategory` enum exists (`INCIDENT`, `DEVICE_POSTURE`).
- `SigmaRule` has required `category: RuleCategory` field and optional `enabled: Boolean = true` field.
- `SigmaRuleParser` requires `category:` on detection + atom rules; rejects correlation rules that declare it.
- All 34 detection rule YAMLs + 5 atom rule YAMLs declare `category:`. 11 posture rules have `level: medium` or lower.
- `SeverityCapPolicy` exists as a standalone testable object.
- `SigmaRuleEvaluator.buildFinding()` uses `SeverityCapPolicy.applyCap(rule.category, rule.level)`.
- `SigmaCorrelationEngine.computeEffectiveCategory()` implements propagation; `evaluate()` accepts `atomRulesById`.
- `SigmaRuleEngine.effectiveRules()` filters disabled rules.
- `AllRulesHaveCategoryTest` passes (3 tests).
- All existing sigma tests pass.
- `FindingCategory`, `ScanResult`, ViewModels, `TimelineAdapter`, `ScanOrchestrator` — **untouched**.

**What plan 2 can assume:** `RuleCategory` exists, the cap policy is enforced, rules are correctly categorized, the disabled-rule mechanism works. Plan 2 does not modify the rule engine.

### Plan 2 — Telemetry Foundation

**Entry state:** end of plan 1. Telemetry data classes (`AppTelemetry`, `AppOpsTelemetry`, etc.) have no `source` field. No `TelemetrySource` enum. No new telemetry types.

**Exit state:**
- `TelemetrySource` enum exists in `com.androdr.data.model` (`LIVE_SCAN`, `BUGREPORT_IMPORT`).
- Every existing telemetry data class has a required `source: TelemetrySource` field (no default).
- Every runtime scanner (`AppScanner`, `DeviceAuditor`, `ReceiverAuditScanner`, `AccessibilityAuditScanner`, `AppOpsScanner`, `FileArtifactScanner`, `ProcessScanner`, `UsageStatsScanner`) sets `source = LIVE_SCAN` explicitly at every telemetry construction site.
- `ForensicTimelineEvent` has a canonical provenance model: the existing `isFromRuntime`/`isFromBugreport` booleans are consolidated into a single `telemetrySource: TelemetrySource` column (Room migration from v14 → v15).
- Seven new telemetry types exist in `com.androdr.data.model`: `PackageInstallHistoryEntry`, `BatteryDailyEvent`, `TombstoneEvent`, `WakelockAcquisition`, `PlatformCompatChange`, `SystemPropertySnapshot`, `DatabasePathObservation`. All are plain data classes (not Room entities) with `source: TelemetrySource` as a required field.
- Tests for every runtime scanner's source assignment pass.
- Room migration `MIGRATION_14_15` is tested.

**What plan 3 can assume:** every telemetry row carries an explicit `source`. New telemetry types exist as empty-shelled data classes, ready for producers to populate in later plans.

### Plan 3 — Timeline UI Refactor

**Entry state:** end of plan 2. `ForensicTimelineEvent` still has `severity: String`. `TimelineViewModel` emits a single-type list. `TimelineEventCard` renders all events uniformly. Export flow has no mode selector.

**Exit state:**
- `ForensicTimelineEvent.severity` field removed (Room migration from v15 → v16 drops the column and its index).
- `UsageStatsScanner.kt:126` no longer writes severity.
- `TimelineRow` sealed type exists with `TelemetryRow` and `FindingRow` variants.
- `TimelineViewModel` queries telemetry and findings separately, joins by timestamp, emits `List<TimelineRow>`.
- `TimelineScreen` / `TimelineEventCard` / `TimelineClusters` render `TelemetryRow` (neutral) and `FindingRow` (severity badge, category indicator, rule ID) distinctly.
- New filter toggle "Hide informational telemetry" exists, default OFF. Hides `TelemetryRow` entries not referenced by any finding.
- Export dialog has three radio options: telemetry only / findings only / both (default). `ReportExporter` produces bundles accordingly.
- Export format version bumped (field exists in existing export header).
- Timeline unit tests pass with the new `TimelineRow` structure.
- Existing export regression tests pass with the new bundle format.

**What plan 4 can assume:** the UI renders telemetry and findings distinctly; no code writes severity to timeline events; export format is structurally split.

### Plan 4 — OEM Allowlist + FileArtifact IOC Migration

**Entry state:** end of plan 3. `known_oem_prefixes.yml` lacks Unisoc/SPRD. `FileArtifactScanner.kt:32-38` has a hardcoded list of Pegasus/Predator paths.

**Exit state:**
- `known_oem_prefixes.yml` includes `com.unisoc.`, `com.sprd.`, `vendor.unisoc.`, `vendor.sprd.` under `chipset_prefixes`.
- New resource file `app/src/main/res/raw/known_spyware_artifacts.yml` exists, with the five current artifacts migrated plus metadata (family, source, first_observed) and `{ext_storage}` templating.
- New class `KnownSpywareArtifactsResolver` exists, loads and parses the YAML, exposes `paths(): List<String>`, and is Hilt-injected.
- `FileArtifactScanner` uses the resolver; hardcoded `knownArtifactPaths` deleted.
- Unit test for the resolver loads real YAML and asserts correct parsing.
- Existing `sigma_androdr_020_spyware_artifact.yml` rule is unchanged (still evaluates `FileArtifactTelemetry`).
- Regression test: pre/post-refactor, the resolver returns the same 5 paths.

**What plan 5 can assume:** the OEM allowlist is complete for Unisoc devices; future spyware artifact paths can be added via YAML without code changes.

### Plan 5 — Bugreport Parser Ports

**Entry state:** end of plan 4. Bugreport modules under `scanner/bugreport/` produce `BugReportFinding` objects directly via hardcoded Kotlin. `BugReportAnalyzer` dispatches to these modules and collects findings.

**Exit state:**
- New `BugReportParser` interface + implementation in `scanner/bugreport/` exposes tokenized access to sections (`appOpsEntries()`, `receiverRegistrations()`, `tombstones()`, etc.). The bugreport is parsed once; modules consume sequences.
- New `TombstoneParser` and `WakelockParser` classes exist, emit `TombstoneEvent` and `WakelockAcquisition` telemetry respectively.
- Seven bugreport modules ported to telemetry-only pattern in individual commits:
  - `AppOpsModule` → emits `AppOpsTelemetry` (`source = BUGREPORT_IMPORT`).
  - `ReceiverModule` → emits `ReceiverTelemetry`.
  - `ActivityModule` → emits `ForensicTimelineEvent` + `IntentObservation` (new telemetry type if needed).
  - `AccessibilityModule` → emits `AccessibilityTelemetry`.
  - `BatteryDailyModule` → emits `BatteryDailyEvent` + `PackageInstallHistoryEntry`.
  - `PlatformCompatModule` → emits `PlatformCompatChange`.
  - `DbInfoModule` → emits `DatabasePathObservation`.
- Each ported module has its hardcoded constant lists deleted (`sensitiveIntents`, `sensitiveSchemes`, `sensitiveDbPaths`, `dangerousOps`, `systemPackagePrefixes`).
- Each ported module has its finding-production code deleted; severity ternaries (`AppOpsModule.kt:91`) and `severity = "HIGH"` literals (`BatteryDailyModule.kt:64, 105`) deleted.
- `BugReportAnalyzer` invokes `SigmaRuleEngine.evaluateXxx()` on the new telemetry.
- `LegacyScanModule.kt` is still present but marked for deletion in plan 6. `BugReportAnalyzer` still dispatches to it for backward compat.
- Per-module unit tests verify telemetry output shape and correctness against recorded bugreport fixtures.

**What plan 6 can assume:** every bugreport module except `LegacyScanModule` is telemetry-only. `BugReportFinding` still exists as a type but has only one remaining producer.

### Plan 6 — LegacyScanModule Teardown + BugReportFinding Cleanup

**Entry state:** end of plan 5. `LegacyScanModule.kt` still produces five hardcoded heuristic findings. `BugReportFinding` type still exists and is referenced by downstream consumers.

**Exit state:**
- `LegacyScanModule.kt` **deleted**. Three commits have tombstone messages for the deleted heuristics:
  - "removed: naive 'graphite' substring match…"
  - "removed: base64 length heuristic was asking the wrong question…"
  - "removed: 'HTTP POST every N' regex was a proxy…"
- New rule `sigma_androdr_crash_loop_anti_forensics.yml` exists, category `incident`, level `medium`, references a new telemetry type `TombstoneEvent` (from plan 5).
- New rule `sigma_androdr_persistent_wakelock.yml` exists, category `incident`, level `low`, `enabled: false` (via plan 1's mechanism), documented as pending UAT tuning per #87.
- `BugReportAnalyzer` no longer dispatches to any hardcoded finding producer — it's entirely telemetry → rule engine.
- Inventory task at the start of the plan ran `grep -r BugReportFinding app/` and produced the full consumer list.
- All listed consumers migrated to use `Finding` (from the sigma package) directly:
  - `ReportExporter`
  - `ReportFormatter`
  - `ReportCsvWriter`
  - `HistoryViewModel`
  - `DashboardViewModel`
  - `AppsViewModel`
  - Any other file surfaced by grep
- `BugReportFinding` type **deleted**.
- `ModuleResult` type deleted or collapsed into a telemetry-only return type.
- Full test suite passes including the existing consumer tests (which now exercise unified `Finding`).

**What plan 7 can assume:** the codebase has exactly one finding type. No hardcoded finding producers remain. Every bugreport module is telemetry-only. Every runtime scanner routes through the rule engine. The refactor is functionally complete — plan 7 is verification only.

### Plan 7 — Integration, Regression Fixture, PR Opening

**Entry state:** end of plan 6. Refactor is functionally complete. No regression test fixture exists yet for the tester's bugreport.

**Exit state:**
- Tester's Redmi A5 bugreport redacted per spec R7: IMEI, phone number, installed apps list, device model, SoC details, vendor build fingerprints all scrubbed and replaced with stable placeholders.
- Redacted fixture checked in at `app/src/test/resources/fixtures/regression-unisoc-redmi-clean.txt`.
- New regression test `UnifiedRefactorRegressionTest` exists, runs the full pipeline (parse → telemetry → rule engine → findings) against the fixture, and asserts:
  - Zero findings for the graphite keyword (heuristic deleted in plan 6).
  - Zero findings for base64 blobs.
  - Zero findings for the C2 beacon regex.
  - Zero HIGH or CRITICAL findings on `com.unisoc.*`, `com.sprd.*`, `com.go.browser`, `com.xiaomi.midrop` packages.
  - Every produced finding has a non-empty `ruleId` field.
- Manual verification checklist executed: install debug build on a clean device, run full scan, compare pre/post refactor findings. Import the tester's bugreport, compare pre/post refactor. Run export flow in both telemetry-only and findings-only modes, verify well-formed output.
- `./gradlew testDebugUnitTest lintDebug assembleDebug detekt` all pass.
- PR opened against `main` with title "refactor: unified telemetry/findings architecture (#84)", body summarizing the seven plans and linking the spec.
- Follow-up issues #85 (MVT docs archive), #86 (DeviceAuditor bootloader), #87 (wakelock UAT), #88 (telemetry STATE/EVENT dedup) are acknowledged in the PR body with "Blocked by" or "Blocks" annotations as appropriate.

**Terminal state:** the branch is ready for merge. The refactor is done.

---

## Write-then-execute order (current approach)

```
Plan 1 (written) → execute → Plan 2 (write) → execute → Plan 3 (write) → execute → …
```

**Why this order:** each plan is written against the *actual* post-execution state of the earlier plans. If plan 1 execution surfaces an unexpected complication (a hidden consumer, a Room migration quirk, a test that breaks in an informative way), plan 2 can incorporate the discovery before being written. Writing all 7 plans upfront would bake in assumptions about code state that the implementation might contradict.

**Cost:** the review cycle is 7 separate checkpoints instead of 1. User sees plans incrementally.

## Alternative orders you can choose

| Order | Pros | Cons |
|---|---|---|
| **A. Serialized write + execute** (current) | Each plan accurate to real state. Discovery during plan N informs plan N+1. | 7 review checkpoints. Longer total wall time. |
| **B. Write all 7 upfront, execute sequentially** | Review the whole roadmap once. Single approval. | Plans 3-7 are speculative. Mid-execution discoveries force plan rewrites. |
| **C. Rolling window of 2 plans** | Balance: next plan ready before current finishes. | Slightly more speculative than A, slightly more coordination than B. |

**Recommendation:** stay with A (current). The refactor touches enough unfamiliar code that speculative later plans would probably need rewriting.

---

## Status tracker

Update this table as execution progresses.

| Plan | Written | Executed | Notes |
|---|---|---|---|
| 1 | ✅ `7635631` | ✅ `fd96d54..3aa3bef` (14 commits) | Approved for plan 2. Items 1-5 addressed in plan 2. |
| 2 | ✅ `10dcd6e` | ✅ `25a509e..a6f9f42` (11 commits) | All 5 plan 1 follow-ups addressed. Ready for plan 3. |
| 3 | ✅ `4c97116` | ✅ `06df9bc..04655ac` (4 commits) | Timeline UI refactor + severity removal + export modes. Ready for plan 4. |
| 4 | ✅ `a27ff19` | ✅ `f1304a9..a7e27d6` (3 commits) | Unisoc/SPRD added. FileArtifactScanner IOCs migrated to YAML. Ready for plan 5. |
| 5 | ✅ `f145432` | ✅ `31fcae5..37f8e51` (9 commits) | 7 modules ported, hardcoded constants deleted, TombstoneParser/WakelockParser created. Ready for plan 6. |
| 6 | ✅ `223cd34` | ✅ `4a111e5..4365d75` (7 commits) | LegacyScanModule deleted, BugReportFinding removed, 6 new rules + typed evaluate methods. Ready for plan 7. |
| 7 | ✅ `8956092` | ✅ `1346676..a8ecd0a` (2 commits) | Fixture + regression test + **PR #89 opened against main**. Refactor complete. |

## Items flagged during plan 1 execution (for plan 2 attention)

1. **`atomRulesById` lookup uses `getRules()` not `effectiveRules()`** — `ScanOrchestrator.kt:367,517` build the lookup from all rules including disabled ones. A disabled atom rule still contributes its category to correlation propagation (though it produces no actual bindings, so correlations can't fire via it). Minor asymmetry; resolve when touching ScanOrchestrator in a later plan.
2. **`SigmaRuleEngine.getRules()` is still public** — consider reducing visibility or adding a `getEnabledRules()` alias as call sites multiply.
3. **`CorrelationRule` lacks "category is derived, never stored" KDoc** — add when next touching the file.
4. **`Finding()` constructor can bypass `SeverityCapPolicy`** — only convention enforces routing through `SigmaRuleEvaluator.buildFinding()`. Consider a factory pattern.
5. **`SigmaRuleEngine.ruleCount()` is undocumented** — returns total including disabled. Add KDoc.

---

**End of meta-plan.**

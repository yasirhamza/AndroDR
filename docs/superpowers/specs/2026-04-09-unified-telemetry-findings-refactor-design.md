# Unified Telemetry/Findings Architecture — Design Spec

**Status:** Approved, ready for implementation
**Tracking issue:** #84
**Related follow-ups:** #85 (MVT docs archive), #86 (DeviceAuditor bootloader), #87 (wakelock UAT tuning), #88 (telemetry STATE/EVENT deduplication)
**Date:** 2026-04-09

---

## 1. Motivation

A tester on a Unisoc-based Android device received an AndroDR report that was alarming for the wrong reasons. Findings included:

- **CRITICAL** alerts for the keyword "graphite" — matched against Android's Skia `graphite_renderengine` feature flag, a stock AOSP graphics config, not the Paragon/Graphite spyware.
- **Hundreds of HIGH** "SuspiciousData: possible exfiltration payload" alerts — matched against any base64 string ≥100 characters, which bugreports contain by design (protobuf, keys, dumpsys output).
- **HIGH** risk ratings on `com.unisoc.*` system firmware packages, `com.go.browser` (stock AOSP-Go browser), and `com.xiaomi.midrop` (ShareMe) — OEM preloads flagged as third-party threats.
- **CRITICAL** "C2Beacon" alerts from a regex matching `"HTTP.*POST.*every [0-9]+"` on bugreport text.

Two audits (one of the bugreport subdirectory, one of the runtime scanners) revealed the structural causes:

1. **Hardcoded detection heuristics in Kotlin.** `bugreport/LegacyScanModule.kt` alone contains five hardcoded detection patterns (keyword regex, base64 length threshold, C2 beacon regex, crash loop counter, wakelock density) that emit findings directly, with inline severity literals (`"CRITICAL"`, `"HIGH"`) and hardcoded categories (`"KnownMalware"`, `"SuspiciousData"`, `"C2Beacon"`). None of these go through `SigmaRuleEngine`. This directly violates the project principle that detection logic must live in SIGMA YAML rules ([project_rule_engine.md]).

2. **Two parallel finding pipelines.** The runtime scanners (`AppScanner`, `DeviceAuditor`, `AppOpsScanner`, etc.) produce `Finding` objects via `SigmaRuleEngine`. The bugreport modules produce `BugReportFinding` objects directly. Downstream code (exporter, CSV writer, UI, correlation) knows about both types. This parallel architecture is what let the hardcoded heuristics survive — they had their own type system and never interacted with the rule engine they were supposed to integrate with.

3. **Hardcoded severity and filtering throughout `bugreport/`.** `AppOpsModule` ternary: `severity = if (op == "REQUEST_INSTALL_PACKAGES") "HIGH" else "INFO"`. `BatteryDailyModule` inline: `severity = "HIGH"` for package uninstall with IOC hit. Three separate hardcoded `systemPackagePrefixes` lists in `ReceiverModule`, `ActivityModule`, `AccessibilityModule`, none of which include Unisoc. Five separate hardcoded IOC-style lists (`dangerousOps`, `sensitiveIntents`, `sensitiveSchemes`, `sensitiveDbPaths`, `knownArtifactPaths`) embedded as Kotlin constants.

4. **Runtime scanners are materially cleaner.** 12 of 14 runtime scanner files follow the correct pattern: collect telemetry, hand it to `SigmaRuleEngine`, let rules produce findings. Only two minor violations exist (`DeviceAuditor.kt:163` substring heuristic, `FileArtifactScanner.kt:32-38` hardcoded path list). The runtime layer is the reference implementation the bugreport layer must converge toward.

The tester's false-positive experience is the visible failure mode. The underlying architectural drift — one policy-compliant half of the codebase and one parallel hardcoded half — is the thing that needs fixing.

---

## 2. Principles

Six invariants, each of which the refactor must preserve or establish. These are load-bearing decisions that future sprints must not erode.

**P1. Two strictly separated layers.** *Telemetry* (Layer 1, ground truth) is separated from *Findings* (Layer 2, derived matches). Telemetry has no severity, no category, no judgment. Findings are produced exclusively by `SigmaRuleEngine` and `SigmaCorrelationEngine` evaluating telemetry. Given the same telemetry + the same ruleset, findings are deterministic; given the same telemetry + a different ruleset, an analyst gets different findings — which is the whole point of exporting telemetry for third-party analysis.

**P2. One finding type.** `BugReportFinding` is deleted. Every finding in the app is a `Finding` produced by the rule engine. Severity, category, and description always come from rule metadata, never from Kotlin literals.

**P3. Severity caps by category.** Every rule declares a required `category:` field. Two categories exist: `incident` (attributable evidence that something happened; uncapped) and `device_posture` (a condition enabling future compromise; capped at MEDIUM). The cap is enforced by the engine at evaluation time, and by a build-time unit test that fails CI if any `device_posture` rule declares a higher severity. Correlation rules inherit `incident` if any member rule is `incident`, otherwise inherit `device_posture`.

**P4. Telemetry is schema-first and source-agnostic.** Telemetry types are named after the facts they represent (`AppOpsTelemetry`, `PackageInstallHistory`), never after their source (no `BugReportBatteryDailyEntry`). One canonical namespace. A telemetry type may have multiple producers (live scanner + bugreport parser) or one (bugreport-only facts like tombstone events) — rules don't care. Provenance lives as a `source: TelemetrySource` field on every telemetry row, never as a type distinction.

**P5. No hardcoded detection data in Kotlin.** IOC lists, keyword patterns, sensitive-intent lists, artifact paths, and OEM prefix allowlists live in YAML resources (evaluated by rules) or in the rule files themselves. Kotlin constants are permitted for *observation targets* (which permissions to watch, which intents to collect telemetry on) because those define what data the telemetry layer gathers — the *judgment* of whether that data is suspicious is always the rule layer's job.

**P6. Single atomic PR.** The refactor ships as one coherent unit. No feature flags, no staged rollout, no intermediate dual-pipeline state. Architectural changes need to land together or they create drift worse than the original problem.

---

## 3. Architecture: Two Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                       LAYER 1: TELEMETRY                        │
│                                                                 │
│  ┌─────────────────┐   ┌─────────────────┐   ┌──────────────┐   │
│  │  Live scanners  │   │  Bugreport      │   │  Future      │   │
│  │                 │   │  parsers        │   │  sources     │   │
│  │  AppScanner     │   │  (was modules)  │   │  (ADB import,│   │
│  │  AppOpsScanner  │   │  AppOpsParser   │   │   analyst    │   │
│  │  DeviceAuditor  │   │  ReceiverParser │   │   upload…)   │   │
│  │  ...            │   │  ...            │   │              │   │
│  └────────┬────────┘   └────────┬────────┘   └──────┬───────┘   │
│           │                     │                   │          │
│           └─────────┬───────────┴───────────────────┘          │
│                     ▼                                          │
│     Canonical telemetry namespace (com.androdr.data.model):    │
│       AppTelemetry, AppOpsTelemetry, ReceiverTelemetry,        │
│       AccessibilityTelemetry, DeviceTelemetry,                 │
│       ForensicTimelineEvent, PackageInstallHistory,            │
│       TombstoneEvent, WakelockAcquisition, …                   │
│                                                                │
│     Every row carries: source: TelemetrySource                 │
│                         (LIVE_SCAN | BUGREPORT_IMPORT | …)     │
└────────────────────────────────┬───────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────┐
│                    LAYER 2: RULE EVALUATION                    │
│                                                                │
│   SigmaRuleEngine.evaluateX(telemetry) ────────┐               │
│                                                │               │
│   SigmaCorrelationEngine.evaluate(             │               │
│     timeline, atomicFindings                   │               │
│   ) ────────────────────────────────────────────┤              │
│                                                │               │
│                                                ▼               │
│                                        Finding (unified type)  │
│                                        rule_id, level,         │
│                                        category, description,  │
│                                        evidence, remediation   │
└────────────────────────────────────────────────────────────────┘
```

**Data flow.** A scan run produces telemetry rows (Layer 1) which are persisted in Room. `SigmaRuleEngine` reads telemetry rows and produces `Finding` rows (Layer 2), also persisted. `SigmaCorrelationEngine` runs over the resulting finding set and the `ForensicTimelineEvent` stream to produce additional `Finding` rows (correlation findings). The UI and reports read both telemetry and findings from their respective tables.

**Re-evaluation is pure.** Given a stored telemetry snapshot and a ruleset version, running the engine always produces the same findings. This is the property that makes analyst portability work: an exported bundle contains the telemetry, and an external analyst running their own rules against it gets a deterministic evaluation.

**Exports have two sections.** `ReportExporter` writes Telemetry and Findings as distinct sections of the export bundle. Telemetry is always fully populated regardless of whether any rule fired. Findings reflect the ruleset version at export time. An analyst may discard the Findings section and re-derive it with a different ruleset.

**Storage.** Telemetry rows and finding rows live in separate Room tables with a foreign key from findings to the telemetry rows they evaluated (where practical — some correlation findings reference multiple telemetry rows and use a join table). Deleting all findings and re-running the engine is a pure function of the telemetry tables.

**No severity in Layer 1.** `ForensicTimelineEvent`'s current `severity` field (seen at `UsageStatsScanner.kt:126` as `severity = "INFO"`) is removed. Timeline events are pure observation — timestamp, source, category (observational, like `app_foreground`), description. The UI's color-coding of timeline entries (if any) must come from findings that reference the event, not from a property of the event itself.

---

## 4. Source-Agnostic Telemetry Schema

The telemetry layer is defined by **what kind of fact it represents**, never by **where it came from**. This section is separated out because it's the easiest invariant to accidentally break during implementation.

### Canonical namespace

All telemetry types live in `app/src/main/java/com/androdr/data/model/` (the existing telemetry package). There is no `bugreport.telemetry` sub-package. There is no `import.telemetry` package. One namespace, facts-first naming.

Types currently in this namespace (runtime scanner telemetry, already clean):

- `AppTelemetry`
- `AppOpsTelemetry`
- `ReceiverTelemetry`
- `AccessibilityTelemetry`
- `DeviceTelemetry`
- `ProcessTelemetry`
- `FileArtifactTelemetry`
- `ForensicTimelineEvent`

Types to be added by this refactor (moving bugreport-sourced data into the canonical namespace):

- `PackageInstallHistoryEntry` — per-package install/uninstall events with timestamps. Currently only derivable from `batterystats` bugreport data; may be augmented by future live-device sources.
- `BatteryDailyEvent` — per-day battery stats events relevant to detection (package uninstall, version change). Bugreport-only for now.
- `TombstoneEvent` — parsed tombstone records (process name, signal, crash timestamp). Bugreport-only. Replaces the hardcoded crash-loop heuristic in `LegacyScanModule`.
- `WakelockAcquisition` — structured wakelock records from the power section. Bugreport-only. Replaces the hardcoded density heuristic in `LegacyScanModule`.
- `PlatformCompatChange` — compatibility framework ChangeId enable/disable events. Bugreport-only. Replaces the hardcoded `CHANGE_ID_DOWNSCALED` check in `PlatformCompatModule`.
- `SystemPropertySnapshot` — relevant `ro.*` and `persist.*` system properties extracted from bugreport. Enables rules to evaluate bootloader state, verified boot state, etc., sourced from bugreport imports (parallel to the live `DeviceAuditor` telemetry).
- `DatabasePathObservation` — presence/path observations for known-sensitive database files. Replaces hardcoded `sensitiveDbPaths` in `DbInfoModule`.

### Naming discipline

Types are named after the fact, not the source. Examples of **forbidden** names:

- ❌ `BugReportBatteryDailyEntry` — leaks source into the type name
- ❌ `ImportedTombstoneRecord` — same
- ❌ `LegacyWakelockEvent` — describes where it came from, not what it is
- ❌ `BrBatteryEvent` — abbreviation of source

**Correct** names:

- ✅ `BatteryDailyEvent` — names the fact
- ✅ `TombstoneEvent` — names the fact
- ✅ `WakelockAcquisition` — names the fact

### Provenance as a field

Every telemetry row carries:

```kotlin
enum class TelemetrySource {
    LIVE_SCAN,          // produced by a runtime scanner on this device
    BUGREPORT_IMPORT,   // produced by parsing an imported bugreport
    // Future values reserved: ADB_SHELL_IMPORT, ANALYST_UPLOAD, …
}

data class SomeTelemetry(
    val someField: String,
    val otherField: Int,
    val source: TelemetrySource,        // REQUIRED, no default
    val capturedAt: Long,               // epoch millis
    // …
)
```

The `source` field has no default. Every telemetry constructor call must name it explicitly. This prevents "implicit LIVE_SCAN" drift and makes the PR diff visibly show which scanner is setting which source.

Rules may optionally filter on `source` (e.g. `source: BUGREPORT_IMPORT` for a rule that only makes sense on imported data), but the default is source-agnostic: a rule that doesn't mention `source` evaluates telemetry regardless of where it came from.

### Worked example: `PackageInstallHistoryEntry`

This is the non-obvious case. `BatteryDailyModule` currently parses package-install-history from the bugreport's `batterystats --history` section and produces findings directly. There is no live-device Android API that gives us the same data (install timestamps are lossy via `PackageManager`).

**Wrong design.** Create `BugReportPackageInstallHistory` in a bugreport-specific package, because it's "bugreport-only".

**Right design.** Create `PackageInstallHistoryEntry` in `com.androdr.data.model/`. Mark the single producer (the bugreport parser) as setting `source = BUGREPORT_IMPORT`. Rules that evaluate install history are written source-agnostic:

```yaml
# sigma_androdr_0XX_known_bad_package_install_history.yml
id: androdr-0XX
category: incident
level: high
detection:
  selection:
    telemetry_type: PackageInstallHistoryEntry
    package_name|in_list: known_bad_packages
  condition: selection
```

If Android ever ships an API that lets us read install history on the live device, we add a second producer that emits the same `PackageInstallHistoryEntry` type with `source = LIVE_SCAN`. **Zero rule changes needed.** The rule was never coupled to the source.

This is the property that makes the telemetry namespace a stable contract.

### The telemetry namespace is a compatibility boundary

Downstream analyst tooling, exported bundle schemas, and rule YAML all depend on telemetry type names and field layouts being stable. Renaming a telemetry type or field is a breaking change equivalent to renaming a public API. If we need to rename one during the refactor, we do it carefully and once — and the new name needs to survive future sprints.

---

## 5. Unified `Finding` Type

### Current state

Two finding types exist:

- `Finding` — defined in `app/src/main/java/com/androdr/sigma/Finding.kt`. Produced by `SigmaRuleEngine`. Carries `ruleId`, `level`, `category` (via `display.category`), `description`, `evidence`, `remediation`. Used by runtime scanners.
- `BugReportFinding` — defined in the bugreport package. Produced directly by bugreport modules. Carries its own `severity` string, its own `category` string, its own `description`. No `ruleId`. No connection to rules.

Downstream consumers (`ReportExporter`, `ReportFormatter`, `ReportCsvWriter`, history screen UI, risk dashboard) handle both types via separate code paths.

### Target state

`BugReportFinding` is deleted. `Finding` is the only finding type in the app. Every finding in the app carries a `ruleId` — if it doesn't trace back to a rule, it doesn't exist.

Downstream consumers handle exactly one type. Code paths that currently branch on "is this a BugReportFinding or a Finding?" collapse into unified code.

### Migration of downstream consumers

The following files currently consume `BugReportFinding` directly or via `BugReportAnalyzer.Result`:

- `reporting/ReportExporter.kt` — formats findings into the shared export. Must be rewritten to read `Finding` from the unified findings table.
- `reporting/ReportFormatter.kt` — same.
- `reporting/ReportCsvWriter.kt` — CSV export. Must be rewritten to emit unified fields. The existing schema (see recent commits `ec613ad`, `ed94402`, `5e91989`) already has finding-related columns; the refactor must preserve backward compatibility for exported CSVs consumed by external tools. Concretely: existing column names stay, but bugreport-sourced findings now populate the same columns runtime findings already use.
- `ui/history/HistoryViewModel.kt` — history screen data source. Should read from the unified findings table.
- `ui/dashboard/DashboardViewModel.kt` — risk summary and category counts. Must aggregate over the unified table.
- `ui/apps/AppsViewModel.kt` — may consume findings for per-app risk badges.
- Any other file found via `grep BugReportFinding` during implementation. The Explore agent's audit identified the above as the primary consumers but an exhaustive list must be produced at implementation time.

### What `BugReportAnalyzer` becomes

Currently: a finding-producing analyzer that dispatches to modules, collects `BugReportFinding` objects, and returns them.

After the refactor: a telemetry producer. It parses the bugreport file into telemetry rows (via the per-module parsers described in §7), writes them to the telemetry tables with `source = BUGREPORT_IMPORT`, and returns. Finding production happens afterward when `SigmaRuleEngine` is invoked over the new telemetry rows — the same way runtime scan findings are produced.

### Finding type field list

`Finding` keeps its existing shape. Its `FindingCategory` (`DEVICE_POSTURE` / `APP_RISK` / `NETWORK`) stays as-is — it drives **UI display and scoring** (which screen shows the finding, how `ScanResult` buckets it for the risk score) and must not be confused with the new policy-level rule category introduced in §6.

### Finding category vs. rule category — a critical distinction

**`FindingCategory`** (existing enum, unchanged): `DEVICE_POSTURE`, `APP_RISK`, `NETWORK`. Populated from each rule's `display.category:` YAML field. Used only for UI display and scoring logic in `ScanResult.kt`, `AppScanViewModel`, `DeviceAuditViewModel`, and `TimelineAdapter`. **Not touched by this refactor.**

**`RuleCategory`** (new enum, introduced by §6): `INCIDENT`, `DEVICE_POSTURE`. Populated from each rule's new top-level `category:` YAML field. Used only for policy enforcement (severity cap, correlation propagation) in `SeverityCapPolicy` and `SigmaCorrelationEngine`.

**The two are orthogonal.** An `APP_RISK` finding produced by an `incident`-class rule is perfectly normal — it's shown on the Apps screen (FindingCategory) and is uncapped (RuleCategory). A `DEVICE_POSTURE` finding produced by a `device_posture`-class rule is likewise normal — shown on the Device screen and capped at MEDIUM. The naming overlap (`DEVICE_POSTURE` exists in both enums) is unfortunate but harmless because the two enums live in different namespaces and are used in different call paths.

### No `source` field on Finding

The telemetry layer carries `source: TelemetrySource`. Findings do not. Rationale: a finding's provenance is fully determined by the telemetry it evaluated, accessible via the evidence reference. Adding a redundant `source` field on findings would create two sources of truth. UI that wants to distinguish "this finding came from an imported bugreport" does so by inspecting the finding's evidence → underlying telemetry → `source` field.

---

## 6. Severity Caps by Rule Category

This is the section most important to prevent future erosion. It gets its own load-bearing treatment.

**Terminology reminder (see §5):** this section concerns `RuleCategory` — the new policy-level enum introduced by this refactor — not `FindingCategory` (the existing UI/scoring enum). Rules declare `category:` in their YAML. The engine uses that declaration to cap severity and propagate correlation classification. `FindingCategory` is untouched.

### The policy

Every rule declares a required `category:` field with one of two values:

- **`incident`** — evidence that something happened or is happening. Attribution to a specific app, event, or actor. Examples: IOC match, app with accessibility + surveillance permissions installed, spyware file artifact present, known-bad domain contacted. **Uncapped.** May declare any severity.

- **`device_posture`** — a condition that enables future compromise but is not itself an incident. Not attributable to an active actor. Examples: bootloader unlocked, no screen lock, ADB enabled, outdated security patch, exploitable CVE present on device. **Capped at MEDIUM.** The engine clamps any `device_posture` finding to `level = min(declared, MEDIUM)` at evaluation time.

### Why the cap

If every weak configuration is red, nothing is. Posture issues must not out-shout actual intrusions in the UI, the report summary, or the dashboard risk score. A bootloader-unlocked device with no active threats is a MEDIUM risk. A bootloader-unlocked device *and* a Pegasus IOC match should be CRITICAL — and it will be, via the correlation propagation rule below.

### Categorization principle

Category reflects the *nature* of the event (something happened vs. a condition exists), not the severity. Some edge cases:

- A sideloaded app is an **incident** even if low severity. The installation was an event; severity reflects how suspicious it is, but the category is fixed by the nature.
- A CVE being exploitable on the device is **device_posture** even if the CVE is critical. The condition exists; no exploitation has been observed. If exploitation is observed, a different rule (spyware artifact, IOC match, or correlation) catches it and is incident-category.
- An accessibility service being enabled for a specific app is **incident**. Attribution to the app makes it behavior evidence, even though it's a state.

### Correlation rule propagation

Correlation rules inherit category from their member rules:

- If **any** member rule is `incident` → the correlation is `incident`, **uncapped**.
- If **all** member rules are `device_posture` → the correlation is `device_posture`, **capped at MEDIUM**.

This is why "bootloader unlocked AND known-bad domain contacted within 24h" reaches HIGH/CRITICAL: the domain IOC leg is incident-category, which promotes the whole correlation to incident. Posture signals alone stacking — "bootloader unlocked AND no screen lock AND ADB enabled" — remain capped at MEDIUM because no leg is an incident.

The propagation is explicit in the engine, not inferred from member severities.

### Engine enforcement

In `SigmaRuleEngine`:

```kotlin
object SeverityCapPolicy {
    // Map of rule category → maximum permitted finding severity.
    // See docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md §6
    // for why device_posture is capped at medium.
    private val caps: Map<RuleCategory, String> = mapOf(
        RuleCategory.DEVICE_POSTURE to "medium",
    )

    fun applyCap(category: RuleCategory, declared: String): String {
        // see plan 1 for the full implementation with severity ordering
        // and case-insensitive handling
    }
}
```

Every `Finding` produced by the engine passes through `SeverityCapPolicy.applyCap(rule.category, rule.level)`. The cap is applied at `buildFinding()` time — downstream code never sees a device_posture finding above `medium`. Note that the cap reads `rule.category` (the new `RuleCategory` field), not `finding.category` (the existing `FindingCategory` used for UI display).

For correlation findings, `SigmaCorrelationEngine` computes the effective rule category via the propagation rule before applying the cap:

```kotlin
fun computeEffectiveCategory(
    referencedRuleIds: List<String>,
    atomRulesById: Map<String, SigmaRule>,
): RuleCategory {
    val knownCategories = referencedRuleIds
        .mapNotNull { atomRulesById[it]?.category }
    if (knownCategories.isEmpty()) return RuleCategory.INCIDENT  // safe default
    return if (knownCategories.any { it == RuleCategory.INCIDENT }) {
        RuleCategory.INCIDENT
    } else {
        RuleCategory.DEVICE_POSTURE
    }
```

### Build-time enforcement

A unit test in `SigmaRuleEngineTest` enumerates all bundled rules in `res/raw/sigma_androdr_*.yml`, parses them, and asserts:

1. Every rule declares a `category:` field. Missing category = test fails.
2. Every `category: device_posture` rule declares `level:` ≤ MEDIUM. A rule declaring `level: high, category: device_posture` fails CI — rule authors can't silently ship a rule that the engine would clamp, because clamping is supposed to be a safety net, not normal operation.

A second unit test validates correlation propagation: given synthetic rules with known categories, assert that a correlation with any incident member produces an incident-category finding and a correlation with only device_posture members produces a device_posture finding capped at MEDIUM.

### Rule YAML schema change

The SIGMA rule parser (`SigmaRuleParser`) is updated to:

1. Require a `category:` field on every rule. Parsing fails with a clear error if missing.
2. Accept only `incident` or `device_posture` as values. Any other value fails with an error listing the valid options.
3. Deprecate `display.category` as a source of category data. `display.category` may continue to exist for display purposes (subtitle text etc.) but is separate from the policy category.

### Migration of existing rules

All bundled rules in `app/src/main/res/raw/sigma_androdr_*.yml` need a top-level `category:` field added. A full audit (post-spec) identified the actual bundled rule count:

- **Detection rules (34):** 001, 002, 003, 004, 005, 010, 011, 012, 013, 014, 015, 016, 017, 018, 020, 040, 041, 042, 043, 044, 045, 046, 047, 048, 049, 050, 060, 061, 062, 063, 064, 065, 067, 068.
- **Atom rules (5):** atom_app_launch, atom_device_admin_grant, atom_dns_lookup, atom_package_install, atom_permission_use.
- **Correlation rules (4):** corr_001, corr_002, corr_003, corr_004 — do **not** get a top-level `category:` field (their effective category is computed at evaluation time from member rule categories).

**Authoritative category assignment:**

- **`incident` (23 detection + 5 atom = 28 rules):** 001–005 (IOC), 010–018 (app behavior), 020 (spyware artifact), 060, 061, 062, 063, 064, 065, 067, 068 (receivers, appops, notification listener, hidden launcher), plus all 5 atom rules.
- **`device_posture` (11 rules, all severity clamped to `medium` or below):** 040, 041, 042, 043, 044, 045, 046, 047, 048, 049, 050.

Any posture rule currently declaring `level: high` or `level: critical` is downgraded to `level: medium` as part of this refactor. The exact list depends on the current YAML state, inspected per-file during plan 1 execution.

The catalog doc (`docs/detection-rules-catalog.md`) was updated in the pre-refactor cleanup commit `bb7d149` with the category assignments and severity downgrades. The YAML files themselves are updated in plan 1 (see `docs/superpowers/plans/2026-04-09-refactor-01-rule-engine-foundation.md`, phase C).

---

## 7. Bugreport Parser Refactor

### Current module pattern

Each bugreport module under `app/src/main/java/com/androdr/scanner/bugreport/` mixes two responsibilities: parsing its section of the bugreport file, and producing findings. Modules return `ModuleResult` containing `List<BugReportFinding>` and `List<TimelineEvent>`, both with hardcoded severity literals.

### Target module pattern

Bugreport modules become **parsers only**. Each module:

1. Receives access to the bugreport's parsed sections via a shared `BugReportParser` facade (extracted from the existing section-parsing code; avoids re-tokenizing the same file multiple times across modules).
2. Emits canonical telemetry objects from `com.androdr.data.model/` with `source = BUGREPORT_IMPORT`.
3. Returns — no findings, no severity, no categories.

`BugReportAnalyzer` collects telemetry from all modules, writes it to the telemetry tables, and invokes `SigmaRuleEngine` to produce findings from the new telemetry rows. This is structurally identical to how `ScanOrchestrator` handles runtime scan telemetry today.

### Per-module migration table

| Current module | Target telemetry type(s) emitted | Rules that evaluate the telemetry |
|---|---|---|
| `AppOpsModule.kt` | `AppOpsTelemetry` (existing; shared with `AppOpsScanner`) | Existing: 063 appops_microphone, 064 appops_camera, 065 appops_install_packages. Severity ternary at line 91 is deleted; rules own severity. |
| `ReceiverModule.kt` | `ReceiverTelemetry` (existing; shared with `ReceiverAuditScanner`) | Existing: 061 sms_receiver, 062 call_receiver. Hardcoded `sensitiveIntents` / `systemPackagePrefixes` / `dangerousOps` in the module are deleted; rules filter on telemetry fields. |
| `ActivityModule.kt` | `ForensicTimelineEvent` entries for activity transitions + `IntentObservation` (new, for sensitive-scheme tracking) | Existing timeline correlation rules. Any new `IntentObservation` rules live in a new rule file. Hardcoded `sensitiveSchemes` / `systemPackagePrefixes` lists deleted. |
| `AccessibilityModule.kt` | `AccessibilityTelemetry` (existing; shared with `AccessibilityAuditScanner`) | Existing: 012 accessibility_abuse, 017 accessibility_surveillance_combo, 060 active_accessibility. Hardcoded `systemPackagePrefixes` list deleted. |
| `BatteryDailyModule.kt` | `BatteryDailyEvent` + `PackageInstallHistoryEntry` (new) | New rule(s) for package uninstall with IOC hit and version downgrade. Must be authored as part of this PR (see §11 testing). Hardcoded `severity = "HIGH"` literals at lines 64, 105 deleted. |
| `PlatformCompatModule.kt` | `PlatformCompatChange` (new) | New rule for ChangeId-based anti-analysis detection, authored as part of this PR. Hardcoded `CHANGE_ID_DOWNSCALED` constant deleted. |
| `DbInfoModule.kt` | `DatabasePathObservation` (new) | New rule for sensitive-database-access detection, authored as part of this PR. Hardcoded `sensitiveDbPaths` list deleted. |
| `LegacyScanModule.kt` | See §8 — the whole file is deleted. | — |

### Shared parser

A `BugReportParser` class (or a set of extension functions on the existing section-parser) tokenizes the bugreport once and exposes typed accessors for each section:

```kotlin
interface BugReportParser {
    fun appOpsEntries(): Sequence<RawAppOpsEntry>
    fun receiverRegistrations(): Sequence<RawReceiverEntry>
    fun activityHistory(): Sequence<RawActivityEntry>
    fun accessibilityServices(): Sequence<RawAccessibilityEntry>
    fun batteryDailySections(): Sequence<RawBatterySection>
    fun tombstones(): Sequence<RawTombstoneEntry>
    fun wakelockRecords(): Sequence<RawWakelockEntry>
    fun platformCompatEvents(): Sequence<RawPlatformCompatEntry>
    fun databasePathReferences(): Sequence<RawDbPathEntry>
    fun systemProperties(): Map<String, String>
}
```

Each bugreport module consumes one or more of these sequences and maps `Raw*` structs to canonical telemetry types. The `Raw*` structs are private to the bugreport package — they represent the bugreport file format, not the canonical data model. Only canonical telemetry types cross the bugreport package boundary.

This gives us three benefits:

1. **Parse the file once.** Currently multiple modules re-scan the bugreport text for overlapping patterns.
2. **Clear contract.** The parser's interface defines exactly what data the bugreport can yield. New modules extend the interface; they don't re-implement tokenization.
3. **Test isolation.** The parser can be tested against recorded bugreport fixtures independent of the telemetry mapping.

### Removal of hardcoded allowlists

Three separate `systemPackagePrefixes` lists exist in `ReceiverModule.kt`, `ActivityModule.kt`, and `AccessibilityModule.kt`. All three are deleted. The canonical source becomes `app/src/main/res/raw/known_oem_prefixes.yml`, read via the existing `OemPrefixResolver`. **The refactor adds Unisoc, Spreadtrum (SPRD), and related ODM prefixes** to that YAML file to fix the Unisoc-device false-positive that motivated this entire refactor:

```yaml
chipset_prefixes:
  - "com.unisoc."
  - "com.sprd."
  - "vendor.unisoc."
  - "vendor.sprd."
```

Any rule that filters on "is this a system / OEM / chipset package" does so via a telemetry field (`is_known_oem_app: Boolean`) populated by the resolver. No rule and no module contains hardcoded prefix lists.

---

## 8. LegacyScanModule Migration

`app/src/main/java/com/androdr/scanner/bugreport/LegacyScanModule.kt` is deleted entirely. Its name was already a signal it didn't belong. Its five heuristics are handled as follows.

### Deleted outright (3)

These are fundamentally broken detections that have no rule-shaped version worth porting. The deletion commit messages document why, so future contributors don't re-invent them.

**1. "graphite" keyword match** (lines 27–30, 132–143).

Current: `Regex("pegasus|spyware|flexispy|mspy|cerberus|droiddream|BIGPRETZEL|graphite", IGNORE_CASE)` emitting CRITICAL findings whenever any match is found in any bugreport line.

Problem: naive substring match with no word boundaries. Matches AOSP's `graphite_renderengine` feature flag anywhere in dumpsys output. Every modern Android device ships with this flag in its system properties. This single heuristic generates **4 CRITICAL false positives** on every clean device.

Replacement: none. Real Graphite/Paragon detection already exists as CVE and domain IOC rules (`androdr-005` graphite domain IOC, `androdr-048` pegasus CVEs, `androdr-049` predator CVEs, and the corresponding graphite CVE rules). The keyword heuristic was a proxy for rules that already exist.

Tombstone commit message: *"removed: naive 'graphite' substring match produced CRITICAL false positives on every device with Skia Graphite render engine (AOSP feature flag `graphite_renderengine`). Real Graphite/Paragon detection lives in `androdr-005` and the graphite/pegasus/predator CVE rules. The keyword regex had no word boundaries and no context exclusions; there is no version of a substring match on security vendor names that produces signal without noise."*

**2. Base64 blob length heuristic** (lines 32–35, 147–157).

Current: `Regex("[A-Za-z0-9+/]{100,}={0,2}")` emitting HIGH `"SuspiciousData: possible exfiltration payload"` for every base64 string ≥100 characters in the bugreport.

Problem: bugreports legitimately contain hundreds of base64 strings by design — protobuf dumps, serialized Java objects, certificate chains, binary sections encoded for inclusion in text reports. The tester's clean-device report showed this rule firing 100+ times.

Replacement: none. Exfiltration detection belongs in DNS and network telemetry, not in bugreport text scanning. The real question — "is this app sending unusual volumes of encoded data off-device?" — is answered by DNS event analysis, not by counting base64 characters in a forensic log.

Tombstone commit message: *"removed: base64 length heuristic was asking the wrong question. Bugreports contain protobuf dumps, keys, and serialized state as base64 by design. Exfiltration detection belongs in DNS/network telemetry (DnsEvent evaluation against domain IOC feeds), not in bugreport text scanning. Produced 100+ HIGH false positives per clean-device report."*

**3. C2 beacon regex** (lines 37–41, 160–169).

Current: `Regex("HTTP.*POST.*every\\s+[0-9]+", IGNORE_CASE)` emitting CRITICAL `"C2Beacon"` findings.

Problem: matches developer comments, documentation strings, and test output captured in tombstones. No validation that an actual network request is being described.

Replacement: none. Real C2 detection comes from DNS events evaluated against domain IOC feeds (`androdr-003` DNS domain IOC). The regex was a proxy for DNS telemetry that already exists.

Tombstone commit message: *"removed: 'HTTP POST every N' regex was a proxy for real C2 detection. Actual C2 signal comes from DNS events evaluated against domain IOC feeds (androdr-003). The regex produced CRITICAL false positives on code comments and documentation embedded in tombstones."*

### Ported to rules (2)

Both heuristics have genuine signal but their current Kotlin implementations are untuned. They become proper rules with new telemetry types.

**4. Crash loop** (lines 44–47, 195–207).

Current: counts lines matching `Regex("Process .* has died", IGNORE_CASE)` and fires MEDIUM if count ≥ 3.

New telemetry type: `TombstoneEvent`

```kotlin
data class TombstoneEvent(
    val processName: String,
    val packageName: String?,
    val signalNumber: Int?,     // e.g. 11 for SIGSEGV
    val abortMessage: String?,  // null for non-abort crashes
    val crashTimestamp: Long,   // epoch millis from tombstone header
    val source: TelemetrySource,
    val capturedAt: Long,
)
```

Parsed by a dedicated `TombstoneParser` that reads the bugreport's tombstone section and constructs one record per tombstone file.

New rule: `sigma_androdr_0XX_crash_loop_anti_forensics.yml`. Category: `incident` (crash loops can indicate failed exploitation attempts or anti-analysis). Level: MEDIUM. Structure: correlation rule with a count-based threshold (e.g., ≥3 tombstones for the same package within 1 hour), threshold expressed in YAML.

**5. Persistent wakelock** (lines 49–53, 209–226).

Current: counts lines matching `Regex("WakeLock.*acquired", IGNORE_CASE)` and fires MEDIUM if density > 0.2 acquisitions per line over the matching span.

New telemetry type: `WakelockAcquisition`

```kotlin
data class WakelockAcquisition(
    val packageName: String,
    val wakelockTag: String,
    val acquiredAt: Long,
    val durationMillis: Long?,
    val source: TelemetrySource,
    val capturedAt: Long,
)
```

Parsed by a dedicated `WakelockParser` reading the bugreport's power section (typically `dumpsys power` output and `batterystats --history`).

New rule: `sigma_androdr_0XX_persistent_wakelock.yml`. Category: `incident` (always-on wakelock behavior is stalkerware-shaped). Level: LOW. **Status: disabled-by-default** (`status: experimental` in the rule YAML, with a disabled flag read by the rule loader). Reason: the density threshold was arbitrary in the legacy implementation and needs real-device UAT data to calibrate. Shipping it enabled would immediately reintroduce the false-positive problem. Tracked for tuning in issue #87.

Rationale for shipping disabled rather than deleting: the telemetry collection ships enabled, so data is gathered for threshold calibration. The rule evaluation is what's disabled. This gives us the data we need to tune the rule without alarming users in the interim.

### File deletion

After the port, `LegacyScanModule.kt` is deleted. The `BugReportAnalyzer` dispatch registry no longer references it. No compatibility shim, no transitional alias — the file is gone and the git history carries the tombstone commits.

---

## 9. FileArtifactScanner IOC Migration

### Current state

`app/src/main/java/com/androdr/scanner/FileArtifactScanner.kt:32-38`:

```kotlin
private val knownArtifactPaths: List<String> by lazy {
    val extStorage = Environment.getExternalStorageDirectory().absolutePath
    listOf(
        "/data/local/tmp/.raptor",
        "/data/local/tmp/.stat",
        "/data/local/tmp/.mobilesoftwareupdate",
        "$extStorage/.hidden_config",
        "$extStorage/Android/data/.system_update"
    )
}
```

Five hardcoded spyware artifact paths sourced from MVT and Citizen Lab research. The rule that evaluates this telemetry (`androdr-020 Known spyware file artifact`) is already rule-driven; only the IOC list itself is stuck in Kotlin.

### Target state

New resource file: `app/src/main/res/raw/known_spyware_artifacts.yml`.

```yaml
version: "2026-04-09"
description: "Known spyware file system artifacts. Paths associated with mercenary spyware, stalkerware, and forensic tools. Evaluated by androdr-020."
sources:
  - mvt
  - citizen-lab
  - amnesty-international
last_reviewed: "2026-04-09"

artifacts:
  - path: "/data/local/tmp/.raptor"
    family: "pegasus"
    source: "citizen-lab"
    first_observed: "2021-07-18"
  - path: "/data/local/tmp/.stat"
    family: "pegasus"
    source: "mvt"
  - path: "/data/local/tmp/.mobilesoftwareupdate"
    family: "pegasus"
    source: "mvt"
  - path: "{ext_storage}/.hidden_config"
    family: "generic_stalkerware"
    source: "androdr-research"
  - path: "{ext_storage}/Android/data/.system_update"
    family: "generic_stalkerware"
    source: "androdr-research"
```

Path template `{ext_storage}` is resolved at runtime to the external storage directory (preserving current behavior).

### Resolver

`KnownSpywareArtifactsResolver` (new class, patterned on `OemPrefixResolver`): loads and parses the YAML, caches the resolved path list, exposes `fun paths(): List<String>`. Injected into `FileArtifactScanner` via Hilt.

`FileArtifactScanner` changes: replace the hardcoded `knownArtifactPaths` with a call to the resolver. No telemetry or rule changes — `androdr-020` continues to evaluate `FileArtifactTelemetry` with no schema change.

### Future compatibility with the `update-rules` agents

The resource file format matches the style used by the existing `update-rules-ingest-*` agents (Citizen Lab, stalkerware-indicators, AmnestyTech). Once the refactor ships, future iterations of the `update-rules` pipeline can append to `known_spyware_artifacts.yml` automatically when new paths are published in threat intel feeds, without any code changes.

---

## 10. Timeline UI and Export Separation

The current timeline UI conflates telemetry (observational events) with findings (rule-produced matches), rendering both in the same chronological list with shared severity coloring. This is a direct violation of principle P1 — it effectively stamps severity onto raw telemetry by proxy. The refactor fixes this.

### Core distinction: display vs. storage vs. export

**Storage is always separated.** Telemetry rows and finding rows live in distinct Room tables (already required by §3). This is non-negotiable — the rest of the architecture depends on it.

**Export is always separated.** The exported bundle contains distinct Telemetry and Findings sections. An analyst can discard the Findings section and re-run their own rules against telemetry alone. This is the property that makes analyst portability meaningful.

**Display may merge** — telemetry and findings may be rendered together in a single chronological view *for user convenience*, as long as the visual treatment makes them clearly distinct. This is a UX choice, not an architectural one. The UI joins the two storage layers at render time for display; the join happens in-memory and does not affect storage or export.

### Target display treatment

The timeline screen renders a unified chronological list where:

- **Telemetry rows** are rendered as neutral entries: no severity color, no severity badge, just a timestamp, source tag, and description. Visual weight is low. Examples: "App X opened at 14:32", "Accessibility service Y enabled at 14:35", "DNS query to example.com at 14:36".
- **Finding rows** are rendered as visually distinct entries: explicit severity badge (CRITICAL / HIGH / MEDIUM / LOW), category indicator (`incident` / `device_posture`), finding title, and a direct reference to the rule that fired (`ruleId` visible on tap/expand). Visual weight is high. Examples: "[HIGH · incident · androdr-012] Accessibility service abuse detected on com.example.stalker".
- **Relationship rendering.** When a finding references specific telemetry rows as evidence, the telemetry rows are visually linked to the finding (indentation, colored side-rail, or similar treatment). A user looking at a finding can see the exact telemetry that triggered it without leaving the timeline. A user looking at a telemetry row can see whether any finding references it.

The **ViewModel** (`TimelineViewModel`) queries the telemetry table and the findings table separately, joins them by timestamp for display order, and emits a unified `TimelineRow` sealed type to the screen:

```kotlin
sealed class TimelineRow {
    abstract val timestamp: Long

    data class TelemetryRow(
        override val timestamp: Long,
        val telemetryType: String,
        val source: TelemetrySource,
        val description: String,
        val referencedByFindingIds: List<String>,  // for visual linking
    ) : TimelineRow()

    data class FindingRow(
        override val timestamp: Long,
        val finding: Finding,
        val evidenceTelemetryIds: List<String>,  // for visual linking
    ) : TimelineRow()
}
```

The screen's composable renders `TelemetryRow` and `FindingRow` with different layouts. There is no shared "severity" field on `TimelineRow` — if you see a severity badge, it's because you're looking at a `FindingRow`. A `TelemetryRow` cannot render a severity by construction.

### Filter controls

The timeline currently has collapsible filter controls (see `TimelineScreen.kt`). Post-refactor, these gain a new toggle:

**"Hide informational telemetry"** — when enabled, `TelemetryRow` entries that are not referenced by any `FindingRow` are hidden. `TelemetryRow` entries that *are* referenced by a finding (their `referencedByFindingIds` list is non-empty) remain visible regardless, so the finding's evidence is never orphaned. `FindingRow` entries are always visible.

Default state: **OFF**. Full chronology is shown by default to preserve the current user experience. Power users enable the toggle for a less noisy view focused on rule-relevant events.

Implementation: the filter is a simple predicate on `TelemetryRow.referencedByFindingIds.isNotEmpty()`, evaluated in the ViewModel so the filter state is preserved across recompositions.

Other existing filters (date range, source, category, etc.) are unaffected. They continue to filter the unified stream.

### Export options

The export flow (`ReportExporter`) gains three explicit options presented to the user at export time:

1. **Telemetry only.** Writes a bundle containing only the Telemetry section — all telemetry rows, grouped by type, with source and capture timestamps preserved. Intended for analyst handoff: the recipient can run their own rules against this bundle and produce their own findings.
2. **Findings only.** Writes a bundle containing only the Findings section — all findings produced by the current ruleset. Intended for quick sharing of "what did the app find on this device" without exposing the underlying raw data.
3. **Both (default).** Writes a bundle containing both sections, clearly labeled. This is the current default behavior and remains the default.

The three options are presented as a simple radio-button selection in the export dialog. No per-type or per-date-range filtering in this refactor — if analysts ask for finer granularity later, it becomes a follow-up.

The export format version field (existing header) is bumped to reflect the new bundle structure, so external tooling can detect the new shape.

### Deduplication across scans — known issue, deferred

The current model stores every scan's telemetry fresh, and the timeline shows the union of all scans. State telemetry (e.g., "App X is installed") observed across N scans produces N rows in the timeline and the export, even though the underlying fact is the same.

This is a real problem but it's a **separate architectural decision** — it requires classifying telemetry types as STATE vs. EVENT, adding upsert semantics for state, and designing a change-log model for state transitions. Bundling it with the unified telemetry/findings refactor would roughly double the PR size and conflate two distinct design decisions.

**Deferred to #88.** The layered architecture defined in this refactor is the prerequisite for dedup (dedup on a mixed-severity pile is pointless), so the ordering is forced regardless. Analysts importing bundles before #88 ships will see N× state rows and can deduplicate at their end — annoying but not broken.

---

## 11. Testing Strategy

### Unit tests — new

**Rule schema validation** (extends `SigmaRuleParserTest`):
- Every bundled rule file parses successfully.
- Every bundled rule declares a `category:` field. A synthetic rule missing `category:` produces a parse error with a clear message.
- A synthetic rule with `category: some_invalid_value` produces a parse error listing the valid options.

**Severity cap enforcement** (extends `SigmaRuleEngineTest`):
- Enumerate all bundled rules tagged `category: device_posture`. For each, assert declared `level:` ≤ MEDIUM. Any violation fails CI.
- Synthetic `device_posture` rule declaring `level: critical` with matching telemetry: assert the produced `Finding.level == MEDIUM` (engine clamps).
- Synthetic `incident` rule declaring `level: critical` with matching telemetry: assert the produced `Finding.level == CRITICAL` (no clamp).

**Correlation category propagation** (extends `SigmaRuleEngineCorrelationTest`):
- Two synthetic member rules, one `incident` + one `device_posture`. Correlation rule references both. Assert the produced correlation finding has `category == INCIDENT` and can declare severity up to CRITICAL.
- Two synthetic member rules, both `device_posture`. Correlation rule references both. Assert the produced correlation finding has `category == DEVICE_POSTURE` and is capped at MEDIUM regardless of declared severity.

**Telemetry source field invariant** (new test file `TelemetrySourceInvariantTest`):
- For each runtime scanner, a test that invokes the scanner against a mock and asserts every emitted telemetry row has `source == LIVE_SCAN`.
- For `BugReportAnalyzer`, a test against a recorded bugreport fixture asserting every emitted telemetry row has `source == BUGREPORT_IMPORT`.

**Bugreport parser round-trip** (new test file `BugReportParserTest`):
- Against a recorded clean-device bugreport fixture, assert the parser produces the expected number of telemetry rows per type and no findings (pure telemetry layer).
- Against a recorded bugreport fixture with known spyware indicators, assert the produced telemetry rows include the expected entries.

**FileArtifactScanner resolver** (extends existing FileArtifactScanner tests):
- Loads `known_spyware_artifacts.yml`, resolves path templates, and asserts the resulting list matches the current hardcoded behavior.

### Unit tests — updated

- Existing SIGMA rule tests: unchanged in behavior but must be re-verified after the YAML files get their new `category:` field.
- Existing `ReportCsvWriter` tests: must pass with unified Finding output. CSV column names preserved.
- Existing `BugReportAnalyzerTest`: rewritten to assert telemetry output rather than finding output.

### Regression tests

- **Tester-provided bugreport as acceptance criterion.** The bugreport file the tester provided is checked into the test fixtures as a redacted version (see R7 for redaction strategy). A regression test runs the full pipeline (parse → telemetry → rule engine → findings) against this fixture and asserts:
  - Zero findings for the graphite keyword (the heuristic is deleted).
  - Zero findings for base64 blobs (the heuristic is deleted).
  - Zero findings for the C2 beacon regex (the heuristic is deleted).
  - Zero HIGH or CRITICAL findings on `com.unisoc.*`, `com.sprd.*`, `com.go.browser`, `com.xiaomi.midrop` packages (they're classified as OEM/system via the expanded `known_oem_prefixes.yml`).
  - Any findings that do fire have `ruleId` set and are traceable to a specific SIGMA rule file.

- **Existing runtime scan regression suite:** unchanged. The runtime scanners don't change behavior (they already route through the rule engine); the only code change is adding explicit `source = LIVE_SCAN` to their telemetry constructors.

### Manual verification

Before merging:

1. Install debug build on a clean test device (not the tester's device). Run a full scan. Compare pre/post refactor findings — should produce an equivalent (or cleaner) set of findings with the same severity distribution for non-posture rules and strictly lower severities for posture rules.
2. Import the tester-provided bugreport via the import flow. Compare pre/post refactor results — should show dramatic reduction in CRITICAL/HIGH noise, zero findings on the OEM system packages, and any remaining findings traceable to actual SIGMA rules.
3. Run the export flow on both devices and verify the CSV / plaintext reports are well-formed and contain the two sections (Telemetry, Findings) clearly separated.

---

## 12. Out of Scope / Follow-ups

The following items were identified during the audit but are explicitly deferred from this refactor to keep its scope manageable and its diff focused on the bugreport pipeline unification.

- **DeviceAuditor bootloader string heuristic** (`DeviceAuditor.kt:163`). Substring match `bootloader.contains("unlocked") || contains("-u-")`. Minor policy violation but structurally isolated from the refactor's theme. Deferred to **#86** — replace with standardized `ro.boot.verifiedbootstate` check. No impact on this PR.

- **Wakelock rule UAT tuning.** The new `sigma_androdr_0XX_persistent_wakelock.yml` rule ships disabled-by-default because its density threshold requires real-device calibration across device classes. Deferred to **#87** — collect baselines, set threshold, re-enable. The rule's telemetry collection ships enabled so the data is available for tuning.

- **MVT-parity docs archival.** The two MVT-parity docs (plan + design spec) are marked SUPERSEDED in the pre-refactor cleanup commit but their bodies are left intact. After this refactor merges, they get moved to `docs/superpowers/archive/` alongside the three other archived docs. Deferred to **#85** — post-merge cleanup.

- **Telemetry deduplication across scans.** Current model stores every scan's telemetry fresh, so state telemetry (e.g., "App X is installed") observed across N scans produces N timeline rows and N export rows. Proper fix requires STATE vs. EVENT classification, upsert semantics for state, and a change-log model. Substantial enough to deserve its own brainstorm/spec cycle. Deferred to **#88** — dedup becomes the next architectural work item after this refactor merges. The layered architecture in this spec is a prerequisite (dedup on a mixed-severity pile is pointless), so the ordering is forced regardless.

- **Retrofitting runtime scanners to parallel bugreport telemetry sources.** In principle, runtime scanners could also become "telemetry producers" in the same way bugreport modules do, with `BugReportAnalyzer`-style orchestration. In practice they already work this way; the refactor just makes them set `source = LIVE_SCAN` explicitly. No deeper retrofit needed.

- **Correlation rules for the new telemetry types.** `PackageInstallHistoryEntry`, `BatteryDailyEvent`, `TombstoneEvent`, `WakelockAcquisition`, `PlatformCompatChange`, `DatabasePathObservation`, `SystemPropertySnapshot` are all new telemetry types. This refactor authors the *atomic* rules needed to replace the legacy hardcoded detections (crash loop, wakelock, package uninstall with IOC, version downgrade, ChangeId anti-analysis, sensitive DB path access). Authoring richer *correlation* rules over these types (e.g., "package uninstalled within N minutes of first contacting a known-bad domain") is follow-up work, tracked per-rule as needed.

- **Export format versioning.** The refactor changes the exported bundle structure (Telemetry / Findings sections, new telemetry types). Consumers of the export format will see the new shape on first refactor-built export. An export format version field exists in the current export header; bump it as part of this PR. Full schema documentation for external analyst tooling is follow-up work — this PR only needs to ensure the format is well-defined and the version is bumped.

- **Runtime scanner auto-derivation of existing category assignments from `display.category`.** The runtime scanners' bundled rules currently populate `display.category` strings; the refactor adds the new `category:` policy field. For the 24 bundled rules, assignments are explicit (see §6). No auto-derivation logic is needed — the assignments are baked into the rule files.

---

## 13. Risks

### R1. Atomic PR size

**Risk:** the refactor touches ~15–25 files across `scanner/bugreport/`, `sigma/`, `data/model/`, `reporting/`, and `res/raw/`. Review fatigue may mask subtle errors. A late-found issue could force substantial rework.

**Mitigation:**
- Commit structure within the branch: even though the PR is atomic, commits on the branch follow a logical progression (telemetry types first, then rule engine changes, then bugreport module ports, then LegacyScanModule deletion, then test additions) so reviewers can walk the history.
- Pre-merge manual verification on both a clean device and the tester-provided bugreport (§11).
- The spec is committed first so reviewers can validate the design before reading implementation.

### R2. Downstream consumer migration

**Risk:** `BugReportFinding` is consumed by `ReportExporter`, `ReportFormatter`, `ReportCsvWriter`, `HistoryViewModel`, `DashboardViewModel`, and possibly others. Missing a consumer means a compile failure (caught by build) or, worse, a runtime crash in an unrelated UI path (caught only by manual testing).

**Mitigation:**
- Implementation step 1 in the plan: `grep -r BugReportFinding app/` to enumerate every consumer before deleting the type. Each consumer is migrated and verified before proceeding.
- Unit tests for `ReportCsvWriter` catch schema drift.
- Manual verification of the History screen, Dashboard screen, and Export flow on a test device.

### R3. Rule category mis-classification

**Risk:** a rule is tagged `device_posture` when it should be `incident` (or vice versa), leading to a silent severity downgrade or a weakening of the cap policy.

**Mitigation:**
- The 24 existing rules are explicitly categorized in §6 of this spec. The list is the authoritative source during implementation.
- Build-time test enforces the device_posture → MEDIUM cap; mis-classifying an incident rule as device_posture would silently downgrade its findings, but this is reversible post-merge (change the rule YAML).
- Mis-classifying a posture rule as incident is the dangerous direction (could allow a posture finding to go CRITICAL). The categorization principle in §6 is specific: "category reflects nature, not severity. A condition is posture; an event is incident." The 24-rule table eliminates ambiguity for the initial set.

### R4. Correlation propagation edge cases

**Risk:** the "any incident member → incident correlation" rule is simple but correlation rules can reference complex conditions (timespan, count, ordering). An edge case — e.g., a correlation that fires only when a posture condition persists long enough to become incident-like — might surprise.

**Mitigation:**
- The propagation rule is explicit in the engine, not inferred from member severities or detection semantics. If you want an incident-category correlation, you reference at least one incident member rule.
- Propagation unit test in §11 covers the incident+posture and posture-only cases.
- Any correlation rule author who wants non-default propagation can break the rule into an intermediate incident-category rule that the correlation then references. (The spec doesn't add a per-rule override field; that complexity isn't needed for the initial set.)

### R5. CSV export backward compatibility

**Risk:** external tools consume AndroDR's CSV export. The refactor changes how findings are shaped internally; if CSV column names or semantics drift, downstream tooling breaks.

**Mitigation:**
- The refactor preserves existing CSV column names. Bugreport-sourced findings populate the same columns runtime findings already use.
- New telemetry types (PackageInstallHistory, etc.) may introduce new columns, but only as additions — not removals or renames.
- Export format version field is bumped so tooling can detect the new shape.

### R6. Timeline UI behavioral change

**Risk:** the timeline UI is a visible user-facing feature. Separating telemetry rows from finding rows visually, adding the "hide informational telemetry" filter, and re-structuring the ViewModel to emit a `TimelineRow` sealed type is a behavioral change users will notice immediately. If the new treatment is confusing or drops a visual cue users relied on, the refactor degrades the UX even though it corrects the architecture.

**Mitigation:**
- The "hide informational telemetry" toggle defaults OFF, so existing users see the full chronology by default and can opt in.
- Visual distinction between telemetry and finding rows is additive (neutral vs. badged), not destructive — users who ignore the badges still see the same rows they saw before.
- The existing filter controls (date range, source, category) are unchanged.
- Manual pre-merge verification includes scrolling the timeline on both a clean device and a device with active findings to confirm both visual treatments render as expected.
- If user feedback post-merge identifies a specific visual regression, the fix is a UI-only patch (not an architectural revert).

### R7. Test fixture bugreport redaction

**Risk:** the tester-provided bugreport becomes a test fixture. If not properly redacted, it leaks device-identifying information (IMEI, phone number, installed apps, device model, SoC details, vendor build fingerprints) into the public repository.

**Mitigation:**
- Before committing the fixture, run it through a redaction pass: replace IMEI/IMSI/phone number / account email / serial numbers / IP addresses / MAC addresses with placeholder values. Preserve structural elements (line counts, section boundaries, parse-relevant tokens) so the fixture still exercises the parser.
- Alternative if full redaction proves infeasible: store a distilled version of the fixture containing only the specific sections relevant to the regression test (dumpsys entries triggering the deleted heuristics, the Unisoc package list), rather than the full bugreport.
- Decision on redaction strategy (full vs. distilled) happens during implementation, not spec time.

---

**End of spec.**

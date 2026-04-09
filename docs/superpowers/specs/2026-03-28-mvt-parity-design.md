# MVT-Parity Forensic Analysis — Design Spec

> ## ⚠️ SUPERSEDED — HISTORICAL RECORD ONLY
>
> This spec describes a `ModuleResult` shape with a `findings: List<BugReportFinding>` field and bugreport modules producing findings directly with inline severity. That architecture has been **superseded** by the unified telemetry/findings refactor (tracking issue **#84**).
>
> **Do not use this spec's architecture diagram or `ModuleResult` interface for new work.** Post-refactor:
> - Bugreport modules emit canonical telemetry types only — no findings, no severity
> - Telemetry types are source-agnostic (shared with runtime scanners via a `source: TelemetrySource` field)
> - Findings are produced exclusively by `SigmaRuleEngine` / `SigmaCorrelationEngine` from telemetry, with severity sourced from rule `level:` and `category:` metadata
> - `BugReportFinding` as a type no longer exists
> - Device posture findings are capped at MEDIUM by the engine
>
> **Authoritative architecture:** `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`
>
> This document is retained for historical context (it describes what was actually shipped in late March 2026) and is scheduled for archival to `docs/superpowers/archive/` once #84 merges (see **#85**).

## Goal

Port MVT's (Mobile Verification Toolkit) 13 structured bugreport analysis modules to Kotlin, and implement runtime API equivalents for the highest-value checks. This gives AndroDR MVT-grade forensic analysis entirely on-device.

## Motivation

- AndroDR's privacy page claims bug report analysis is available, but the current `BugReportAnalyzer` does a single-pass regex scan with 6 patterns — far below MVT's 13 structured modules
- MVT cannot run on-device (it's a PC tool using ADB to connect to a phone); a Kotlin port is the only viable path
- The portable detection logic is ~1000-2000 lines of text parsing — small scope
- AndroDR already has 80% of the infrastructure (IOC matching, SIGMA engine, package scanning)
- Three T2 checks (AppOps, Receivers, Accessibility) can also run as **runtime scanners** via Android APIs, making them available during regular scans without a bugreport

## Non-Goals

- Running Python/MVT on-device (infeasible: native dependency blockers, architectural mismatch)
- ADB-based checks (MVT's ADB modules connect from PC; on-device we use Android APIs directly)
- iOS support (MVT also covers iOS; out of scope)
- Backup file analysis (MVT parses Android backup .ab files; separate feature if needed)

---

## Architecture

### Two Analysis Paths, Shared Detection Logic

```
                    ┌─────────────────────────────────┐
                    │        Bug Report ZIP            │
                    └──────────────┬──────────────────┘
                                   │
                    ┌──────────────▼──────────────────┐
                    │     DumpsysSectionParser         │
                    │  (extracts DUMP OF SERVICE X:)   │
                    └──────────────┬──────────────────┘
                                   │
              ┌────────┬───────────┼───────────┬────────┐
              ▼        ▼           ▼           ▼        ▼
         AppOps   Receivers   Accessibility  Battery  Others
         Module    Module       Module       Module   ...
              │        │           │           │        │
              └────────┴───────────┼───────────┴────────┘
                                   │
                    ┌──────────────▼──────────────────┐
                    │   List<BugReportFinding>         │
                    │   + List<TimelineEvent>          │
                    └─────────────────────────────────┘


    ┌─────────────────────────────────────────────────────┐
    │              Runtime Scanners (live)                 │
    │  AppOpsScanner, ReceiverScanner, AccessibilityScanner│
    │         ↓ produce Telemetry objects ↓               │
    │              SigmaRuleEngine.evaluate()              │
    └─────────────────────────────────────────────────────┘
```

Bugreport modules parse dumpsys text. Runtime scanners query Android APIs. Both produce the same telemetry models evaluated by the same SIGMA rules. No duplicated detection logic.

### BugReportAnalyzer Refactoring

The current monolithic single-pass scanner becomes a module dispatcher:

**Before:**
```
analyze(uri) → open ZIP → for each text entry → analyzeTextEntry() → all 6 regexes
```

**After:**
```
analyze(uri) → open ZIP
  → identify dumpstate entry
  → DumpsysSectionParser.extractSections(dumpstate, allNeededServices)
  → for each module:
       module.analyze(sections[module.targetSection], iocResolver)
  → LegacyScanModule runs on raw logcat/bugreport entries (unchanged behavior)
  → flatten all ModuleResult.findings into List<BugReportFinding>
  → collect all ModuleResult.timeline into List<TimelineEvent>
```

The existing 6 regex checks (spyware keywords, base64 blobs, C2 beacons, crash loops, wakelocks, package IOC matching) move to `LegacyScanModule` — same logic, no behavior change. These checks scan raw text broadly and don't target a specific dumpsys section.

The public API (`analyze(uri): List<BugReportFinding>`) stays the same. `BugReportViewModel` and `BugReportScreen` remain unchanged.

---

## Module Interface & Data Models

### BugreportModule Interface

```kotlin
interface BugreportModule {
    /** Which dumpsys service section(s) this module needs, or null for raw entries */
    val targetSections: List<String>?

    /**
     * Analyze a dumpsys section (passed as String for section-targeted modules)
     * or raw ZIP entries (passed via analyzeRaw for LegacyScanModule/TombstoneModule).
     * Modules override whichever method matches their targetSections contract.
     */
    suspend fun analyze(
        sectionText: String,
        iocResolver: IocResolver
    ): ModuleResult = ModuleResult(emptyList(), emptyList())

    /**
     * Analyze raw ZIP entries (for modules with targetSections == null).
     * Default no-op; only LegacyScanModule and TombstoneModule override.
     */
    suspend fun analyzeRaw(
        entries: Sequence<Pair<String, InputStream>>,
        iocResolver: IocResolver
    ): ModuleResult = ModuleResult(emptyList(), emptyList())
}

data class ModuleResult(
    val findings: List<BugReportFinding>,
    val timeline: List<TimelineEvent>
)

data class TimelineEvent(
    val timestamp: Long,        // epoch millis, or -1 if undetermined
    val source: String,         // module name e.g. "appops", "battery_daily"
    val category: String,       // e.g. "permission_use", "package_install"
    val description: String,
    val severity: String        // INFO, MEDIUM, HIGH, CRITICAL
)
```

### Module Inventory

| Module | `targetSections` | Key Output |
|--------|-----------------|------------|
| `AppOpsModule` | `["appops"]` | Per-package permission usage with timestamps |
| `ReceiverModule` | `["package"]` | SMS/call broadcast receivers by package |
| `AccessibilityModule` | `["accessibility"]` | Enabled accessibility services |
| `PackageDetailModule` | `["package"]` | Root packages, dangerous permission count, version history |
| `BatteryDailyModule` | `["batterystats"]` | Install/uninstall/downgrade events with dates |
| `ActivityModule` | `["package"]` | Registered intent handlers |
| `DbInfoModule` | `["dbinfo"]` | Database operations by package |
| `AdbStateModule` | `["adb"]` | Trusted ADB public keys |
| `PlatformCompatModule` | `["platform_compat"]` | Compatibility overrides |
| `TombstoneModule` | `null` (raw ZIP `*/tombstone_*`) | Crash data with UID/SELinux context |
| `LegacyScanModule` | `null` (raw text entries) | Existing 6 regex checks, unchanged |

`ReceiverModule`, `ActivityModule`, and `PackageDetailModule` all target the `"package"` section but parse different subsections within it (Receiver Resolver Table, Activity Resolver Table, Packages list). The section is extracted once; modules receive the same text.

### Runtime Telemetry Models

```kotlin
data class AppOpsTelemetry(
    val packageName: String,
    val operation: String,          // e.g. "CAMERA", "RECORD_AUDIO"
    val lastAccessTime: Long,
    val lastRejectTime: Long,
    val accessCount: Int,
    val isSystemApp: Boolean
) : TelemetryRecord

data class ReceiverTelemetry(
    val packageName: String,
    val intentAction: String,       // e.g. "android.provider.Telephony.SMS_RECEIVED"
    val componentName: String,
    val isSystemApp: Boolean
) : TelemetryRecord

data class AccessibilityTelemetry(
    val packageName: String,
    val serviceName: String,
    val isSystemApp: Boolean,
    val isEnabled: Boolean
) : TelemetryRecord
```

All implement `toFieldMap()` for SIGMA rule evaluation, consistent with existing telemetry models.

---

## DumpsysSectionParser

Streaming utility that extracts `DUMP OF SERVICE <name>:` sections from dumpstate files without loading the entire file into memory.

```kotlin
class DumpsysSectionParser {
    fun extractSection(stream: InputStream, serviceName: String): String?
    fun extractSections(stream: InputStream, serviceNames: Set<String>): Map<String, String>
    fun extractSystemProperties(stream: InputStream): String?
    fun iterateZipEntries(zipStream: ZipInputStream, namePattern: Regex): Sequence<Pair<String, InputStream>>
}
```

**Section delimiters:** Both `---------- SERVICE <name> ----------` and `DUMP OF SERVICE <name>:` formats are handled (varies across Android versions).

**Single-pass multi-section extraction:** `extractSections()` reads the stream once and captures all requested sections simultaneously. The orchestrator calls this once with all needed service names, then distributes sections to modules.

**Memory budget:** Each extracted section is held as a `String`. The `package` section is the largest (~2-10MB on a typical device). Acceptable for on-device analysis since sections are processed one at a time.

---

## Runtime Scanners & SIGMA Integration

### New Scanners

```kotlin
@Singleton
class AppOpsScanner @Inject constructor(@ApplicationContext private val context: Context) {
    suspend fun collectTelemetry(): List<AppOpsTelemetry>
    // Uses AppOpsManager.getPackagesForOps()
    // Filters to dangerous ops: CAMERA, RECORD_AUDIO, READ_SMS, etc.
}

@Singleton
class ReceiverAuditScanner @Inject constructor(@ApplicationContext private val context: Context) {
    suspend fun collectTelemetry(): List<ReceiverTelemetry>
    // Uses PackageManager.queryBroadcastReceivers() for 5 sensitive intents
    // Filters out system apps
}

@Singleton
class AccessibilityAuditScanner @Inject constructor(@ApplicationContext private val context: Context) {
    suspend fun collectTelemetry(): List<AccessibilityTelemetry>
    // Uses AccessibilityManager.getEnabledAccessibilityServiceList()
}
```

### ScanOrchestrator Changes

Phase 1 (parallel telemetry collection) adds three more `async` calls alongside existing scanners. Phase 2 (SIGMA evaluation) adds three new evaluation calls:

```
existing:  evaluateApps(), evaluateDevice(), evaluateProcesses(), evaluateFiles()
new:       evaluateAppOps(), evaluateReceivers(), evaluateAccessibility()
```

### Example SIGMA Rules

```yaml
# androdr-060: Non-system app with enabled accessibility service
title: Non-system app with active accessibility service
service: accessibility_audit
detection:
  selection:
    is_system_app: false
    is_enabled: true
level: high

# androdr-061: App registered for SMS_RECEIVED broadcast
title: App intercepting incoming SMS
service: receiver_audit
detection:
  selection:
    intent_action: "android.provider.Telephony.SMS_RECEIVED"
    is_system_app: false
level: critical

# androdr-062: App accessed microphone recently (non-system)
title: Recent microphone access by non-system app
service: appops_audit
detection:
  selection:
    operation: "RECORD_AUDIO"
    is_system_app: false
    last_access_time|gte: 86400000
level: high
```

### API Level Considerations

- `AppOpsManager.getPackagesForOps()` — API 19+, useful results require API 26+. Returns empty list on older devices.
- `PackageManager.queryBroadcastReceivers()` — all API levels. No restrictions.
- `AccessibilityManager.getEnabledAccessibilityServiceList()` — API 14+. No restrictions.

No new permissions required.

---

## Hilt Wiring

Modules are injected as a set into `BugReportAnalyzer`:

```kotlin
@Module
@InstallIn(SingletonComponent::class)
abstract class BugreportModuleBindings {
    @Binds @IntoSet abstract fun appOps(m: AppOpsModule): BugreportModule
    @Binds @IntoSet abstract fun receivers(m: ReceiverModule): BugreportModule
    @Binds @IntoSet abstract fun accessibility(m: AccessibilityModule): BugreportModule
    @Binds @IntoSet abstract fun legacy(m: LegacyScanModule): BugreportModule
    // ... more modules added as implemented
}
```

Adding a new module: write the class, add one `@Binds` line. Open for extension.

---

## File Layout

```
app/src/main/java/com/androdr/
├── scanner/
│   ├── BugReportAnalyzer.kt          ← refactored to orchestrator
│   ├── ScanOrchestrator.kt           ← adds 3 new scanner calls
│   ├── AppOpsScanner.kt              ← NEW runtime scanner
│   ├── ReceiverAuditScanner.kt       ← NEW runtime scanner
│   ├── AccessibilityAuditScanner.kt  ← NEW runtime scanner
│   └── bugreport/
│       ├── BugreportModule.kt        ← interface + ModuleResult + TimelineEvent
│       ├── DumpsysSectionParser.kt   ← section extraction utility
│       ├── LegacyScanModule.kt       ← extracted from current BugReportAnalyzer
│       ├── AppOpsModule.kt
│       ├── ReceiverModule.kt
│       ├── AccessibilityModule.kt
│       ├── PackageDetailModule.kt
│       ├── BatteryDailyModule.kt
│       ├── ActivityModule.kt
│       ├── DbInfoModule.kt
│       ├── AdbStateModule.kt
│       ├── PlatformCompatModule.kt
│       └── TombstoneModule.kt
├── data/model/
│   ├── AppOpsTelemetry.kt            ← NEW
│   ├── ReceiverTelemetry.kt          ← NEW
│   ├── AccessibilityTelemetry.kt     ← NEW
│   └── TimelineEvent.kt              ← NEW
```

---

## Scope Boundaries

**In scope:**
- Bugreport module interface + 11 modules (including LegacyScanModule)
- DumpsysSectionParser utility
- 3 runtime scanners + ScanOrchestrator integration
- New SIGMA rules for runtime telemetry types
- Unit tests for all modules and scanners
- Dashboard card entry point (#31)

**Not in scope:**
- UI changes beyond Dashboard card — `BugReportScreen` already works
- New Android permissions — all runtime APIs are permission-free
- New Room tables — timeline events live in memory during analysis
- Changes to SIGMA rule engine — it already supports arbitrary service types
- Changes to IOC infrastructure — modules use existing `IocResolver`
- Timeline UI (#41) — data model designed now, UI is a separate issue

---

## Testing Strategy

- Each bugreport module: unit tests with sample dumpsys section text (same pattern as `BugReportAnalyzerTest.kt`)
- Each runtime scanner: unit tests with mocked Android APIs (MockK)
- SIGMA rules for new telemetry types: rule evaluation tests
- `DumpsysSectionParser`: tests with representative dumpstate fragments covering both delimiter formats
- No instrumented/device tests — all parsing is pure Kotlin string manipulation

---

## Priority & Delivery Order

Scored on: detection value × user impact × publishability.

### Tier 1 — Foundation
1. #31 — Dashboard UI entry point
2. #32 — DumpsysSectionParser + BugreportModule interface + LegacyScanModule extraction

### Tier 2 — High-Value Detection
3. #33 — AppOpsModule + AppOpsScanner + SIGMA rules
4. #34 — ReceiverModule + ReceiverAuditScanner + SIGMA rules
5. #35 — AccessibilityModule + AccessibilityAuditScanner + SIGMA rules

### Tier 3 — Moderate Value
6. #36 — BatteryDailyModule
7. #37 — Full STIX2 indicator pattern support
8. #38 — ActivityModule

### Tier 4 — Specialist / Forensic
9. #39 — DbInfoModule
10. #40 — AdbStateModule + PlatformCompatModule
11. #41 — Cross-module forensic timeline view

---

## Reference

- MVT source: https://github.com/mvt-project/mvt
- MVT indicators: https://github.com/mvt-project/mvt-indicators
- Parent epic: #11
- Architecture decision: Kotlin port (not Python-on-Android) — see brainstorm analysis 2026-03-28

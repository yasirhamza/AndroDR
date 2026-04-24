# AndroDR Architecture

> This is the canonical architecture reference for AndroDR. For how to contribute, see [CONTRIBUTING.md](../CONTRIBUTING.md). For user-facing guarantees, see [PRIVACY_POLICY.md](PRIVACY_POLICY.md). The README carries only a short sketch that links here.

## 1. Overview

AndroDR is an on-device Android security scanner and endpoint detection and response (EDR) app. It detects stalkerware, malware, mercenary spyware, sideloaded app risk, accessibility-service and device-admin abuse, DNS command-and-control traffic, and unpatched CVEs — entirely on the device, with no backend and no cloud dependency. Detection logic is expressed as SIGMA-style YAML rules that are evaluated against structured telemetry events emitted by scanner modules; the Kotlin rule engine is the evaluator, and the YAML files are the behavior. IOC (indicator of compromise) data lives in an external `android-sigma-rules` repository rather than being bundled in the APK, which means new indicators reach users within hours via a background refresh rather than weeks via an app-store release.

```
┌────────────────────────┐
│  Device                │
└─────────┬──────────────┘
          │ (packages, flags, DNS, bug reports)
          ▼
┌────────────────────────┐      ┌───────────────────────┐
│  Telemetry emitters    │      │  IOC resolver         │
│  scanner/, network/    │◄────▶│  ioc/ + ioc/feeds/    │
└─────────┬──────────────┘      └───────────────────────┘
          │ structured events
          ▼
┌────────────────────────┐
│  SIGMA rule engine     │
│  sigma/                │
└─────────┬──────────────┘
          │ findings
          ▼
┌────────────────────────┐      ┌───────────────────────┐
│  Data layer  (Room)    │─────▶│  UI  (Compose)        │
│  data/                 │      │  ui/                  │
└─────────┬──────────────┘      └───────────────────────┘
          │
          ▼
┌────────────────────────┐
│  Reports (+STIX2)      │
│  reporting/            │
└────────────────────────┘
```

### Reader's map

- **Chapter 2** — Design principles: non-negotiables that constrain every module.
- **Chapter 3** — Module map: the actual package tree.
- **Chapter 4** — Detection pipeline: end-to-end data flow from device state to a user-visible finding. **Read first if you want to understand how it all fits.**
- **Chapters 5–8** — Subsystem deep-dives (data, reporting, DNS VPN, bug-report analysis).
- **Chapter 9** — External AI rule-authoring pipeline (Claude Code skills under `.claude/`).
- **Chapter 10** — Test strategy.
- **Chapter 11** — Architecture decisions with the reasoning behind each one.

---

## 2. Design Principles

The following six principles are non-negotiables that constrain every module. A change that violates any one of them requires an explicit architecture decision (see Chapter 11) before it can be merged.

1. **Detection logic lives in YAML SIGMA rules, not in Kotlin code.** The Kotlin engine is the evaluator; rules are the behavior. Adding a new detection means adding a rule file. Consequence: rules are reviewable as data, portable, and updatable without an app release.

2. **IOC data lives in the external `android-sigma-rules` repository, not bundled in the APK.** Indicator lists refresh at runtime so new indicators reach users within hours, not weeks.

3. **Telemetry emitters are pure and stateless.** `scanner/` and `network/` modules produce structured events; they do NOT decide what counts as a finding — the rule engine does. Static enforcement of this contract is tracked in [#136] and the machine-readable schema in [#137].

4. **All processing happens on the device.** No backend, no cloud, no accounts, no analytics SDK. Report sharing is user-initiated only, via the Android share sheet.

5. **Privacy by design.** Collect only what's needed; persist only what's needed; never transmit user data automatically; disable cloud backup (`android:allowBackup="false"`).

6. **SIGMA compatibility where practical.** The rule schema deliberately tracks SIGMA semantics so rules are readable by SIGMA-familiar reviewers and long-run portability stays feasible.

[#136]: https://github.com/yasirhamza/AndroDR/issues/136
[#137]: https://github.com/yasirhamza/AndroDR/issues/137

---

## 3. Module Map

Current package tree under `app/src/main/java/com/androdr/`:

```
.
├── AndroDRApplication.kt
├── MainActivity.kt
├── data/
│   ├── db/          Room DAOs + AppDatabase
│   ├── model/       Domain models (AppRisk, DeviceFlag, DnsEvent, ScanResult, timeline events, bug-report findings)
│   └── repo/        Repositories (ScanRepository, DnsEventRepository, etc.)
├── di/              Hilt modules
├── ioc/             IOC resolver, dispatcher, feeds, STIX2 serialization, periodic update worker
│   └── feeds/       Feed-specific ingesters (stalkerware, MVT, MalwareBazaar, ThreatFox, UAD, Plexus, cert-hash)
├── network/         LocalVpnService (local DNS interception) + DNS event capture
├── reporting/       ReportFormatter, ReportExporter, timeline formatter/exporter, guidance text helpers
├── scanner/         Pure telemetry emitters (app, device, accessibility, app-ops, file artifacts, process, usage stats, receivers, device-admin-grant, install event)
│   └── bugreport/   Bug-report ZIP parser and per-section modules
├── sigma/           SIGMA rule engine: parser, evaluator, engine, correlation, rule feeds, telemetry field maps
└── ui/              Jetpack Compose screens
    ├── apps/          Apps screen + ViewModel
    ├── bugreport/     Bug-report analysis screen + ViewModel
    ├── common/        Shared composables
    ├── dashboard/     Dashboard screen + ViewModel
    ├── device/        Device audit screen + ViewModel
    ├── history/       Scan history + export
    ├── network/       DNS monitor screen + ViewModel
    ├── permissions/   Permission prompts + rationales
    ├── settings/      Settings + About
    ├── theme/         Material theme tokens
    └── timeline/      Forensic timeline screen + ViewModel
```

### Notes

The sole WorkManager worker (`IocUpdateWorker`) lives inside `ioc/`, not in a separate `worker/` package. It is responsible for periodic IOC feed refreshes and is wired up via a Hilt module in `di/`.

STIX2 serialization (`StixBundle.kt`) lives directly in `ioc/`, not in a subdirectory. It is used by the reporting layer to produce machine-readable threat-intelligence exports alongside the human-readable plaintext report.

Scanner modules under `scanner/` are pure: each emitter observes one aspect of device state (installed packages, accessibility services, app-ops grants, running processes, etc.) and produces structured telemetry events. No scanner module evaluates rules or makes pass/fail judgments. The rule engine in `sigma/` is the single place detection logic runs.

UI is strictly a consumer. ViewModels observe repositories via `StateFlow`; no scanning or rule evaluation happens on the UI dispatcher. The UI layer has no direct dependency on `scanner/`, `sigma/`, or `ioc/`.

---

## 4. Detection pipeline

### 4.0 Introduction

This chapter traces a finding from raw device state to the user's screen. The pipeline has four stages with deliberately separated responsibilities. Telemetry emitters observe device state and produce structured records; they never decide what counts as suspicious. The SIGMA rule engine consumes those records and decides which rules match; it does not ingest indicators or produce display text independently of rules. The IOC resolver answers "is this value known-bad?" for the four supported indicator types; it never evaluates rules. Findings are the output of the evaluator — they carry rule identity, severity, matched-record context, and remediation text, but no logic.

Keeping these responsibilities separated means each concern can change independently: a new malware family can be detected by adding a YAML rule without touching Kotlin; an updated stalkerware cert hash reaches users within hours via IOC refresh rather than weeks via an app-store release; and UI text changes live in rule YAML, not in Compose composables.

---

### 4.1 Telemetry emitters (`scanner/`, `network/`, `scanner/bugreport/`)

A telemetry emitter is a pure function of device state: given the current state of one device subsystem (installed packages, running processes, accessibility grants, etc.), it returns a list of typed, structured records. Emitters perform no rule evaluation, no IOC lookups, and produce no display text. They are the eyes of the pipeline, not the brain.

**App-layer scanners**

- `AppScanner` — Enumerates every installed package via `PackageManager` and emits one `AppTelemetry` record per app. Fields include `packageName`, `appName`, `certHash` (SHA-256), `certHashSha1` (SHA-1), `apkHash` (SHA-256 of the APK file), `isSystemApp`, `isSideloaded`, `fromTrustedStore`, `installer`, `isKnownOemApp`, `permissions` (surveillance-relevant only), `surveillancePermissionCount`, `hasAccessibilityService`, `hasDeviceAdmin`, `knownAppCategory`, `servicePermissions`, `receiverPermissions`, `hasLauncherActivity`, `firstInstallTime`, and `lastUpdateTime`. Hashing runs in a bounded parallel pool (up to 16 concurrent workers) to keep wall time acceptable on devices with many installed packages.
- `AccessibilityAuditScanner` — Emits `AccessibilityTelemetry` for every enabled accessibility service.
- `AppOpsScanner` — Emits `AppOpsTelemetry` records for sensitive app-op grants (microphone, camera, package installation).
- `ReceiverAuditScanner` — Emits `ReceiverTelemetry` for broadcast receivers matching sensitive permission patterns (SMS, call interception).
- `FileArtifactScanner` — Emits `FileArtifactTelemetry` for file paths that match known spyware artifact patterns.
- `ProcessScanner` — Emits `ProcessTelemetry` for running processes of interest.
- `UsageStatsScanner` — Emits usage-statistics records for behavioral analysis.
- `DeviceAuditor` — Emits `DeviceTelemetry` records covering security-relevant flags: ADB enabled state, developer options, unknown sources, screen-lock posture, patch level, bootloader lock state, and others.
- `DeviceAdminGrantEmitter` / `InstallEventEmitter` — Event-based emitters that fire on device-admin grants and package install/uninstall events respectively, feeding the forensic timeline.

**Network / DNS**

- `LocalVpnService` (in `network/`) — Intercepts DNS queries via a local VPN loopback and emits `DnsEvent` records, each carrying the queried domain and the requesting app's UID. These records are the telemetry input for the `dns_monitor` rule service.

**Bug-report analysis** (`scanner/bugreport/`)

Bug-report ZIP parsers are a separate family of emitters that extract structured telemetry from Android bug reports rather than from live device state. Modules include `TombstoneParser` (native crash tombstones → `TombstoneEvent`), `WakelockParser` (`WakelockAcquisition`), `BatteryDailyModule` (`BatteryDailyEvent`), `InstallTimeModule` (`PackageInstallHistoryEntry`), `PlatformCompatModule` (`PlatformCompatChange`), `DbInfoModule` (`DatabasePathObservation`), `AccessibilityModule`, `ActivityModule`, `AdbKeysModule`, `AppOpsModule`, `ReceiverModule`, and `GetpropParser`/`DumpsysSectionParser` for raw section extraction. The overarching coordinator is `BugreportModule` / `BugReportAnalyzer`.

**Purity contract**

The purity contract — emitters produce structured records, period — is enforced by convention today, with static enforcement and a machine-readable schema tracked in [#136].

---

### 4.2 SIGMA rule engine (`sigma/`)

The rule engine is the single place detection logic runs. It is stateless relative to any single evaluation call: given a list of rules and a list of telemetry records, it returns findings.

**Classes**

| Class | Role |
|---|---|
| `SigmaRuleEngine` | Singleton coordinator. Loads bundled rules from `res/raw/` on startup, merges optional remote rules, holds the live `iocLookups` and `evidenceProviders` maps, and dispatches each typed telemetry batch to `SigmaRuleEvaluator` via one `evaluate*` method per logsource service. |
| `SigmaRuleParser` | Parses YAML rule documents into `SigmaRule` objects. Raises `SigmaRuleParseException` (non-swallowed) for required-field violations so bad bundled rules fail loudly at startup. Also exposes `parseCorrelation()` for correlation rule documents. |
| `SigmaRuleEvaluator` | Pure evaluation function: `(rules, records, service, iocLookups, evidenceProviders) → findings`. Filters rules by `logsource.service`, evaluates each rule's condition against each record, and calls `buildFinding()` when a condition matches. |
| `SigmaRule` | Data class representing a parsed detection rule. |
| `SigmaRuleFeed` | Interface for remote rule feeds that supply additional rules at runtime (beyond the bundled set). |
| `SigmaCorrelationEngine` | Evaluates `CorrelationRule` objects against a forensic timeline, matching temporal sequences (`temporal_ordered`), co-occurrence windows (`temporal`), and event counts (`event_count`). |
| `CorrelationRule` | Data class representing a parsed correlation rule. |
| `TelemetryFieldMaps` | Extension functions (`.toFieldMap()`) that convert each typed telemetry class into the `Map<String, Any?>` record shape `SigmaRuleEvaluator` expects. Field names are `snake_case` to match SIGMA rule conventions. |
| `TemplateResolver` | Resolves `{variable}` placeholders in rule title and remediation templates using fields from the matched record. |

**What a rule declares**

A detection rule is a YAML document with these sections:

- `logsource.service` — names the telemetry type the rule targets. Supported services (verified in `SigmaRuleEngine`): `app_scanner`, `device_auditor`, `process_monitor`, `dns_monitor`, `file_scanner`, `accessibility_audit`, `receiver_audit`, `appops_audit`, `tombstone_parser`, `wakelock_parser`, `battery_daily`, `package_install_history`, `platform_compat`, `db_info`.
- `detection` — one or more named selections, each mapping field names (with optional modifiers) to match values, plus a `condition` expression combining selection names with `and`, `or`, `not`.
- `category` — required top-level field, must be `incident` or `device_posture`. Missing or invalid category raises `SigmaRuleParseException` and fails the build.
- `level` — severity string (`informational`, `low`, `medium`, `high`, `critical`). The `SeverityCapPolicy` caps `device_posture` rules at `high`.
- `display` — contains `triggered_title`, `safe_title`, `icon`, `evidence_type`, `summary_template`, `guidance`.
- `remediation` — list of strings (template-expanded at finding-build time).

**Field modifiers** (verified against `SigmaRuleParser.modifierFromToken`, lines 319–333):

`contains`, `startswith`, `endswith`, `re` (regex, ReDoS-protected: length cap 500 chars, 1-second timeout, cache-bounded at 256 entries), `gte`, `lte`, `gt`, `lt`, `ioc_lookup`, `all`.

All string modifiers support list-valued fields element-wise; the `|all` combiner flips the default `any` quantifier to `all`.

**Bundled rules**

44 rule files (detection + atom + correlation) ship inside `app/src/main/res/raw/` and are loaded at startup by an explicit manifest in `SigmaRuleEngine.BUNDLED_RULE_IDS` (R8-safe, no reflection). The first four rules (`androdr-001` through `androdr-004`) drive IOC matching for package names, cert hashes, C2 domains, and APK file hashes respectively.

**Schema enforcement**

`BundledRulesSchemaCrossCheckTest` compiles the schema from `third-party/android-sigma-rules/validation/rule-schema.json` (the git submodule) and cross-checks it against the modifiers and services `SigmaRuleParser` actually recognizes. The build fails if parser and schema disagree — the submodule schema is the authoritative contract between the rule-authoring pipeline and the Kotlin engine.

---

### 4.3 IOC resolver (`ioc/`, `ioc/feeds/`)

The IOC resolver answers point queries: "is this package name / cert hash / APK hash / domain known-bad?" It does not evaluate rules.

**Supported indicator types and owning classes**

| Type | Runtime resolution | Bundled fallback |
|---|---|---|
| Package name | `IndicatorResolver.isKnownBadPackage()` → `indicators` table (Room) | `IocDatabase` (`known_bad_packages.json`) |
| Cert hash (SHA-256 or SHA-1) | `IndicatorResolver.isKnownBadCert()` → `indicators` table | `CertHashIocDatabase` (`known_bad_certs.json`) |
| APK file hash (SHA-256) | `IndicatorResolver.isKnownBadApkHash()` → `indicators` table | `ApkHashIocDatabase` (`known_bad_apk_hashes.json`) |
| C2 domain | `IndicatorResolver.isKnownBadDomain()` → `DomainBloomIndex` | `domain_blocklist.txt` |

Domain lookups never touch Room on the hot path. `DomainBloomIndex` is a bloom filter over a sorted 64-bit hash array built in memory at cache-refresh time. A query for `c2.evil.com` walks the label hierarchy (`c2.evil.com` → `evil.com`) so a blocklist entry on the parent domain catches all subdomains. The bloom-negative fast path costs approximately 150 ns, keeping the VPN packet-read thread unblocked.

The known-good side is handled by `KnownAppResolver` / `KnownAppDatabase` (Plexus + UAD feeds, 14 000+ popular apps) and `OemPrefixResolver` (OEM package-name prefix matching for apps not yet in the DB).

**Feed ingesters** (`ioc/feeds/`)

| Ingester | Indicator type(s) | Source |
|---|---|---|
| `StalkerwareIndicatorsFeed` | Package names | `stalkerware-indicators` GitHub repo |
| `StalkerwareCertHashFeed` / `MalwareBazaarCertFeed` | Cert hashes | stalkerware-indicators + MalwareBazaar |
| `MvtIndicatorsFeed` | Domains, package names | MVT (Mobile Verification Toolkit) public indicator list |
| `ThreatFoxDomainFeed` | C2 domains | abuse.ch ThreatFox |
| `HaGeZiTifFeed` | Domains | HaGeZi threat-intelligence feed |
| `ZimperiumIocFeed` | Package names / domains | Zimperium public IOC data |
| `UadKnownAppFeed` / `PlexusKnownAppFeed` | Known-good apps | UAD-ng + Plexus |
| `RemoteJsonFeed` | Generic (configurable) | Remote JSON endpoint |
| `PublicRepoIocFeed` | All types | `android-sigma-rules` public repo `ioc-data/` directory |

**Orchestration and deduplication**

`IndicatorUpdater` is the unified feed orchestrator. It runs all package, domain, and cert-hash feeds in parallel (`coroutineScope` + `async`), converts results to the unified `Indicator` entity, and upserts into the `indicators` Room table. After each feed run it calls `dao.deleteStaleEntries(sourceId, runStart)` to evict removed indicators. A `Mutex` prevents concurrent update runs. After all feeds complete, `IndicatorResolver.refreshCache()` rebuilds the in-memory caches and the `DomainBloomIndex` atomically.

Deduplication is handled by the Room `UNIQUE` constraint on `(type, value)` combined with `upsertAll` (insert-or-replace semantics). When two feeds contribute the same indicator value, the later upsert wins. Dual-writer collision semantics (last-write-wins vs. merge-by-severity) are an open question tracked in [#143].

Feed-level cursor state (last-fetched timestamps) and per-indicator provenance (`source`, `fetchedAt` fields on `Indicator`) are persisted in the database, making the ingest pipeline auditable after the fact.

---

### 4.4 Findings

When `SigmaRuleEvaluator` matches a rule against a telemetry record, it produces a `Finding` via the internal `buildFinding()` factory (the only sanctioned construction path — bypassing it risks severity-cap violations). A `Finding` carries:

- `ruleId`, `title` — rule identity and display title (template-expanded from the matched record)
- `level` — severity after `SeverityCapPolicy.applyCap()` (caps `device_posture` rules at `high`)
- `category` — `FindingCategory` enum: `DEVICE_POSTURE`, `APP_RISK`, or `NETWORK`
- `tags` — MITRE ATT&CK and other tags from the rule
- `remediation` — list of template-expanded remediation strings
- `iconHint`, `guidance` — UI hints sourced entirely from the rule YAML
- `triggered` — `true` for a positive match; `false` when `report_safe_state: true` and the condition did not match (safe-state reporting)
- `evidence` — structured evidence record (e.g., the matching IOC entry), or `Evidence.None`
- `matchContext` — shallow copy of the matched telemetry record's scalar fields (for display and export)

Findings are serialized via `kotlinx.serialization` and stored as part of `ScanResult` in Room via `ScanRepository.saveScan()`. The dashboard, apps, device-audit, and timeline screens all observe `ScanRepository` as a `Flow<List<ScanResult>>`, so they update automatically whenever a new scan is saved.

Because all display metadata (title, icon, guidance, remediation text) lives in the rule YAML rather than in Kotlin, adding a new detection never requires touching UI code.

---

### 4.5 Example end-to-end walkthrough

The following steps trace a stalkerware app from installation to a user-visible finding.

1. **Telemetry emission.** `AppScanner.collectTelemetry()` enumerates installed packages and, for the stalkerware app, builds an `AppTelemetry` record with `packageName = "com.example.trackview"`, `certHash = "a3f7…"` (SHA-256 of the signing cert), `apkHash = "9c12…"` (SHA-256 of the APK file), `isSystemApp = false`, `isSideloaded = true`, and several entries in `permissions` (e.g., `ACCESS_FINE_LOCATION`, `RECORD_AUDIO`). No IOC lookups happen here.

2. **Field-map conversion.** `SigmaRuleEngine.evaluateApps()` calls `it.toFieldMap()` on each `AppTelemetry` instance, converting it to the `Map<String, Any?>` shape `SigmaRuleEvaluator` expects. The field name for the package identifier in the map is `package_name`.

3. **Rule load.** `SigmaRuleEngine` has already loaded `sigma_androdr_001_package_ioc.yml` at startup. Its detection section is:
   ```yaml
   detection:
     selection:
       package_name|ioc_lookup: package_ioc_db
     filter_system_app:
       is_system_app: true
     condition: selection and not filter_system_app
   ```
   The `ioc_lookup` modifier tells the evaluator to call the lambda registered under the key `package_ioc_db` in the `iocLookups` map.

4. **IOC resolution.** The `package_ioc_db` lambda delegates to `IndicatorResolver.isKnownBadPackage("com.example.trackview")`. The resolver checks the in-memory `IndicatorCache` first (populated from the `indicators` Room table by the most recent `IocUpdateWorker` run), then falls back to the bundled `IocDatabase` (`known_bad_packages.json`). The package is found; a non-null `BadPackageInfo` is returned.

5. **Condition match.** `is_system_app` is `false`, so `filter_system_app` evaluates to `false`, `not filter_system_app` is `true`, and `selection and not filter_system_app` is `true`. `SigmaRuleEvaluator.buildFinding()` produces a `Finding` with `ruleId = "androdr-001"`, `title = "Known Malicious Package"`, `level = "critical"`, `category = APP_RISK`, and `remediation = ["Uninstall this app immediately."]`.

6. **Persistence.** `ScanOrchestrator` collects all findings from all evaluators and passes the completed `ScanResult` (including findings) to `ScanRepository.saveScan()`, which writes it to Room in a single transaction.

7. **UI update.** The apps-screen `ViewModel` observes `ScanRepository.allScans` as a `Flow`. The Room `InvalidationTracker` fires exactly once per transaction, triggering a recomposition that displays the finding with its title, severity badge, and remediation text — all sourced from the rule YAML.

8. **Report export.** When the user requests an export, `ReportExporter` reads the persisted `ScanResult` from `ScanRepository`, formats findings via `ReportFormatter` (including the remediation text), captures a logcat snapshot, and writes a plaintext (and optionally STIX2 JSON) report to `cacheDir/reports/`, served via `FileProvider` to the Android share sheet.

---

[#143]: https://github.com/yasirhamza/AndroDR/issues/143

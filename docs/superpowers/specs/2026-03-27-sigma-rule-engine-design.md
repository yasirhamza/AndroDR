# SIGMA-Compatible Detection Rule Engine — Design Spec

## Goal

Replace all hardcoded detection logic in AndroDR with a SIGMA-compatible YAML rule engine. Detection patterns become data (YAML rules in a public repo), not code. Rules are updatable independently of the app binary.

## Motivation

- Detection logic is an ongoing process informed by threat intelligence — hardcoded heuristics go stale
- Threat disguise patterns (system name impersonation, permission combinations) change constantly
- No open-source mobile detection rule standard exists — SIGMA covers Windows/Linux/macOS/cloud only
- AndroDR would be the first SIGMA-compatible Android EDR
- SOC teams can reuse the same rules on-device (AndroDR) and in their SIEM

---

## Architecture

### Two-Phase Scan

```
Phase 1: COLLECT (pure telemetry — no detection logic)
  AppScanner      → List<AppTelemetry>      (one per installed package)
  DeviceAuditor   → List<DeviceTelemetry>   (one per posture check)
  DnsMonitor      → List<DnsTelemetry>      (one per DNS event)

Phase 2: EVALUATE (rule engine — all detection logic)
  RuleEngine.evaluate(telemetry, rules) → List<Finding>

Optional: Export phase 1 telemetry to external SIEM receiver
```

Phase 1 produces normalized data with no opinions. Phase 2 applies rules and produces findings. If rules fail to load, the app still shows raw telemetry. The phases are fully decoupled.

### SIGMA Logsource Mapping

```yaml
logsource:
  product: androdr
  service: app_scanner | device_auditor | dns_monitor
```

`product: androdr` — the software producing telemetry.
`service` — the specific scanner component. Maps directly to an AndroDR class.

---

## Components

### 1. Field Vocabulary

Each service defines a fixed set of normalized field names that rules can reference.

**`service: app_scanner`** — one record per installed package:

| Field | Type | Description |
|-------|------|-------------|
| `package_name` | String | Android package name |
| `app_name` | String | Display name from PackageManager |
| `cert_hash` | String | SHA-256 of signing cert (lowercase hex, no colons) |
| `is_system_app` | Boolean | `ApplicationInfo.FLAG_SYSTEM` set |
| `from_trusted_store` | Boolean | Installer is Play Store, Galaxy Store, or Samsung ecosystem |
| `installer` | String? | Installer package name or null |
| `is_sideloaded` | Boolean | Not system, not from trusted store, not known OEM |
| `is_known_oem_app` | Boolean | Matches known OEM/AOSP package prefix or community feed |
| `permissions` | List[String] | Granted dangerous permissions (short names) |
| `surveillance_permission_count` | Int | Count of surveillance-capable permissions |
| `has_accessibility_service` | Boolean | Declares AccessibilityService in manifest |
| `has_device_admin` | Boolean | Declares DeviceAdminReceiver in manifest |
| `known_app_category` | String? | Category from KnownAppResolver (OEM, USER_APP, etc.) |

**`service: device_auditor`** — one record per posture check:

| Field | Type | Description |
|-------|------|-------------|
| `check_id` | String | e.g., "adb_enabled", "bootloader_unlocked" |
| `is_triggered` | Boolean | Whether the check failed |
| `adb_enabled` | Boolean | USB debugging on |
| `dev_options_enabled` | Boolean | Developer options on |
| `unknown_sources_enabled` | Boolean | Install from unknown sources allowed |
| `screen_lock_enabled` | Boolean | PIN/password/biometric configured |
| `patch_level` | String | Security patch date (YYYY-MM-DD) |
| `patch_age_days` | Int | Days since patch level date |
| `bootloader_unlocked` | Boolean | Bootloader unlocked |
| `wifi_adb_enabled` | Boolean | Wireless ADB active |

**`service: dns_monitor`** — one record per DNS event:

| Field | Type | Description |
|-------|------|-------------|
| `domain` | String | Queried domain name |
| `timestamp` | Long | Epoch millis |
| `app_uid` | Int | UID of querying app (-1 if unknown) |
| `app_name` | String? | Name of querying app |
| `is_blocked` | Boolean | Whether the query was blocked |

### 2. Telemetry Data Classes

New Kotlin data classes for phase 1 output:

```kotlin
data class AppTelemetry(
    val packageName: String,
    val appName: String,
    val certHash: String?,
    val isSystemApp: Boolean,
    val fromTrustedStore: Boolean,
    val installer: String?,
    val isSideloaded: Boolean,
    val isKnownOemApp: Boolean,
    val permissions: List<String>,
    val surveillancePermissionCount: Int,
    val hasAccessibilityService: Boolean,
    val hasDeviceAdmin: Boolean,
    val knownAppCategory: String?
)
```

Similar classes for `DeviceTelemetry` and `DnsTelemetry`.

### 2b. Future Service Field Vocabularies (reserved)

These services are not yet implemented but their field vocabularies are defined
here so that rules can be written against them today (with `status: experimental`)
and will activate once the corresponding scanner ships.

**`service: network_monitor`** (roadmap #6) — one record per outbound connection:

| Field | Type | Description |
|-------|------|-------------|
| `destination_ip` | String | IPv4/IPv6 address |
| `destination_port` | Int | TCP/UDP port |
| `protocol` | String | "tcp" or "udp" |
| `app_uid` | Int | UID of connecting app |
| `app_name` | String? | Name of connecting app |
| `timestamp` | Long | Epoch millis |

**`service: file_scanner`** (roadmap #8) — one record per file path checked:

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | String | Absolute path on device |
| `file_exists` | Boolean | Whether the file was found |
| `file_size` | Long? | Size in bytes if exists |
| `file_modified` | Long? | Last modified epoch millis |

**`service: process_monitor`** (roadmap #9) — one record per running process:

| Field | Type | Description |
|-------|------|-------------|
| `process_name` | String | Process name from /proc or ActivityManager |
| `process_uid` | Int | UID of the process |
| `package_name` | String? | Associated package name if known |
| `is_foreground` | Boolean | Whether the process is in foreground |

### 3. Rule Format

Standard SIGMA YAML with AndroDR extensions:

```yaml
title: Sideloaded app with system-impersonating name
id: androdr-016
status: production
description: >
    Detects apps installed from untrusted sources that use display names
    mimicking system components. A hallmark of stalkerware and mercenary
    spyware that disguises itself as a legitimate system app.
author: AndroDR
date: 2026/03/27
tags:
    - attack.t1036.005
logsource:
    product: androdr
    service: app_scanner
detection:
    selection_untrusted:
        is_system_app: false
        from_trusted_store: false
    selection_name:
        app_name|contains:
            - 'System'
            - 'Service'
            - 'Google'
            - 'Android'
            - 'Samsung'
            - 'Update'
            - 'Security'
    condition: selection_untrusted and selection_name
level: high
falsepositives:
    - Legitimate developer tools with system-sounding names
# AndroDR extension: remediation guidance shown in bottom sheet
remediation:
    - "This app's name impersonates a system component but was installed from an untrusted source."
    - "Uninstall it unless you specifically installed it."
```

**Supported SIGMA detection modifiers:**
- `|contains` — substring match
- `|startswith` — prefix match
- `|endswith` — suffix match
- `|re` — regex match (use sparingly)
- `|all` — all values must match (for list fields)
- Numeric comparisons: `|gte`, `|lte`, `|gt`, `|lt`
- Boolean fields: direct `true`/`false` matching
- List fields: `fieldname|contains` checks if any element matches
- `condition` syntax: `selection_a and selection_b`, `selection_a or selection_b`, `not selection_a`, `1 of selection_*`, `all of selection_*`

**AndroDR extensions (non-standard SIGMA fields):**
- `remediation` — list of user-facing remediation steps (shown in bottom sheet)
- `severity_escalation` — conditional severity override (e.g., escalate to CRITICAL if sideloaded)
- `ioc_lookup` — reference to an IOC database for lookup-based rules

### 4. IOC Lookup Rules

Rules that reference IOC databases use a special detection pattern:

```yaml
title: APK signed with known malicious certificate
id: androdr-002
logsource:
    product: androdr
    service: app_scanner
detection:
    selection:
        cert_hash|ioc_lookup: cert_hash_ioc_db
    condition: selection
level: critical
remediation:
    - "This app is signed by a known malware developer. Uninstall it."
```

The `|ioc_lookup` modifier tells the rule engine to check the field value against the named IOC database (existing Room-backed resolvers: `package_ioc_db`, `cert_hash_ioc_db`, `domain_ioc_db`).

### 5. Rule Engine (`SigmaRuleEngine`)

Kotlin class that:

1. **Loads rules** from bundled `res/raw/sigma_rules/` and remote feed
2. **Parses SIGMA YAML** into `SigmaRule` data class (id, logsource, detection conditions, level, remediation)
3. **Evaluates rules** against telemetry records — for each telemetry record, check all rules whose `logsource.service` matches
4. **Produces findings** — `Finding(ruleId, title, level, matchedFields, remediation)`

```kotlin
class SigmaRuleEngine(
    private val rules: List<SigmaRule>,
    private val iocLookups: Map<String, IocLookup>  // name → lookup function
) {
    fun evaluate(telemetry: List<AppTelemetry>): List<Finding> { ... }
    fun evaluate(telemetry: List<DeviceTelemetry>): List<Finding> { ... }
    fun evaluate(telemetry: List<DnsTelemetry>): List<Finding> { ... }
}
```

The engine is a pure function: `(telemetry, rules) → findings`. No side effects, no state, fully testable.

### 6. Rule Feed (`SigmaRuleFeed`)

Fetches rules from the public `android-sigma-rules/rules` repo. Same pattern as existing IOC feeds:

- Source: `https://raw.githubusercontent.com/android-sigma-rules/rules/main/`
- Fetches a manifest (`rules.yml`) listing all rule files
- Downloads individual rule YAML files
- Caches in app storage
- Updated via `IocUpdateWorker` alongside IOC feeds

Bundled rules in `res/raw/sigma_rules/` provide offline baseline.

### 7. AppScanner Migration

Current AppScanner has two responsibilities interleaved:
1. Collect app metadata (PackageManager queries)
2. Apply detection logic (hardcoded if-checks)

Migration:
- AppScanner keeps responsibility 1: collect metadata, output `List<AppTelemetry>`
- Responsibility 2 moves entirely to `SigmaRuleEngine`
- All hardcoded detection code in AppScanner is removed
- `AppRisk` is still the UI-facing model — constructed from `Finding` objects

### 8. Finding → AppRisk Mapping

The UI still consumes `AppRisk`. A mapper converts rule engine output:

```kotlin
fun findingsToAppRisks(
    telemetry: List<AppTelemetry>,
    findings: List<Finding>
): List<AppRisk> {
    // Group findings by package_name
    // Merge into AppRisk with reasons from each finding's rule title/remediation
    // Set isKnownMalware if any finding has level: critical + ioc_lookup
    // Set riskLevel from highest finding level
}
```

### 9. Public Rules Repo Structure

```
android-sigma-rules/rules/
├── README.md
├── LICENSE                          # DRL (Detection Rule License) or CC-BY
├── rules.yml                        # manifest listing all rule files
├── app_scanner/
│   ├── ioc_package_name.yml         # ANDRODR-001
│   ├── ioc_cert_hash.yml            # ANDRODR-002
│   ├── sideloaded_app.yml           # ANDRODR-010
│   ├── surveillance_permissions.yml # ANDRODR-011
│   ├── accessibility_abuse.yml      # ANDRODR-012
│   ├── device_admin_abuse.yml       # ANDRODR-013
│   ├── app_impersonation.yml        # ANDRODR-014
│   ├── firmware_implant.yml         # ANDRODR-015
│   ├── system_name_disguise.yml     # ANDRODR-016
│   ├── accessibility_surveillance_combo.yml  # ANDRODR-017
│   └── packer_detection.yml         # ANDRODR-018
├── device_auditor/
│   ├── adb_enabled.yml              # ANDRODR-040
│   ├── dev_options.yml              # ANDRODR-041
│   ├── unknown_sources.yml          # ANDRODR-042
│   ├── no_screen_lock.yml           # ANDRODR-043
│   ├── stale_patch.yml              # ANDRODR-044
│   ├── bootloader_unlocked.yml      # ANDRODR-045
│   └── wifi_adb.yml                 # ANDRODR-046
└── dns_monitor/
    └── ioc_domain.yml               # ANDRODR-003
```

### 10. Integration with Existing Components

| Component | Current | After |
|-----------|---------|-------|
| `AppScanner` | Collects metadata + applies detection | Collects metadata only → `List<AppTelemetry>` |
| `DeviceAuditor` | Checks flags + constructs DeviceFlag | Checks flags only → `List<DeviceTelemetry>` |
| `ScanOrchestrator` | Calls scanner + auditor | Calls scanner + auditor + rule engine, maps findings to AppRisk/DeviceFlag |
| `DnsVpnService` | Checks domain blocklist inline | Emits DnsTelemetry, rule engine evaluates (or keeps inline for performance) |
| `IocUpdateWorker` | Updates IOC feeds | Also fetches latest rules from public repo |
| `AppRisk` | Constructed by AppScanner | Constructed from rule engine findings |
| `DeviceFlag` | Constructed by DeviceAuditor | Constructed from rule engine findings |

**Exception — DNS monitor performance:** DNS query evaluation must happen in real-time (milliseconds per query). The rule engine may be too slow for inline DNS blocking. Keep the existing `DomainIocResolver` for real-time DNS blocking; the rule engine evaluates DNS events post-hoc for reporting.

---

## Testing

- **Rule engine unit tests:** Pure function — feed it test telemetry + test rules, assert findings
- **Rule parsing tests:** Verify all 24 seed rules parse without error
- **Field vocabulary tests:** Verify AppScanner produces correct AppTelemetry fields for known packages
- **Integration test:** Full scan with rules produces same findings as current hardcoded logic (regression)
- **Adversary simulation:** Existing harness validates rule-based detection matches expected patterns

---

## Migration Strategy

1. Ship rule engine alongside hardcoded detection (both run, results compared)
2. Verify rule-based results match hardcoded results across adversary simulation
3. Remove hardcoded detection code from AppScanner
4. All future detection logic added as YAML rules only

---

## Out of Scope

- SIGMA-to-SIEM query compilation (Splunk, Elastic conversion)
- Real-time DNS rule evaluation (keep existing DomainIocResolver for performance)
- Rule editor UI in the app
- Telemetry export to external SIEM (architecture supports it, implementation deferred)
- pySigma backend for AndroDR (community contribution opportunity)

# Author Quality Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve AI rule pipeline output quality by adding cross-source IOC verification, a logsource field taxonomy, and fixing source name inconsistencies.

**Architecture:** Edit two skill prompt files (researcher + author) and the orchestrator to enforce a `requires_verification` gate on single-source IOCs and inject a field taxonomy. Add a new `logsource-taxonomy.yml` to the submodule validation directory with a cross-check unit test. Fix `amnesty-tech` → `amnesty-investigations` atomically across the submodule.

**Tech Stack:** Kotlin (unit tests), YAML (taxonomy), Python (validate-rule.py), Markdown (skill prompts), JSON (sir-schema.json, allowed-sources.json)

**Spec:** `docs/superpowers/specs/2026-04-13-author-quality-design.md`
**Issue:** #108 | **Epic:** #104

---

### Task 1: Fix amnesty source name in submodule (atomic rename)

**Files:**
- Modify: `third-party/android-sigma-rules/validation/allowed-sources.json:18`
- Modify: `third-party/android-sigma-rules/ioc-data/package-names.yml` (4 entries)
- Modify: `third-party/android-sigma-rules/ioc-data/c2-domains.yml` (22 entries)
- Modify: `third-party/android-sigma-rules/ioc-data/cert-hashes.yml` (header + 3 entries)

This must be atomic — changing `allowed-sources.json` without fixing the IOC data
files will break `validate-ioc-data.py`.

- [ ] **Step 1: Rename in allowed-sources.json**

In `third-party/android-sigma-rules/validation/allowed-sources.json`, change:

```json
{
    "id": "amnesty-tech",
    "name": "Amnesty International Security Lab",
    "url": "https://github.com/AmnestyTech/investigations"
}
```

to:

```json
{
    "id": "amnesty-investigations",
    "name": "Amnesty International Security Lab",
    "url": "https://github.com/AmnestyTech/investigations"
}
```

- [ ] **Step 2: Rename in all IOC data files**

In each of these files, find-and-replace `amnesty-tech` with `amnesty-investigations`:

- `third-party/android-sigma-rules/ioc-data/package-names.yml` — 4 entries at lines 162, 168, 174, 180
- `third-party/android-sigma-rules/ioc-data/c2-domains.yml` — 22 entries (lines 100-205, every 5th line)
- `third-party/android-sigma-rules/ioc-data/cert-hashes.yml` — sources header line 4 + entries at lines 14, 20, 26

- [ ] **Step 3: Verify no remaining references**

Run: `grep -r "amnesty-tech" third-party/android-sigma-rules/`
Expected: no output (all instances replaced)

- [ ] **Step 4: Commit in submodule**

```bash
cd third-party/android-sigma-rules
git add validation/allowed-sources.json ioc-data/package-names.yml ioc-data/c2-domains.yml ioc-data/cert-hashes.yml
git commit -m "fix: rename amnesty-tech to amnesty-investigations

Standardize on amnesty-investigations to match upstream repo name
(AmnestyTech/investigations). Atomic rename across allowed-sources
and all IOC data files.

Closes #108"
cd ../..
```

- [ ] **Step 5: Bump submodule pointer in AndroDR**

```bash
git add third-party/android-sigma-rules
git commit -m "build: bump android-sigma-rules submodule (amnesty source rename)"
```

---

### Task 2: Add `requires_verification` to SIR schema

**Files:**
- Modify: `third-party/android-sigma-rules/validation/sir-schema.json`

- [ ] **Step 1: Add field to SIR schema**

In `third-party/android-sigma-rules/validation/sir-schema.json`, add `requires_verification` as an optional top-level property. After the existing `rule_hint` property, add:

```json
    "requires_verification": {
      "type": "boolean",
      "description": "True when SIR is built from a single unstructured source. Signals the Rule Author to record an ioc_confidence decision.",
      "default": false
    }
```

Do NOT add it to the `required` array — it is optional and defaults to false.

- [ ] **Step 2: Commit in submodule**

```bash
cd third-party/android-sigma-rules
git add validation/sir-schema.json
git commit -m "feat: add requires_verification field to SIR schema

Optional boolean at SIR level (not per-indicator). Signals that the
SIR was built from a single unstructured source and IOCs need
human review before promotion."
cd ../..
```

- [ ] **Step 3: Bump submodule pointer**

```bash
git add third-party/android-sigma-rules
git commit -m "build: bump android-sigma-rules submodule (SIR schema update)"
```

---

### Task 3: Create `logsource-taxonomy.yml`

**Files:**
- Create: `third-party/android-sigma-rules/validation/logsource-taxonomy.yml`

- [ ] **Step 1: Write the full taxonomy file**

Create `third-party/android-sigma-rules/validation/logsource-taxonomy.yml`:

```yaml
# Logsource Field Taxonomy — AndroDR SIGMA Rule Engine
#
# Authoritative reference for which fields each logsource service provides.
# Field names are the map keys from toFieldMap(), NOT Kotlin property names.
# The Rule Author skill uses this to constrain detection block fields.
# LogsourceTaxonomyCrossCheckTest.kt validates this matches the Kotlin runtime.

product: androdr

services:
  # ── Member-function toFieldMap() (data model classes) ──────────────

  app_scanner:
    model_class: AppTelemetry
    field_map: member
    status: active
    fields:
      package_name: { type: string, description: "Android package name (e.g., com.example.app)" }
      app_name: { type: string, description: "User-visible app label" }
      cert_hash: { type: string, nullable: true, description: "SHA-256 of signing certificate" }
      apk_hash: { type: string, nullable: true, description: "SHA-256 of APK file" }
      is_system_app: { type: boolean, description: "True if app is in /system partition" }
      from_trusted_store: { type: boolean, description: "True if installed from Play Store or other trusted source" }
      installer: { type: string, nullable: true, description: "Package name of the installer (e.g., com.android.vending)" }
      is_sideloaded: { type: boolean, description: "True if installed outside trusted stores" }
      is_known_oem_app: { type: boolean, description: "True if package matches known OEM prefix list" }
      permissions: { type: list, description: "List of declared Android permissions" }
      surveillance_permission_count: { type: int, description: "Count of surveillance-related permissions (camera, mic, location, SMS, etc.)" }
      has_accessibility_service: { type: boolean, description: "True if app declares an accessibility service" }
      has_device_admin: { type: boolean, description: "True if app declares a device admin receiver" }
      known_app_category: { type: string, nullable: true, description: "Category from known-good apps DB (e.g., SOCIAL, PRODUCTIVITY)" }
      service_permissions: { type: list, description: "Permissions declared on exported services" }
      receiver_permissions: { type: list, description: "Permissions declared on broadcast receivers" }
      has_launcher_activity: { type: boolean, description: "True if app has a launcher-visible activity" }
      first_install_time: { type: long, description: "Epoch ms of first install (0 = unknown)" }
      last_update_time: { type: long, description: "Epoch ms of last update (0 = unknown)" }

  device_auditor:
    model_class: DeviceTelemetry
    field_map: member
    status: active
    fields:
      check_id: { type: string, description: "Identifier for the specific device check" }
      is_triggered: { type: boolean, description: "True if the check found an issue" }
      adb_enabled: { type: boolean, description: "USB debugging enabled" }
      dev_options_enabled: { type: boolean, description: "Developer options enabled" }
      unknown_sources_enabled: { type: boolean, description: "Install from unknown sources enabled" }
      screen_lock_enabled: { type: boolean, description: "Screen lock is configured" }
      patch_level: { type: string, description: "Android security patch level (YYYY-MM-DD)" }
      patch_age_days: { type: int, description: "Days since last security patch" }
      bootloader_unlocked: { type: boolean, description: "Bootloader is unlocked" }
      wifi_adb_enabled: { type: boolean, description: "Wireless ADB debugging enabled" }
      unpatched_cve_count: { type: int, description: "Number of unpatched CVEs for this patch level" }
      unpatched_cves: { type: list, description: "List of CveEntity objects" }
      unpatched_cve_id: { type: string, description: "Comma-joined CVE IDs (derived field, not a constructor param)" }

  dns_monitor:
    model_class: DnsEvent
    field_map: member
    status: active
    fields:
      domain: { type: string, description: "Queried domain name" }
      app_uid: { type: int, description: "UID of the app that made the DNS query" }
      source_package: { type: string, nullable: true, description: "Package name of querying app (key differs from property appName)" }
      is_blocked: { type: boolean, description: "True if DNS response was replaced with NXDOMAIN" }
      reason: { type: string, nullable: true, description: "Reason for blocking (blocklist match, etc.)" }

  process_monitor:
    model_class: ProcessTelemetry
    field_map: member
    status: active
    fields:
      process_name: { type: string, description: "Process name from /proc" }
      process_uid: { type: int, description: "Linux UID of the process" }
      package_name: { type: string, nullable: true, description: "Android package name if resolvable" }
      is_foreground: { type: boolean, description: "True if process is in foreground" }

  file_scanner:
    model_class: FileArtifactTelemetry
    field_map: member
    status: active
    fields:
      file_path: { type: string, description: "Absolute path to the file" }
      file_exists: { type: boolean, description: "True if the file exists at scan time" }
      file_size: { type: long, nullable: true, description: "File size in bytes" }
      file_modified: { type: long, nullable: true, description: "Last modified timestamp (epoch ms)" }

  receiver_audit:
    model_class: ReceiverTelemetry
    field_map: member
    status: active
    fields:
      package_name: { type: string, description: "Package declaring the receiver" }
      intent_action: { type: string, description: "Intent action the receiver listens for" }
      component_name: { type: string, description: "Fully qualified receiver class name" }
      is_system_app: { type: boolean, description: "True if declaring app is a system app" }

  accessibility_audit:
    model_class: AccessibilityTelemetry
    field_map: member
    status: active
    fields:
      package_name: { type: string, description: "Package declaring the accessibility service" }
      service_name: { type: string, description: "Fully qualified service class name" }
      is_system_app: { type: boolean, description: "True if declaring app is a system app" }
      is_enabled: { type: boolean, description: "True if the service is currently enabled" }

  appops_audit:
    model_class: AppOpsTelemetry
    field_map: member
    status: active
    fields:
      package_name: { type: string, description: "Package the operation belongs to" }
      operation: { type: string, description: "AppOps operation name (e.g., android:camera)" }
      last_access_time: { type: long, description: "Epoch ms of last access" }
      last_reject_time: { type: long, description: "Epoch ms of last rejection" }
      access_count: { type: int, description: "Total access count" }
      is_system_app: { type: boolean, description: "True if app is a system app" }

  network_monitor:
    model_class: NetworkTelemetry
    field_map: member
    status: unwired  # toFieldMap() exists but NO evaluate method in SigmaRuleEngine — rules cannot fire
    fields:
      destination_ip: { type: string, description: "Destination IP address" }
      destination_port: { type: int, description: "Destination port number" }
      protocol: { type: string, description: "Protocol (TCP/UDP)" }
      app_uid: { type: int, description: "UID of the app making the connection" }
      app_name: { type: string, nullable: true, description: "Package name of the connecting app" }
      timestamp: { type: long, description: "Connection timestamp (epoch ms)" }

  # ── Extension-function toFieldMap() (TelemetryFieldMaps.kt) ────────

  tombstone_parser:
    model_class: TombstoneEvent
    field_map: extension  # internal fun TombstoneEvent.toFieldMap() in com.androdr.sigma
    status: active
    fields:
      process_name: { type: string, description: "Crashed process name" }
      package_name: { type: string, nullable: true, description: "Package name if resolvable" }
      signal_number: { type: int, nullable: true, description: "Signal that caused the crash" }
      abort_message: { type: string, nullable: true, description: "Abort message from the crash" }
      crash_timestamp: { type: long, description: "When the crash occurred (epoch ms)" }
      source: { type: string, description: "TelemetrySource enum name (LIVE_SCAN or BUGREPORT_IMPORT)" }
      captured_at: { type: long, description: "When this telemetry was captured (epoch ms)" }

  wakelock_parser:
    model_class: WakelockAcquisition
    field_map: extension
    status: active
    fields:
      package_name: { type: string, description: "Package holding the wakelock" }
      wakelock_tag: { type: string, description: "Wakelock tag string" }
      acquired_at: { type: long, description: "When the wakelock was acquired (epoch ms)" }
      duration_millis: { type: long, nullable: true, description: "How long the wakelock was held" }
      source: { type: string, description: "TelemetrySource enum name" }
      captured_at: { type: long, description: "When this telemetry was captured (epoch ms)" }

  battery_daily:
    model_class: BatteryDailyEvent
    field_map: extension
    status: active
    fields:
      day_index: { type: int, description: "Day offset in the battery stats history" }
      event_type: { type: string, description: "Battery event type" }
      package_name: { type: string, nullable: true, description: "Package associated with the event" }
      description: { type: string, description: "Human-readable event description" }
      source: { type: string, description: "TelemetrySource enum name" }
      captured_at: { type: long, description: "When this telemetry was captured (epoch ms)" }

  package_install_history:
    model_class: PackageInstallHistoryEntry
    field_map: extension
    status: active
    fields:
      package_name: { type: string, description: "Installed/updated/uninstalled package name" }
      event_type: { type: string, description: "INSTALL, UNINSTALL, or UPDATE" }
      timestamp: { type: long, description: "When the event occurred (epoch ms)" }
      version_code: { type: long, nullable: true, description: "Version code at time of event" }
      source: { type: string, description: "TelemetrySource enum name" }
      captured_at: { type: long, description: "When this telemetry was captured (epoch ms)" }

  platform_compat:
    model_class: PlatformCompatChange
    field_map: extension
    status: active
    fields:
      change_id: { type: string, description: "Platform compatibility change ID" }
      package_name: { type: string, description: "Package affected by the change" }
      enabled: { type: boolean, description: "Whether the compat change is enabled" }
      source: { type: string, description: "TelemetrySource enum name" }
      captured_at: { type: long, description: "When this telemetry was captured (epoch ms)" }

  db_info:
    model_class: DatabasePathObservation
    field_map: extension
    status: active
    fields:
      file_path: { type: string, description: "Absolute path to the database file" }
      process_name: { type: string, nullable: true, description: "Process that owns the database" }
      package_name: { type: string, nullable: true, description: "Package that owns the database" }
      observation_timestamp: { type: long, description: "When the database was observed (epoch ms)" }
      source: { type: string, description: "TelemetrySource enum name" }
      captured_at: { type: long, description: "When this telemetry was captured (epoch ms)" }
```

- [ ] **Step 2: Commit in submodule**

```bash
cd third-party/android-sigma-rules
git add validation/logsource-taxonomy.yml
git commit -m "feat: add logsource field taxonomy for Rule Author

All 15 services with toFieldMap() implementations, including:
- status: active/unwired per service
- field names matching map keys (not Kotlin property names)
- derived fields (e.g., unpatched_cve_id)
- nullable annotations"
cd ../..
```

- [ ] **Step 3: Bump submodule pointer**

```bash
git add third-party/android-sigma-rules
git commit -m "build: bump android-sigma-rules submodule (logsource taxonomy)"
```

---

### Task 4: Update `validate-rule.py` service whitelist

**Files:**
- Modify: `third-party/android-sigma-rules/validation/validate-rule.py:63-68`

- [ ] **Step 1: Update the valid_services set**

Replace lines 63-68 in `validate-rule.py`:

```python
    valid_services = {
        "app_scanner", "device_auditor", "dns_monitor",
        "process_monitor", "file_scanner",
        "receiver_audit", "tombstone_parser",
        "accessibility", "appops", "network_monitor",
    }
```

with:

```python
    valid_services = {
        "app_scanner", "device_auditor", "dns_monitor",
        "process_monitor", "file_scanner",
        "receiver_audit", "accessibility_audit", "appops_audit",
        "network_monitor", "tombstone_parser", "wakelock_parser",
        "battery_daily", "package_install_history",
        "platform_compat", "db_info",
    }
```

- [ ] **Step 2: Run validator against an existing rule to verify**

```bash
cd third-party/android-sigma-rules
python3 validation/validate-rule.py ../app/src/main/res/raw/sigma_androdr_accessibility_active.yml
```

Expected: `PASS: sigma_androdr_accessibility_active.yml` (this rule uses `accessibility_audit` service, which was previously missing but now accepted)

- [ ] **Step 3: Commit in submodule**

```bash
git add validation/validate-rule.py
git commit -m "fix: update valid_services whitelist to match runtime

- accessibility → accessibility_audit
- appops → appops_audit
- Add: wakelock_parser, battery_daily, package_install_history,
  platform_compat, db_info
- Total: 15 services matching SigmaRuleEngine evaluate methods"
cd ../..
```

- [ ] **Step 4: Bump submodule pointer**

```bash
git add third-party/android-sigma-rules
git commit -m "build: bump android-sigma-rules submodule (validate-rule.py service fix)"
```

---

### Task 5: Write `LogsourceTaxonomyCrossCheckTest.kt`

**Files:**
- Create: `app/src/test/java/com/androdr/sigma/LogsourceTaxonomyCrossCheckTest.kt`

- [ ] **Step 1: Write the test**

Create `app/src/test/java/com/androdr/sigma/LogsourceTaxonomyCrossCheckTest.kt`:

```kotlin
package com.androdr.sigma

import com.androdr.data.model.*
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Build-time cross-check: validates that logsource-taxonomy.yml field lists
 * match the actual toFieldMap() output for every service.
 *
 * Must be in com.androdr.sigma package for internal extension function visibility.
 */
class LogsourceTaxonomyCrossCheckTest {

    private fun taxonomyFile(): File? {
        val candidates = listOf(
            File("third-party/android-sigma-rules/validation/logsource-taxonomy.yml"),
            File("../third-party/android-sigma-rules/validation/logsource-taxonomy.yml"),
            File("/home/yasir/AndroDR/third-party/android-sigma-rules/validation/logsource-taxonomy.yml"),
        )
        return candidates.firstOrNull { it.isFile }
    }

    @Suppress("UNCHECKED_CAST")
    private fun loadTaxonomy(): Map<String, Map<String, Any?>> {
        val file = taxonomyFile()!!
        val yaml = Load(LoadSettings.builder().build())
        val root = yaml.loadFromString(file.readText()) as Map<String, Any?>
        return root["services"] as Map<String, Map<String, Any?>>
    }

    private fun taxonomyFieldNames(serviceEntry: Map<String, Any?>): Set<String> {
        @Suppress("UNCHECKED_CAST")
        val fields = serviceEntry["fields"] as? Map<String, Any?> ?: emptyMap()
        return fields.keys
    }

    /**
     * Build the map of service name → actual toFieldMap() keys from Kotlin code.
     * Member functions are called on dummy instances; extension functions are
     * called via imports from com.androdr.sigma (this package).
     */
    private fun actualFieldMaps(): Map<String, Set<String>> = mapOf(
        "app_scanner" to AppTelemetry(
            packageName = "x", appName = "x", certHash = null, apkHash = null,
            isSystemApp = false, fromTrustedStore = false, installer = null,
            isSideloaded = false, isKnownOemApp = false, permissions = emptyList(),
            surveillancePermissionCount = 0, hasAccessibilityService = false,
            hasDeviceAdmin = false, knownAppCategory = null,
            source = TelemetrySource.LIVE_SCAN,
        ).toFieldMap().keys,

        "device_auditor" to DeviceTelemetry(
            checkId = "x", isTriggered = false,
            source = TelemetrySource.LIVE_SCAN,
        ).toFieldMap().keys,

        "dns_monitor" to DnsEvent(
            timestamp = 0L, domain = "x", appUid = 0, appName = null,
            isBlocked = false, reason = null,
        ).toFieldMap().keys,

        "process_monitor" to ProcessTelemetry(
            processName = "x", processUid = 0, packageName = null,
            isForeground = false, source = TelemetrySource.LIVE_SCAN,
        ).toFieldMap().keys,

        "file_scanner" to FileArtifactTelemetry(
            filePath = "x", fileExists = false, fileSize = null,
            fileModified = null, source = TelemetrySource.LIVE_SCAN,
        ).toFieldMap().keys,

        "receiver_audit" to ReceiverTelemetry(
            packageName = "x", intentAction = "x", componentName = "x",
            isSystemApp = false, source = TelemetrySource.LIVE_SCAN,
        ).toFieldMap().keys,

        "accessibility_audit" to AccessibilityTelemetry(
            packageName = "x", serviceName = "x", isSystemApp = false,
            isEnabled = false, source = TelemetrySource.LIVE_SCAN,
        ).toFieldMap().keys,

        "appops_audit" to AppOpsTelemetry(
            packageName = "x", operation = "x", lastAccessTime = 0L,
            lastRejectTime = 0L, accessCount = 0, isSystemApp = false,
            source = TelemetrySource.LIVE_SCAN,
        ).toFieldMap().keys,

        "network_monitor" to NetworkTelemetry(
            destinationIp = "x", destinationPort = 0, protocol = "TCP",
            appUid = 0, appName = null, timestamp = 0L,
        ).toFieldMap().keys,

        // Extension functions (internal, visible because we're in com.androdr.sigma)
        "tombstone_parser" to TombstoneEvent(
            processName = "x", packageName = null, signalNumber = null,
            abortMessage = null, crashTimestamp = 0L,
            source = TelemetrySource.BUGREPORT_IMPORT, capturedAt = 0L,
        ).toFieldMap().keys,

        "wakelock_parser" to WakelockAcquisition(
            packageName = "x", wakelockTag = "x", acquiredAt = 0L,
            durationMillis = null, source = TelemetrySource.BUGREPORT_IMPORT,
            capturedAt = 0L,
        ).toFieldMap().keys,

        "battery_daily" to BatteryDailyEvent(
            dayIndex = 0, eventType = "x", packageName = null,
            description = "x", source = TelemetrySource.BUGREPORT_IMPORT,
            capturedAt = 0L,
        ).toFieldMap().keys,

        "package_install_history" to PackageInstallHistoryEntry(
            packageName = "x", eventType = PackageHistoryEventType.INSTALL,
            timestamp = 0L, versionCode = null,
            source = TelemetrySource.BUGREPORT_IMPORT, capturedAt = 0L,
        ).toFieldMap().keys,

        "platform_compat" to PlatformCompatChange(
            changeId = "x", packageName = "x", enabled = false,
            source = TelemetrySource.BUGREPORT_IMPORT, capturedAt = 0L,
        ).toFieldMap().keys,

        "db_info" to DatabasePathObservation(
            filePath = "x", processName = null, packageName = null,
            observationTimestamp = 0L, source = TelemetrySource.BUGREPORT_IMPORT,
            capturedAt = 0L,
        ).toFieldMap().keys,
    )

    @Test
    fun `taxonomy file is reachable from submodule`() {
        val file = taxonomyFile()
        assertTrue(
            "logsource-taxonomy.yml not found. Run: git submodule update --init",
            file != null && file.isFile,
        )
    }

    @Test
    fun `taxonomy field names match toFieldMap output for every service`() {
        val file = taxonomyFile()
        assumeTrue(
            "Skipping: logsource-taxonomy.yml not found (submodule not initialized).",
            file != null && file.isFile,
        )

        val taxonomy = loadTaxonomy()
        val actual = actualFieldMaps()
        val failures = mutableListOf<String>()

        // Check every service in actual has a taxonomy entry
        for ((service, actualKeys) in actual) {
            val entry = taxonomy[service]
            if (entry == null) {
                failures += "$service: missing from taxonomy YAML"
                continue
            }
            val taxonomyKeys = taxonomyFieldNames(entry)
            val extraInKotlin = actualKeys - taxonomyKeys
            val extraInTaxonomy = taxonomyKeys - actualKeys
            if (extraInKotlin.isNotEmpty()) {
                failures += "$service: fields in Kotlin toFieldMap() but missing from taxonomy: $extraInKotlin"
            }
            if (extraInTaxonomy.isNotEmpty()) {
                failures += "$service: fields in taxonomy but missing from Kotlin toFieldMap(): $extraInTaxonomy"
            }
        }

        // Check for taxonomy services not covered by actual
        val untested = taxonomy.keys - actual.keys
        if (untested.isNotEmpty()) {
            failures += "Taxonomy services with no Kotlin cross-check: $untested"
        }

        if (failures.isNotEmpty()) {
            fail(
                "Taxonomy cross-check FAILED:\n" +
                    failures.joinToString("\n") { "  - $it" } + "\n\n" +
                    "If you added/removed a field in toFieldMap(), update " +
                    "logsource-taxonomy.yml in the android-sigma-rules submodule."
            )
        }
    }

    @Test
    fun `taxonomy service count matches expected`() {
        val file = taxonomyFile()
        assumeTrue(
            "Skipping: logsource-taxonomy.yml not found.",
            file != null && file.isFile,
        )

        val taxonomy = loadTaxonomy()
        val actual = actualFieldMaps()
        assertEquals(
            "Taxonomy service count must match Kotlin toFieldMap() count",
            actual.size,
            taxonomy.size,
        )
    }
}
```

- [ ] **Step 2: Run the test**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.sigma.LogsourceTaxonomyCrossCheckTest"`
Expected: all 3 tests PASS

- [ ] **Step 3: Commit**

```bash
git add app/src/test/java/com/androdr/sigma/LogsourceTaxonomyCrossCheckTest.kt
git commit -m "test: add logsource taxonomy cross-check test

Validates logsource-taxonomy.yml field names match toFieldMap() output
for all 15 services (9 member functions + 6 extension functions).
Fails the build if taxonomy drifts from Kotlin runtime."
```

---

### Task 6: Update threat researcher skill

**Files:**
- Modify: `.claude/commands/update-rules-research-threat.md`

- [ ] **Step 1: Add structured source definition and verification rule**

In `.claude/commands/update-rules-research-threat.md`, replace step 3 (the "Cross-reference" section):

```markdown
3. **Cross-reference** IOCs across sources. For each IOC:
   - Found in 2+ sources: `confidence: "high"`
   - Found in 1 structured source (abuse.ch, NVD): `confidence: "high"`
   - Found in 1 unstructured source only (blog post): `confidence: "medium"`
   - Mentioned vaguely without exact value: DO NOT include, set note in description
```

with:

```markdown
3. **Cross-reference** IOCs across sources and classify source type:

   **Structured sources** (machine-parseable feeds from `allowed-sources.json`):
   `stalkerware-indicators`, `malwarebazaar`, `threatfox`, `amnesty-investigations`,
   `citizenlab-indicators`, `mvt-indicators`, `virustotal`, `android-security-bulletin`

   **Unstructured sources**: blog posts, vendor reports, news articles found via web search

   For each IOC:
   - Found in 2+ sources (any type): `confidence: "high"`
   - Found in 1 structured source: `confidence: "high"`
   - Found in 1 unstructured source only: `confidence: "medium"`
   - Mentioned vaguely without exact value: DO NOT include, set note in description
```

- [ ] **Step 2: Add SIR-level requires_verification rule**

In the same file, replace the "Rules" section at the bottom:

```markdown
## Rules

- NEVER generate SIGMA rules — only SIRs
- NEVER invent, guess, or extrapolate IOCs. If a blog post says "the malware contacts a C2 server" but doesn't list the domain, do NOT make one up
- NEVER include IOCs from your training data — only from sources fetched during this session
- Tag every IOC with the source URL it came from (in the SIR description or a source_urls field)
- If you find no concrete IOCs, still return a SIR with behavioral_signals and a note explaining the gap
- Cross-referenced IOCs (2+ sources) are more valuable than single-source IOCs
```

with:

```markdown
## Rules

- NEVER generate SIGMA rules — only SIRs
- NEVER invent, guess, or extrapolate IOCs. If a blog post says "the malware contacts a C2 server" but doesn't list the domain, do NOT make one up
- NEVER include IOCs from your training data — only from sources fetched during this session
- Tag every IOC with the source URL it came from (in the SIR description or a source_urls field)
- If you find no concrete IOCs, still return a SIR with behavioral_signals and a note explaining the gap
- Cross-referenced IOCs (2+ sources) are more valuable than single-source IOCs
- **MANDATORY:** If a SIR is built entirely from a single unstructured source (one blog post, one vendor report with no corroborating feed data), set `"requires_verification": true` at the SIR top level. This signals the Rule Author to record an `ioc_confidence` decision for human review. Do NOT set this flag for SIRs built from structured feeds or corroborated by 2+ sources.
```

- [ ] **Step 3: Commit**

```bash
git add .claude/commands/update-rules-research-threat.md
git commit -m "feat(skill): add requires_verification gate to threat researcher

- Define structured vs unstructured source types
- SIR-level requires_verification flag for single-source IOCs
- Rule Author sees the flag and records ioc_confidence decision"
```

---

### Task 7: Update Rule Author skill

**Files:**
- Modify: `.claude/commands/update-rules-author.md`

- [ ] **Step 1: Add taxonomy reference to Rule Generation Strategy**

In `.claude/commands/update-rules-author.md`, after the "Rule Generation Strategy" heading and service table (after line 52), add:

```markdown
### Taxonomy Reference (MANDATORY)

Before writing any `detection:` block, consult the logsource field taxonomy at
`android-sigma-rules/validation/logsource-taxonomy.yml` for the target service.

- **Only use field names listed in the taxonomy.** If a field you need isn't there, record a `telemetry_gap` decision (see below) instead of guessing.
- **Services with `status: unwired`** have a data model but no rule engine wiring — rules targeting them cannot fire. Record a `telemetry_gap` decision instead of writing a rule.
- The orchestrator injects the relevant taxonomy fields into your context. If you don't see them, read the file directly as a fallback.
```

- [ ] **Step 2: Add ioc_confidence and telemetry_gap decision types**

In the same file, after the existing "Decision Flagging" format block (after line 114), add:

```markdown
### IOC Confidence Decisions

When a SIR has `requires_verification: true`, you MUST record a decision for each IOC you choose to include or skip:

```yaml
decisions:
  - rule_id: "androdr-NNN"
    field: "ioc_data"
    type: "ioc_confidence"
    chosen: "include"
    alternative: "skip — single unstructured source"
    reasoning: "Domain appears in blog post with detailed C2 analysis; behavioral context is strong"
```

Or to skip:

```yaml
decisions:
  - rule_id: null
    field: "ioc_data"
    type: "ioc_confidence"
    chosen: "skip"
    alternative: "include domain example.com from single blog post"
    reasoning: "Only mentioned in passing, no technical analysis confirming C2 role"
```

### Telemetry Gap Decisions

When the taxonomy lacks a field needed to detect a threat, or the target service has `status: unwired`:

```yaml
decisions:
  - rule_id: null
    field: "rule_creation"
    type: "telemetry_gap"
    chosen: "skip"
    alternative: "create rule using field 'battery_drain_rate'"
    reasoning: "SIR describes rapid battery drain detection but app_scanner has no battery_drain_rate field in taxonomy"
    missing_field: "battery_drain_rate"
    suggested_service: "app_scanner"
```

These decisions feed back into AndroDR's development roadmap — a structured signal for telemetry the AI pipeline wanted but doesn't exist yet.
```

- [ ] **Step 3: Commit**

```bash
git add .claude/commands/update-rules-author.md
git commit -m "feat(skill): add taxonomy reference and new decision types to Rule Author

- Mandatory taxonomy consultation before writing detection blocks
- ioc_confidence decision type for requires_verification SIRs
- telemetry_gap decision type for missing fields and unwired services"
```

---

### Task 8: Update orchestrator to inject taxonomy

**Files:**
- Modify: `.claude/commands/update-rules.md`

- [ ] **Step 1: Add taxonomy injection to Step 4**

In `.claude/commands/update-rules.md`, replace Step 4:

```markdown
## Step 4: Generate Rules

Pass all valid SIRs to the Rule Author agent (`update-rules-author`) along with:
- The next available rule ID
- 5 existing production rules as style examples (pick diverse services/types)
- The existing rule index (for dedup awareness)

The Rule Author returns a list of CandidateRule objects (YAML + decision manifest).
```

with:

```markdown
## Step 4: Generate Rules

**Before dispatching the Rule Author**, read the logsource field taxonomy:
1. Read `android-sigma-rules/validation/logsource-taxonomy.yml`
2. Identify which services are relevant based on the SIRs' `rule_hint` values:
   - `ioc_lookup` → `app_scanner` (package names), `dns_monitor` (domains)
   - `behavioral` → `app_scanner`, `accessibility_audit`, `appops_audit`, `receiver_audit`
   - `device_posture` → `device_auditor`
   - `network` → `dns_monitor`, `network_monitor`
   - `hybrid` → include all of the above
3. Extract the `fields:` blocks for the relevant services

Pass all valid SIRs to the Rule Author agent (`update-rules-author`) along with:
- The next available rule ID
- 5 existing production rules as style examples (pick diverse services/types)
- The existing rule index (for dedup awareness)
- **The extracted taxonomy field lists for relevant services** (injected into the prompt context so the Rule Author doesn't need to read the file itself)

The Rule Author returns a list of CandidateRule objects (YAML + decision manifest).
```

- [ ] **Step 2: Commit**

```bash
git add .claude/commands/update-rules.md
git commit -m "feat(skill): inject taxonomy into Rule Author context

Orchestrator pre-reads logsource-taxonomy.yml and passes relevant
field lists to the Rule Author, ensuring field accuracy without
relying on mid-generation file reads."
```

---

### Task 9: Run tests and verify build

**Files:** none (verification only)

- [ ] **Step 1: Run all unit tests**

Run: `./gradlew testDebugUnitTest`
Expected: BUILD SUCCESSFUL, all tests pass including the new `LogsourceTaxonomyCrossCheckTest`

- [ ] **Step 2: Run lint**

Run: `./gradlew lintDebug`
Expected: no new warnings from our changes

- [ ] **Step 3: Verify no remaining amnesty-tech references**

Run: `grep -r "amnesty-tech" . --include="*.json" --include="*.yml" --include="*.yaml" --include="*.md" | grep -v ".git/"`
Expected: no output (or only historical references in plan/spec docs)

---

### Task 10: Validation re-run A — feed ingester path

**Files:** none (pipeline validation)

- [ ] **Step 1: Run stalkerware feed**

Run: `/update-rules source stalkerware`

- [ ] **Step 2: Verify dimension 1 (field accuracy)**

Check the Rule Author output: every `detection:` block field name should appear in
`logsource-taxonomy.yml` for the target service. If any field is out-of-taxonomy,
the taxonomy instruction failed.

- [ ] **Step 3: Verify dimension 3 (decision manifest)**

Check whether `telemetry_gap` decisions appear in the output. If the SIR describes
behaviors requiring fields not in the taxonomy, the Rule Author should have recorded
a `telemetry_gap` decision rather than guessing a field name.

- [ ] **Step 4: Record comparison notes**

Note any differences from the Bundle 1c run. Commit notes in the final PR
description.

---

### Task 11: Validation re-run B — threat research path

**Files:** none (pipeline validation)

- [ ] **Step 1: Run threat research**

Run: `/update-rules threat "<recently reported Android banking trojan>"`

Pick a real threat with recent blog coverage (e.g., a banking trojan reported in
the last 3 months). The researcher will web-search and produce SIRs from blog posts.

- [ ] **Step 2: Verify dimension 2 (IOC confidence)**

Check the researcher output: any SIR built from a single blog post should have
`"requires_verification": true`. Check the Rule Author output: it should have
`ioc_confidence` decisions for those SIRs.

- [ ] **Step 3: Verify dimensions 1 and 3**

Same checks as re-run A: field accuracy against taxonomy, `telemetry_gap` decisions
where appropriate.

- [ ] **Step 4: Record comparison notes and commit**

```bash
git commit --allow-empty -m "docs: record validation re-run results (#108)

Re-run A (stalkerware feed): [summary]
Re-run B (threat research): [summary]
All three dimensions verified."
```

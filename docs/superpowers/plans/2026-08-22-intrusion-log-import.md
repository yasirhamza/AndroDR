# Intrusion Log Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Import and analyze Android 16 Advanced Protection Intrusion Logging ZIP exports (dns_event / connect_event / security_event JSONL), evaluated by SIGMA rules and persisted to the forensic timeline.

**Architecture:** A sibling analyzer beside the bugreport pipeline: an artifact sniffer routes the existing import screen's ZIP to either `BugReportAnalyzer` (unchanged) or a new `IntrusionLogAnalyzer` whose per-type parsers are pure emitters. Connect events wire the reserved-but-stranded `network_monitor` logsource end-to-end; security events get a new `security_log` service. Events persist as `ForensicTimelineEvent` rows with `TelemetrySource.INTRUSION_LOG_IMPORT` and replace-on-reimport semantics.

**Tech Stack:** Kotlin, Hilt, Room, kotlinx.serialization (JSON), JUnit4 + MockK, Compose (Material3), git submodule `third-party/android-sigma-rules`.

**Spec:** `docs/superpowers/specs/2026-08-22-intrusion-log-import-design.md` (read it first; this plan implements it). Issue: #342. Spec PR: #343.

## Global Constraints

- JDK 21 required (`java -version` must report 21.x) before any `./gradlew` command.
- Unit tests: `./gradlew testDebugUnitTest`. Lint: `./gradlew lintDebug`. Detekt runs in CI's build check — keep functions under its length limits (split long methods as the codebase does).
- **Pure-emitter contract:** no new code outside `SigmaRuleEvaluator.kt` may construct `Finding(` or `.copy(level = …)` — `PureEmitterContractTest` scans all of `app/src/main` and fails the build. Telemetry types must not declare `severity`/`level`/`priority` properties or field-map keys.
- **Safe ordering (CLAUDE.md):** the taxonomy/schema edits land on an `android-sigma-rules` branch first; the AndroDR PR bumps the submodule to that **branch commit**; only after AndroDR CI is green does the rules branch merge to main, and the submodule is then re-pointed at the main commit. The `submodule-check` CI job goes RED mid-ordering **by design**; `build-and-test` is the real gate.
- All work on branch `feat/342-intrusion-log-import` off current `main`. Never push to main; PR body must contain `Closes #342`.
- Rules-repo work on branch `feat/security-log-service` in the rules repo (working checkout: `third-party/android-sigma-rules/` in the main AndroDR checkout `/home/yasir/AndroDR`, or a fresh clone). Rules-repo PRs need a green `validate` check before merge. No `rules.sha256` regen (taxonomy/schema are not listed in `rules.txt`).
- The sample record format (verified against a real export + MVT docs — see spec §3): JSONL, wrapper key per line, `event_id` monotonic counter shared across types, epoch-ms `event_time`, IP literals prefixed `/`, `connect_event` has NO protocol field.
- Starter detection rules are OUT of scope for this plan — they go through the update-rules pipeline with per-candidate human review later. This plan ships the wiring; existing `dns_monitor` rules fire on imported DNS events with zero rule changes.

---

### Task 1: Rules-repo taxonomy + schema edits (branch `feat/security-log-service`)

**Files:**
- Modify: `third-party/android-sigma-rules/validation/logsource-taxonomy.yml` (the `network_monitor` service entry, and a new `security_log` entry after the extension-function group)
- Modify: `third-party/android-sigma-rules/validation/rule-schema.json` (the `logsource.properties.service.enum` array)

**Interfaces:**
- Produces: taxonomy `network_monitor.status: active` with fields `destination_ip, destination_port, protocol (nullable), app_uid, app_name, timestamp, source, captured_at`; new service `security_log` with fields `timestamp, tag, tag_name, security_data, source, captured_at`; schema enum gains `"security_log"` (`"network_monitor"` is already present). Tasks 3–4 make the Kotlin side match these exact field sets.

- [ ] **Step 1: Create the branch in the rules repo**

```bash
cd /home/yasir/AndroDR/third-party/android-sigma-rules
git fetch origin && git checkout -b feat/security-log-service origin/main
```

- [ ] **Step 2: Edit `validation/logsource-taxonomy.yml`**

Replace the whole `network_monitor:` entry (currently `status: unwired` with a trailing comment) with:

```yaml
  network_monitor:
    model_class: NetworkTelemetry
    field_map: member
    status: active
    fields:
      destination_ip: { kind: raw_fact, type: string, description: "Destination IP address" }
      destination_port: { kind: raw_fact, type: int, description: "Destination port number" }
      protocol: { kind: raw_fact, type: string, nullable: true, description: "Protocol (TCP/UDP); null for Intrusion Logging imports, where the source genuinely does not record it" }
      app_uid: { kind: raw_fact, type: int, description: "UID of the app making the connection (-1 if unresolvable)" }
      app_name: { kind: raw_fact, type: string, nullable: true, description: "Package name of the connecting app (hint, not identity — shared-UID components smear)" }
      timestamp: { kind: raw_fact, type: long, description: "Connection timestamp (epoch ms)" }
      source: { kind: raw_fact, type: string, description: "TelemetrySource enum name (INTRUSION_LOG_IMPORT for imported logs)" }
      captured_at: { kind: raw_fact, type: long, description: "When this telemetry was captured/imported (epoch ms)" }
```

After the last extension-function service entry (`db_info:`), add:

```yaml
  security_log:
    model_class: SecurityLogEvent
    field_map: extension  # internal fun SecurityLogEvent.toFieldMap() in com.androdr.sigma
    status: active
    fields:
      timestamp: { kind: raw_fact, type: long, description: "Event time (epoch ms)" }
      tag: { kind: raw_fact, type: int, description: "Numeric android.app.admin.SecurityLog tag" }
      tag_name: { kind: raw_fact, type: string, description: "Registry-resolved tag name (e.g. adb_shell_cmd); unknown_<tag> for unmapped tags" }
      security_data: { kind: raw_fact, type: list, description: "Tag-specific value array, emitted verbatim as strings (emitter-emits-all-facts; typed per-tag extraction deferred until real fixtures validate layouts — spec §11.1)" }
      source: { kind: raw_fact, type: string, description: "TelemetrySource enum name" }
      captured_at: { kind: raw_fact, type: long, description: "When this telemetry was captured/imported (epoch ms)" }
```

- [ ] **Step 3: Edit `validation/rule-schema.json`**

In `properties.logsource.properties.service.enum`, insert `"security_log"` keeping the list alphabetically sorted (between `"receiver_audit"` and `"timeline"`). Do NOT add `network_monitor` — it is already there.

- [ ] **Step 4: Sanity-check YAML/JSON parse**

```bash
python3 -c "import yaml,json; yaml.safe_load(open('validation/logsource-taxonomy.yml')); json.load(open('validation/rule-schema.json')); print('OK')"
```
Expected: `OK`

- [ ] **Step 5: Commit and push the rules branch**

```bash
git add validation/logsource-taxonomy.yml validation/rule-schema.json
git commit -m "feat(taxonomy): activate network_monitor + add security_log service (AndroDR #342)"
git push -u origin feat/security-log-service
git rev-parse HEAD   # note this SHA — Task 2 pins the submodule to it
```

---

### Task 2: AndroDR feature branch + submodule bump

**Files:**
- Modify: submodule pointer `third-party/android-sigma-rules` (gitlink only)

**Interfaces:**
- Consumes: the rules-branch SHA from Task 1 Step 5.
- Produces: branch `feat/342-intrusion-log-import` whose pinned taxonomy has the Task 1 content. `LogsourceTaxonomyCrossCheckTest` is now RED — that failure is the driving test for Tasks 3–4.

- [ ] **Step 1: Create the AndroDR branch off current main**

```bash
cd /home/yasir/AndroDR && git fetch origin main
git checkout -b feat/342-intrusion-log-import origin/main
git submodule update --init
```

- [ ] **Step 2: Pin the submodule to the rules branch commit**

```bash
cd third-party/android-sigma-rules && git fetch origin && git checkout <SHA-from-task-1> && cd ../..
git add third-party/android-sigma-rules
```

- [ ] **Step 3: Run the taxonomy cross-check — verify it FAILS for the right reason**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.LogsourceTaxonomyCrossCheckTest"
```
Expected: FAIL with `Taxonomy services with no Kotlin cross-check: [security_log]`, a service-count mismatch, and `network_monitor: fields in taxonomy but missing from Kotlin toFieldMap(): [source, captured_at]`. Any OTHER failure means Task 1's edit is wrong — fix it there first.

- [ ] **Step 4: Commit the bump**

```bash
git commit -m "build(submodule): pin to feat/security-log-service (network_monitor active + security_log) — #342"
```

---

### Task 3: `TelemetrySource.INTRUSION_LOG_IMPORT` + `NetworkTelemetry` completion

**Files:**
- Modify: `app/src/main/java/com/androdr/data/model/TelemetrySource.kt`
- Modify: `app/src/main/java/com/androdr/data/model/NetworkTelemetry.kt`
- Modify: `app/src/test/java/com/androdr/sigma/LogsourceTaxonomyCrossCheckTest.kt` (the `network_monitor` dummy constructor, ~line 128)

**Interfaces:**
- Produces: `TelemetrySource.INTRUSION_LOG_IMPORT`; `NetworkTelemetry(destinationIp: String, destinationPort: Int, protocol: String?, appUid: Int, appName: String?, timestamp: Long, source: TelemetrySource, capturedAt: Long)` with `toFieldMap()` emitting exactly the Task 1 taxonomy keys. Consumed by Tasks 5, 6, 8, 9.

- [ ] **Step 1: Add the enum value**

In `TelemetrySource.kt`, after `BUGREPORT_IMPORT,` add:

```kotlin
    /**
     * Produced by parsing an imported Android Advanced Protection
     * Intrusion Logging export (#342). Import-only — the platform offers
     * no app-read API for this stream.
     */
    INTRUSION_LOG_IMPORT,
```

(Enum values are stored by name via the Room converter — no DB migration.)

- [ ] **Step 2: Rewrite `NetworkTelemetry.kt`**

```kotlin
package com.androdr.data.model

data class NetworkTelemetry(
    val destinationIp: String,
    val destinationPort: Int,
    /** Null when the source does not record it (Intrusion Logging imports). */
    val protocol: String?,
    val appUid: Int,
    val appName: String?,
    val timestamp: Long,
    val source: TelemetrySource,
    val capturedAt: Long
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "destination_ip" to destinationIp,
        "destination_port" to destinationPort,
        "protocol" to protocol,
        "app_uid" to appUid,
        "app_name" to appName,
        "timestamp" to timestamp,
        "source" to source.name,
        "captured_at" to capturedAt
    )
}
```

- [ ] **Step 3: Fix the cross-check dummy**

In `LogsourceTaxonomyCrossCheckTest.kt`, replace the `"network_monitor" to NetworkTelemetry(...)` entry with:

```kotlin
        "network_monitor" to NetworkTelemetry(
            destinationIp = "x", destinationPort = 0, protocol = null,
            appUid = 0, appName = null, timestamp = 0L,
            source = TelemetrySource.LIVE_SCAN, capturedAt = 0L,
        ).toFieldMap().keys,
```

- [ ] **Step 4: Run the cross-check — network_monitor lines gone, security_log remains**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.LogsourceTaxonomyCrossCheckTest"
```
Expected: still FAIL, but ONLY with the `security_log` no-cross-check line and the count mismatch (Task 4 clears those). Also run `--tests "com.androdr.sigma.PureEmitterContractTest"` — expected PASS (`NetworkTelemetry.kt` is already in `expectedEmitterFiles`; no severity-shaped fields added).

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/data/model/TelemetrySource.kt app/src/main/java/com/androdr/data/model/NetworkTelemetry.kt app/src/test/java/com/androdr/sigma/LogsourceTaxonomyCrossCheckTest.kt
git commit -m "feat(model): INTRUSION_LOG_IMPORT source + complete NetworkTelemetry emitter (#342)"
```

---

### Task 4: `SecurityLogEvent` model + tag registry + field-map extension

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/SecurityLogEvent.kt`
- Create: `app/src/main/java/com/androdr/scanner/intrusionlog/SecurityLogTagRegistry.kt`
- Modify: `app/src/main/java/com/androdr/sigma/TelemetryFieldMaps.kt` (append one extension)
- Modify: `app/src/test/java/com/androdr/sigma/LogsourceTaxonomyCrossCheckTest.kt` (add `security_log` to `extensionFunctionFieldMaps`)
- Test: `app/src/test/java/com/androdr/scanner/intrusionlog/SecurityLogTagRegistryTest.kt`

**Interfaces:**
- Produces: `SecurityLogEvent(timestamp: Long, tag: Int, tagName: String, securityData: List<String>, source: TelemetrySource, capturedAt: Long)`; `SecurityLogTagRegistry.nameFor(tag: Int): String`; `internal fun SecurityLogEvent.toFieldMap(): Map<String, Any?>`. Consumed by Tasks 5, 6, 8, 9.

- [ ] **Step 1: Write the failing registry test**

```kotlin
package com.androdr.scanner.intrusionlog

import android.app.admin.SecurityLog
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityLogTagRegistryTest {

    @Test
    fun `known tags resolve to snake_case names`() {
        assertEquals("adb_shell_cmd", SecurityLogTagRegistry.nameFor(SecurityLog.TAG_ADB_SHELL_CMD))
        assertEquals("adb_shell_interactive", SecurityLogTagRegistry.nameFor(SecurityLog.TAG_ADB_SHELL_INTERACTIVE))
        assertEquals("app_process_start", SecurityLogTagRegistry.nameFor(SecurityLog.TAG_APP_PROCESS_START))
        assertEquals("keyguard_dismissed", SecurityLogTagRegistry.nameFor(SecurityLog.TAG_KEYGUARD_DISMISSED))
        assertEquals("cert_authority_installed", SecurityLogTagRegistry.nameFor(SecurityLog.TAG_CERT_AUTHORITY_INSTALLED))
    }

    @Test
    fun `unknown tag falls back to unknown_N and is never dropped`() {
        assertEquals("unknown_999999", SecurityLogTagRegistry.nameFor(999999))
    }

    @Test
    fun `registry names are unique`() {
        val names = SecurityLogTagRegistry.allNames()
        assertTrue(names.size == names.toSet().size)
    }
}
```

- [ ] **Step 2: Run it to make sure it fails**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.scanner.intrusionlog.SecurityLogTagRegistryTest"
```
Expected: compilation FAILURE (`SecurityLogTagRegistry` unresolved).

- [ ] **Step 3: Write the model and registry**

`SecurityLogEvent.kt`:

```kotlin
package com.androdr.data.model

/**
 * One Advanced Protection Intrusion Logging security_event record (#342).
 * `securityData` is the tag-specific value array emitted verbatim — typed
 * per-tag extraction is deferred until real fixtures validate the layouts
 * (spec 2026-08-22-intrusion-log-import §11.1).
 */
data class SecurityLogEvent(
    val timestamp: Long,
    val tag: Int,
    val tagName: String,
    val securityData: List<String>,
    val source: TelemetrySource,
    val capturedAt: Long
)
```

`SecurityLogTagRegistry.kt` — `SecurityLog.TAG_*` are compile-time int constants (inlined; no runtime API-level dependency). If any constant below does not resolve against compileSdk 34, DELETE that single entry and its test assertion rather than hardcoding a numeric literal:

```kotlin
package com.androdr.scanner.intrusionlog

import android.app.admin.SecurityLog

/** Maps android.app.admin.SecurityLog numeric tags to stable snake_case names. */
object SecurityLogTagRegistry {

    private val names: Map<Int, String> = mapOf(
        SecurityLog.TAG_ADB_SHELL_INTERACTIVE to "adb_shell_interactive",
        SecurityLog.TAG_ADB_SHELL_CMD to "adb_shell_cmd",
        SecurityLog.TAG_SYNC_RECV_FILE to "sync_recv_file",
        SecurityLog.TAG_SYNC_SEND_FILE to "sync_send_file",
        SecurityLog.TAG_APP_PROCESS_START to "app_process_start",
        SecurityLog.TAG_KEYGUARD_DISMISSED to "keyguard_dismissed",
        SecurityLog.TAG_KEYGUARD_DISMISS_AUTH_ATTEMPT to "keyguard_dismiss_auth_attempt",
        SecurityLog.TAG_KEYGUARD_SECURED to "keyguard_secured",
        SecurityLog.TAG_OS_STARTUP to "os_startup",
        SecurityLog.TAG_OS_SHUTDOWN to "os_shutdown",
        SecurityLog.TAG_LOGGING_STARTED to "logging_started",
        SecurityLog.TAG_LOGGING_STOPPED to "logging_stopped",
        SecurityLog.TAG_MEDIA_MOUNT to "media_mount",
        SecurityLog.TAG_MEDIA_UNMOUNT to "media_unmount",
        SecurityLog.TAG_LOG_BUFFER_SIZE_CRITICAL to "log_buffer_size_critical",
        SecurityLog.TAG_PASSWORD_EXPIRATION_SET to "password_expiration_set",
        SecurityLog.TAG_PASSWORD_COMPLEXITY_SET to "password_complexity_set",
        SecurityLog.TAG_PASSWORD_HISTORY_LENGTH_SET to "password_history_length_set",
        SecurityLog.TAG_MAX_SCREEN_LOCK_TIMEOUT_SET to "max_screen_lock_timeout_set",
        SecurityLog.TAG_MAX_PASSWORD_ATTEMPTS_SET to "max_password_attempts_set",
        SecurityLog.TAG_KEYGUARD_DISABLED_FEATURES_SET to "keyguard_disabled_features_set",
        SecurityLog.TAG_REMOTE_LOCK to "remote_lock",
        SecurityLog.TAG_WIPE_FAILURE to "wipe_failure",
        SecurityLog.TAG_KEY_GENERATED to "key_generated",
        SecurityLog.TAG_KEY_IMPORT to "key_import",
        SecurityLog.TAG_KEY_DESTRUCTION to "key_destruction",
        SecurityLog.TAG_USER_RESTRICTION_ADDED to "user_restriction_added",
        SecurityLog.TAG_USER_RESTRICTION_REMOVED to "user_restriction_removed",
        SecurityLog.TAG_CERT_AUTHORITY_INSTALLED to "cert_authority_installed",
        SecurityLog.TAG_CERT_AUTHORITY_REMOVED to "cert_authority_removed",
        SecurityLog.TAG_CRYPTO_SELF_TEST_COMPLETED to "crypto_self_test_completed",
        SecurityLog.TAG_KEY_INTEGRITY_VIOLATION to "key_integrity_violation",
        SecurityLog.TAG_CERT_VALIDATION_FAILURE to "cert_validation_failure",
        SecurityLog.TAG_CAMERA_POLICY_SET to "camera_policy_set",
        SecurityLog.TAG_PASSWORD_CHANGED to "password_changed",
        SecurityLog.TAG_WIFI_CONNECTION to "wifi_connection",
        SecurityLog.TAG_WIFI_DISCONNECTION to "wifi_disconnection",
        SecurityLog.TAG_BLUETOOTH_CONNECTION to "bluetooth_connection",
        SecurityLog.TAG_BLUETOOTH_DISCONNECTION to "bluetooth_disconnection",
        SecurityLog.TAG_PACKAGE_INSTALLED to "package_installed",
        SecurityLog.TAG_PACKAGE_UPDATED to "package_updated",
        SecurityLog.TAG_PACKAGE_UNINSTALLED to "package_uninstalled",
    )

    fun nameFor(tag: Int): String = names[tag] ?: "unknown_$tag"

    fun allNames(): Collection<String> = names.values
}
```

Append to `TelemetryFieldMaps.kt` (add `import com.androdr.data.model.SecurityLogEvent` to its imports):

```kotlin
internal fun SecurityLogEvent.toFieldMap(): Map<String, Any?> = mapOf(
    "timestamp" to timestamp,
    "tag" to tag,
    "tag_name" to tagName,
    "security_data" to securityData,
    "source" to source.name,
    "captured_at" to capturedAt,
)
```

- [ ] **Step 4: Add the cross-check entry**

In `LogsourceTaxonomyCrossCheckTest.kt`, add `import com.androdr.data.model.SecurityLogEvent` and append to `extensionFunctionFieldMaps()`:

```kotlin
        "security_log" to SecurityLogEvent(
            timestamp = 0L, tag = 0, tagName = "x", securityData = emptyList(),
            source = TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt = 0L,
        ).toFieldMap().keys,
```

- [ ] **Step 5: Run registry test + both gates to verify they pass**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.scanner.intrusionlog.SecurityLogTagRegistryTest" --tests "com.androdr.sigma.LogsourceTaxonomyCrossCheckTest" --tests "com.androdr.sigma.PureEmitterContractTest"
```
Expected: all PASS. The taxonomy cross-check going green here is the completion of the Task 2 red state. (PureEmitter's emitter-file set is unchanged: the extension lives in `TelemetryFieldMaps.kt`, already classified.)

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/data/model/SecurityLogEvent.kt app/src/main/java/com/androdr/scanner/intrusionlog/ app/src/main/java/com/androdr/sigma/TelemetryFieldMaps.kt app/src/test/java/com/androdr/sigma/LogsourceTaxonomyCrossCheckTest.kt app/src/test/java/com/androdr/scanner/intrusionlog/
git commit -m "feat(model): SecurityLogEvent + tag registry + security_log field map (#342)"
```

---

### Task 5: Rule-engine evaluators for `network_monitor` and `security_log`

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt` (two methods after `evaluateDatabasePathObservations`, ~line 296)
- Test: `app/src/test/java/com/androdr/sigma/NetworkEvaluationTest.kt`
- Test: `app/src/test/java/com/androdr/sigma/SecurityLogEvaluationTest.kt`

**Interfaces:**
- Consumes: `NetworkTelemetry` (Task 3), `SecurityLogEvent` + `toFieldMap()` (Task 4).
- Produces: `fun evaluateNetwork(telemetry: List<NetworkTelemetry>): List<Finding>` and `fun evaluateSecurityLog(telemetry: List<SecurityLogEvent>): List<Finding>` on `SigmaRuleEngine`. Consumed by Task 8.

- [ ] **Step 1: Write the failing tests** (pattern copied from `DnsEvaluationTest` — evaluator-level, no engine instance needed for rule-match tests; engine-method tests use the class)

`NetworkEvaluationTest.kt`:

```kotlin
package com.androdr.sigma

import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkEvaluationTest {

    private fun connect(ip: String, port: Int, pkg: String?) = NetworkTelemetry(
        destinationIp = ip, destinationPort = port, protocol = null,
        appUid = -1, appName = pkg, timestamp = 1787400345540L,
        source = TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt = 0L,
    )

    @Test
    fun `toFieldMap exposes taxonomy keys`() {
        val fields = connect("34.160.125.113", 443, "com.example").toFieldMap()
        assertEquals("34.160.125.113", fields["destination_ip"])
        assertEquals(443, fields["destination_port"])
        assertEquals(null, fields["protocol"])
        assertEquals("INTRUSION_LOG_IMPORT", fields["source"])
    }

    @Test
    fun `network_monitor rule fires on destination port`() {
        val ruleYaml = """
            title: ADB over TCP connect
            id: androdr-test-net
            status: experimental
            description: Test
            category: incident
            logsource:
                product: androdr
                service: network_monitor
            detection:
                selection:
                    destination_port: 5555
                condition: selection
            level: medium
            tags:
                - attack.t1021
        """.trimIndent()
        val rule = SigmaRuleParser.parse(ruleYaml)!!
        val records = listOf(
            connect("192.168.1.7", 5555, "com.evil").toFieldMap(),
            connect("142.250.200.163", 443, "com.google.android.gms").toFieldMap(),
        )
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(rule), records, "network_monitor", emptyMap(), emptyMap()
        )
        assertEquals(1, findings.count { it.triggered })
    }

    @Test
    fun `engine evaluateNetwork routes through network_monitor service`() {
        // Method existence + service-string test: an engine with zero rules
        // returns no findings but must not throw.
        val engine = SigmaRuleEngine(io.mockk.mockk(relaxed = true))
        assertTrue(engine.evaluateNetwork(listOf(connect("1.2.3.4", 80, null))).isEmpty())
    }
}
```

`SecurityLogEvaluationTest.kt`:

```kotlin
package com.androdr.sigma

import com.androdr.data.model.SecurityLogEvent
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityLogEvaluationTest {

    private fun event(tagName: String, data: List<String>) = SecurityLogEvent(
        timestamp = 1787400345540L, tag = 210002, tagName = tagName,
        securityData = data, source = TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt = 0L,
    )

    @Test
    fun `security_log rule fires on tag_name`() {
        val ruleYaml = """
            title: ADB shell command observed
            id: androdr-test-sec
            status: experimental
            description: Test
            category: incident
            logsource:
                product: androdr
                service: security_log
            detection:
                selection:
                    tag_name: adb_shell_cmd
                condition: selection
            level: low
            tags:
                - attack.t1059
        """.trimIndent()
        val rule = SigmaRuleParser.parse(ruleYaml)!!
        val records = listOf(
            event("adb_shell_cmd", listOf("pm install /data/local/tmp/x.apk")).toFieldMap(),
            event("keyguard_dismissed", emptyList()).toFieldMap(),
        )
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(rule), records, "security_log", emptyMap(), emptyMap()
        )
        assertEquals(1, findings.count { it.triggered })
    }

    @Test
    fun `engine evaluateSecurityLog exists and tolerates empty rules`() {
        val engine = SigmaRuleEngine(io.mockk.mockk(relaxed = true))
        assertTrue(engine.evaluateSecurityLog(listOf(event("adb_shell_cmd", emptyList()))).isEmpty())
    }
}
```

Note: mirror how `SigmaRuleEngineTest.kt` constructs its engine (`SigmaRuleEngine(mockContext)`, ~line 30) — if that test builds the mock differently (e.g. a shared helper), copy its exact construction instead of `io.mockk.mockk(relaxed = true)`.

- [ ] **Step 2: Run to verify failure**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.NetworkEvaluationTest" --tests "com.androdr.sigma.SecurityLogEvaluationTest"
```
Expected: compilation FAILURE (`evaluateNetwork` / `evaluateSecurityLog` unresolved).

- [ ] **Step 3: Implement the two methods** (in `SigmaRuleEngine.kt`, directly after `evaluateDatabasePathObservations`; add imports `com.androdr.data.model.NetworkTelemetry` and `com.androdr.data.model.SecurityLogEvent`)

```kotlin
    fun evaluateNetwork(telemetry: List<NetworkTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(
            effectiveRules(), records, "network_monitor", iocLookups, evidenceProviders
        )
    }

    fun evaluateSecurityLog(telemetry: List<SecurityLogEvent>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(
            effectiveRules(), records, "security_log", iocLookups, evidenceProviders
        )
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Same command as Step 2. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt app/src/test/java/com/androdr/sigma/NetworkEvaluationTest.kt app/src/test/java/com/androdr/sigma/SecurityLogEvaluationTest.kt
git commit -m "feat(sigma): wire network_monitor + security_log evaluators (#342)"
```

---

### Task 6: `IntrusionLogParser` — JSONL → typed events

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/intrusionlog/IntrusionLogParser.kt`
- Test: `app/src/test/java/com/androdr/scanner/intrusionlog/IntrusionLogParserTest.kt`

**Interfaces:**
- Consumes: `SecurityLogTagRegistry.nameFor` (Task 4), `TelemetrySource.INTRUSION_LOG_IMPORT` (Task 3).
- Produces:
  - `data class ImportedDnsEvent(val event: DnsEvent, val resolvedIps: List<String>)`
  - `data class ParsedIntrusionLog(val dnsEvents: List<ImportedDnsEvent>, val networkEvents: List<NetworkTelemetry>, val securityEvents: List<SecurityLogEvent>, val duplicatesCollapsed: Int, val malformedLines: Int)`
  - `class IntrusionLogParser { fun parse(lines: Sequence<String>, uidResolver: (String) -> Int, capturedAt: Long): ParsedIntrusionLog }`
  - Consumed by Task 8. Dedup on `event_id`, first-seen, ACROSS the whole sequence (the caller concatenates all files' lines into one sequence, so cross-file dedup is inherent).

- [ ] **Step 1: Write the failing tests**

```kotlin
package com.androdr.scanner.intrusionlog

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class IntrusionLogParserTest {

    // Real (sanitized) lines from a 2026-08-22 Samsung Android 17 export.
    private val dnsLine = """{"dns_event":{"event_id":0,"event_time":1787400345334,"package_name":"com.samsung.android.intellivoiceservice","hostname":"scs-apne2.bixbyllm.com","ip_addresses":["/34.160.125.113"],"ip_addresses_count":1}}"""
    private val connectLine = """{"connect_event":{"event_id":1,"event_time":1787400345540,"package_name":"com.samsung.android.intellivoiceservice","port":443,"ip_address":"/34.160.125.113"}}"""
    private val securityLine = """{"security_event":{"event_id":2,"event_time":1787400345600,"tag":210002,"data":["pm list packages"]}}"""

    private fun parse(vararg lines: String) =
        IntrusionLogParser().parse(lines.asSequence(), uidResolver = { 10042 }, capturedAt = 999L)

    @Test
    fun `routes wrapper keys to the three event types`() {
        val result = parse(dnsLine, connectLine, securityLine)
        assertEquals(1, result.dnsEvents.size)
        assertEquals(1, result.networkEvents.size)
        assertEquals(1, result.securityEvents.size)
        assertEquals(0, result.malformedLines)
    }

    @Test
    fun `dns_event maps to DnsEvent with resolved ips stripped of slash prefix`() {
        val dns = parse(dnsLine).dnsEvents.single()
        assertEquals("scs-apne2.bixbyllm.com", dns.event.domain)
        assertEquals("com.samsung.android.intellivoiceservice", dns.event.appName)
        assertEquals(10042, dns.event.appUid)
        assertEquals(1787400345334L, dns.event.timestamp)
        assertEquals(false, dns.event.isBlocked)
        assertEquals(null, dns.event.reason)
        assertEquals(listOf("34.160.125.113"), dns.resolvedIps)
    }

    @Test
    fun `connect_event maps to NetworkTelemetry with null protocol`() {
        val net = parse(connectLine).networkEvents.single()
        assertEquals("34.160.125.113", net.destinationIp)
        assertEquals(443, net.destinationPort)
        assertEquals(null, net.protocol)
        assertEquals("com.samsung.android.intellivoiceservice", net.appName)
        assertEquals(999L, net.capturedAt)
    }

    @Test
    fun `security_event resolves tag name via registry`() {
        val sec = parse(securityLine).securityEvents.single()
        assertEquals(210002, sec.tag)
        assertEquals("adb_shell_cmd", sec.tagName)
        assertEquals(listOf("pm list packages"), sec.securityData)
    }

    @Test
    fun `byte-identical duplicate event_ids collapse first-seen`() {
        val result = parse(connectLine, connectLine)
        assertEquals(1, result.networkEvents.size)
        assertEquals(1, result.duplicatesCollapsed)
    }

    @Test
    fun `distinct events with same fields but different event_id are both kept`() {
        val second = connectLine.replace(""""event_id":1""", """"event_id":7""")
        val result = parse(connectLine, second)
        assertEquals(2, result.networkEvents.size)
        assertEquals(0, result.duplicatesCollapsed)
    }

    @Test
    fun `malformed lines are counted and skipped, never fatal`() {
        val result = parse("not json at all", """{"unknown_type":{"event_id":9}}""", dnsLine, "")
        assertEquals(1, result.dnsEvents.size)
        // blank lines are ignored silently; garbage + unknown wrapper count as malformed
        assertEquals(2, result.malformedLines)
    }

    @Test
    fun `uidResolver miss yields -1`() {
        val result = IntrusionLogParser().parse(
            sequenceOf(connectLine), uidResolver = { -1 }, capturedAt = 0L
        )
        assertEquals(-1, result.networkEvents.single().appUid)
    }

    @Test
    fun `security_event with non-string data values stringifies them`() {
        val line = """{"security_event":{"event_id":3,"event_time":1,"tag":210005,"data":["proc",123,true]}}"""
        val sec = parse(line).securityEvents.single()
        assertEquals(listOf("proc", "123", "true"), sec.securityData)
    }
}
```

- [ ] **Step 2: Run to verify failure**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.scanner.intrusionlog.IntrusionLogParserTest"
```
Expected: compilation FAILURE.

- [ ] **Step 3: Implement the parser** (kotlinx.serialization JSON — already a project dependency; `org.json` is unavailable in JVM unit tests, do not use it)

```kotlin
package com.androdr.scanner.intrusionlog

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.SecurityLogEvent
import com.androdr.data.model.TelemetrySource
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/** A dns_event record plus the resolved IPs the DnsEvent entity cannot carry. */
data class ImportedDnsEvent(
    val event: DnsEvent,
    val resolvedIps: List<String>
)

data class ParsedIntrusionLog(
    val dnsEvents: List<ImportedDnsEvent>,
    val networkEvents: List<NetworkTelemetry>,
    val securityEvents: List<SecurityLogEvent>,
    val duplicatesCollapsed: Int,
    val malformedLines: Int
)

/**
 * Parses Advanced Protection Intrusion Logging JSONL (#342, spec §3).
 * Pure emitter: emits every fact verbatim, constructs no findings.
 * Fail-soft per line; dedup on the type-shared monotonic event_id,
 * first-seen across the whole (multi-file) sequence.
 */
class IntrusionLogParser {

    private val json = Json { ignoreUnknownKeys = true }

    @Suppress("TooGenericExceptionCaught") // any per-line parse error means one malformed line, never a failed import
    fun parse(
        lines: Sequence<String>,
        uidResolver: (String) -> Int,
        capturedAt: Long
    ): ParsedIntrusionLog {
        val dns = mutableListOf<ImportedDnsEvent>()
        val net = mutableListOf<NetworkTelemetry>()
        val sec = mutableListOf<SecurityLogEvent>()
        val seenEventIds = HashSet<Long>()
        var duplicates = 0
        var malformed = 0

        for (rawLine in lines) {
            val line = rawLine.trim()
            if (line.isEmpty()) continue
            try {
                val root = json.parseToJsonElement(line).jsonObject
                val entry = root.entries.firstOrNull() ?: throw IllegalArgumentException("empty object")
                val body = entry.value.jsonObject
                val eventId = body["event_id"]!!.jsonPrimitive.long
                when (entry.key) {
                    "dns_event", "connect_event", "security_event" -> {
                        if (!seenEventIds.add(eventId)) { duplicates++; continue }
                    }
                    else -> throw IllegalArgumentException("unknown wrapper ${entry.key}")
                }
                val eventTime = body["event_time"]!!.jsonPrimitive.long
                when (entry.key) {
                    "dns_event" -> {
                        val pkg = body["package_name"]?.jsonPrimitive?.contentOrNull
                        dns += ImportedDnsEvent(
                            event = DnsEvent(
                                timestamp = eventTime,
                                domain = body["hostname"]!!.jsonPrimitive.content,
                                appUid = pkg?.let(uidResolver) ?: -1,
                                appName = pkg,
                                isBlocked = false,
                                reason = null
                            ),
                            resolvedIps = body["ip_addresses"]?.jsonArray
                                ?.map { stripIpPrefix(it.jsonPrimitive.content) }
                                .orEmpty()
                        )
                    }
                    "connect_event" -> {
                        val pkg = body["package_name"]?.jsonPrimitive?.contentOrNull
                        net += NetworkTelemetry(
                            destinationIp = stripIpPrefix(body["ip_address"]!!.jsonPrimitive.content),
                            destinationPort = body["port"]!!.jsonPrimitive.int,
                            protocol = null, // genuinely absent from the source (spec §3)
                            appUid = pkg?.let(uidResolver) ?: -1,
                            appName = pkg,
                            timestamp = eventTime,
                            source = TelemetrySource.INTRUSION_LOG_IMPORT,
                            capturedAt = capturedAt
                        )
                    }
                    "security_event" -> {
                        val tag = body["tag"]!!.jsonPrimitive.int
                        sec += SecurityLogEvent(
                            timestamp = eventTime,
                            tag = tag,
                            tagName = SecurityLogTagRegistry.nameFor(tag),
                            securityData = body["data"]?.jsonArray
                                ?.map { it.jsonPrimitive.content }
                                .orEmpty(),
                            source = TelemetrySource.INTRUSION_LOG_IMPORT,
                            capturedAt = capturedAt
                        )
                    }
                }
            } catch (e: Exception) {
                malformed++
            }
        }
        return ParsedIntrusionLog(dns, net, sec, duplicates, malformed)
    }

    /** Java InetAddress.toString() renders "hostname/literal"; exports show "/1.2.3.4". */
    private fun stripIpPrefix(raw: String): String = raw.substringAfterLast('/')
}
```

- [ ] **Step 4: Run tests to verify they pass**

Same command as Step 2. Expected: PASS. If the `jsonPrimitive.content` call on a non-string primitive behaves differently than the last test expects, adjust the implementation (e.g. `it.jsonPrimitive.content` already stringifies numbers/booleans in kotlinx.serialization) — the TEST's expectation is the contract.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/intrusionlog/IntrusionLogParser.kt app/src/test/java/com/androdr/scanner/intrusionlog/IntrusionLogParserTest.kt
git commit -m "feat(intrusionlog): JSONL parser with event_id dedup and fail-soft lines (#342)"
```

---

### Task 7: `ArtifactSniffer` — ZIP routing decision

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/ArtifactSniffer.kt`
- Test: `app/src/test/java/com/androdr/scanner/ArtifactSnifferTest.kt`

**Interfaces:**
- Produces: `enum class ArtifactType { BUG_REPORT, INTRUSION_LOG, UNRECOGNIZED }` and `object ArtifactSniffer { fun classify(entryNames: Sequence<String>): ArtifactType }`. Consumed by Task 9 (which feeds it ZIP entry names from the Uri).

- [ ] **Step 1: Write the failing tests**

```kotlin
package com.androdr.scanner

import org.junit.Assert.assertEquals
import org.junit.Test

class ArtifactSnifferTest {

    @Test
    fun `dumpstate entry wins as bug report`() {
        assertEquals(
            ArtifactType.BUG_REPORT,
            ArtifactSniffer.classify(sequenceOf("dumpstate.txt", "2026-08-22.txt"))
        )
    }

    @Test
    fun `bugreport-prefixed txt is a bug report`() {
        assertEquals(
            ArtifactType.BUG_REPORT,
            ArtifactSniffer.classify(sequenceOf("bugreport-crownqltesq-2026-08-22.txt"))
        )
    }

    @Test
    fun `per-day txt at top level is an intrusion log`() {
        assertEquals(
            ArtifactType.INTRUSION_LOG,
            ArtifactSniffer.classify(sequenceOf("2026-08-22.txt"))
        )
    }

    @Test
    fun `per-day txt one directory deep matches (androidqf layout)`() {
        assertEquals(
            ArtifactType.INTRUSION_LOG,
            ArtifactSniffer.classify(sequenceOf("intrusion-logs/2026-08-21.txt"))
        )
    }

    @Test
    fun `per-day txt nested deeper does not match`() {
        assertEquals(
            ArtifactType.UNRECOGNIZED,
            ArtifactSniffer.classify(sequenceOf("a/b/2026-08-21.txt"))
        )
    }

    @Test
    fun `random zip is unrecognized`() {
        assertEquals(
            ArtifactType.UNRECOGNIZED,
            ArtifactSniffer.classify(sequenceOf("photo.jpg", "notes.txt"))
        )
    }
}
```

- [ ] **Step 2: Run to verify failure** — `./gradlew testDebugUnitTest --tests "com.androdr.scanner.ArtifactSnifferTest"` → compilation FAILURE.

- [ ] **Step 3: Implement**

```kotlin
package com.androdr.scanner

enum class ArtifactType { BUG_REPORT, INTRUSION_LOG, UNRECOGNIZED }

/**
 * Classifies an imported ZIP by entry names alone (#342 spec §4.1).
 * Deliberately one `when` in one place, not a registry framework — this
 * routing point becomes the registry seed if a third artifact type arrives.
 */
object ArtifactSniffer {

    /** Advanced Protection per-day export file, e.g. 2026-08-22.txt. */
    private val intrusionLogEntry = Regex("""\d{4}-\d{2}-\d{2}\.txt""")

    fun classify(entryNames: Sequence<String>): ArtifactType {
        var sawIntrusionLog = false
        for (name in entryNames) {
            val base = name.substringAfterLast('/').lowercase()
            val isDumpstate = base == "dumpstate.txt" ||
                (base.startsWith("bugreport-") && base.endsWith(".txt"))
            if (isDumpstate) return ArtifactType.BUG_REPORT
            // Top level or one directory deep (covers androidqf's intrusion-logs/).
            if (intrusionLogEntry.matches(base) && name.count { it == '/' } <= 1) {
                sawIntrusionLog = true
            }
        }
        return if (sawIntrusionLog) ArtifactType.INTRUSION_LOG else ArtifactType.UNRECOGNIZED
    }
}
```

- [ ] **Step 4: Run tests to verify pass** — same command, expected PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/ArtifactSniffer.kt app/src/test/java/com/androdr/scanner/ArtifactSnifferTest.kt
git commit -m "feat(scanner): artifact sniffer routes bugreport vs intrusion-log zips (#342)"
```

---### Task 8: `IntrusionLogAnalyzer` — coordinator

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/IntrusionLogAnalyzer.kt`
- Test: `app/src/test/java/com/androdr/scanner/IntrusionLogAnalyzerTest.kt`

**Interfaces:**
- Consumes: `IntrusionLogParser`/`ParsedIntrusionLog`/`ImportedDnsEvent` (Task 6), `SigmaRuleEngine.evaluateDns/evaluateNetwork/evaluateSecurityLog` (Task 5).
- Produces (consumed by Tasks 9–11):

```kotlin
data class IntrusionLogStats(
    val dnsEventCount: Int, val connectEventCount: Int, val securityEventCount: Int,
    val duplicatesCollapsed: Int, val malformedLines: Int,
    val earliestEventMs: Long?, val latestEventMs: Long?,
)
data class IntrusionLogAnalysisResult(
    val findings: List<Finding>,
    val dnsEvents: List<ImportedDnsEvent>,
    val networkEvents: List<NetworkTelemetry>,
    val securityEvents: List<SecurityLogEvent>,
    val stats: IntrusionLogStats,
)
class IntrusionLogAnalyzer {
    suspend fun analyze(uri: Uri): IntrusionLogAnalysisResult
    internal fun analyzeEntries(entries: Sequence<Pair<String, java.io.InputStream>>, uidResolver: (String) -> Int, capturedAt: Long): IntrusionLogAnalysisResult
}
```

- [ ] **Step 1: Write the failing tests** (JVM-only via `analyzeEntries`; engine mocked with MockK)

```kotlin
package com.androdr.scanner

import com.androdr.sigma.SigmaRuleEngine
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayInputStream

class IntrusionLogAnalyzerTest {

    private val engine = mockk<SigmaRuleEngine>(relaxed = true) {
        every { evaluateDns(any()) } returns emptyList()
        every { evaluateNetwork(any()) } returns emptyList()
        every { evaluateSecurityLog(any()) } returns emptyList()
    }

    private fun entry(name: String, vararg lines: String) =
        name to ByteArrayInputStream(lines.joinToString("\n").toByteArray())

    private val day1Dns = """{"dns_event":{"event_id":0,"event_time":1787400345334,"package_name":"com.a","hostname":"h1.example.com","ip_addresses":["/1.1.1.1"],"ip_addresses_count":1}}"""
    private val day1Net = """{"connect_event":{"event_id":1,"event_time":1787400345540,"package_name":"com.a","port":443,"ip_address":"/1.1.1.1"}}"""
    private val day2NetDupe = day1Net // same event_id 1 — overlapping-file duplicate
    private val day2Sec = """{"security_event":{"event_id":2,"event_time":1787400350000,"tag":210002,"data":["id"]}}"""

    @Test
    fun `parses matching entries only, dedups across files, computes stats`() {
        val result = IntrusionLogAnalyzer(mockk(relaxed = true), engine).analyzeEntries(
            sequenceOf(
                entry("2026-08-21.txt", day1Dns, day1Net),
                entry("2026-08-22.txt", day2NetDupe, day2Sec),
                entry("intrusion-logs/2026-08-20.txt"),          // one dir deep: included (empty)
                entry("README.md", "not a log line"),            // non-matching: ignored entirely
            ),
            uidResolver = { -1 }, capturedAt = 42L,
        )
        assertEquals(1, result.stats.dnsEventCount)
        assertEquals(1, result.stats.connectEventCount)
        assertEquals(1, result.stats.securityEventCount)
        assertEquals(1, result.stats.duplicatesCollapsed)
        assertEquals(0, result.stats.malformedLines)
        assertEquals(1787400345334L, result.stats.earliestEventMs)
        assertEquals(1787400350000L, result.stats.latestEventMs)
    }

    @Test
    fun `evaluates all three streams through the engine`() {
        val analyzer = IntrusionLogAnalyzer(mockk(relaxed = true), engine)
        analyzer.analyzeEntries(
            sequenceOf(entry("2026-08-22.txt", day1Dns, day1Net, day2Sec)),
            uidResolver = { -1 }, capturedAt = 0L,
        )
        verify(exactly = 1) { engine.evaluateDns(match { it.size == 1 }) }
        verify(exactly = 1) { engine.evaluateNetwork(match { it.size == 1 }) }
        verify(exactly = 1) { engine.evaluateSecurityLog(match { it.size == 1 }) }
    }
}
```

- [ ] **Step 2: Run to verify failure** — `./gradlew testDebugUnitTest --tests "com.androdr.scanner.IntrusionLogAnalyzerTest"` → compilation FAILURE.

- [ ] **Step 3: Implement**

```kotlin
package com.androdr.scanner

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.util.Log
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.SecurityLogEvent
import com.androdr.scanner.intrusionlog.ImportedDnsEvent
import com.androdr.scanner.intrusionlog.IntrusionLogParser
import com.androdr.sigma.Finding
import com.androdr.sigma.SigmaRuleEngine
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.util.zip.ZipInputStream
import javax.inject.Inject
import javax.inject.Singleton

data class IntrusionLogStats(
    val dnsEventCount: Int,
    val connectEventCount: Int,
    val securityEventCount: Int,
    val duplicatesCollapsed: Int,
    val malformedLines: Int,
    val earliestEventMs: Long?,
    val latestEventMs: Long?
)

data class IntrusionLogAnalysisResult(
    val findings: List<Finding>,
    val dnsEvents: List<ImportedDnsEvent>,
    val networkEvents: List<NetworkTelemetry>,
    val securityEvents: List<SecurityLogEvent>,
    val stats: IntrusionLogStats
)

/**
 * Coordinator for Advanced Protection Intrusion Logging imports (#342).
 * Streams per-day JSONL entries out of the export ZIP, parses them into
 * typed telemetry (pure emitters), and evaluates SIGMA rules over the
 * COMPLETE parsed stream — persistence caps are applied later by the
 * orchestrator, never here (spec §7: detection sees everything).
 */
@Singleton
class IntrusionLogAnalyzer @Inject constructor(
    @ApplicationContext private val context: Context,
    private val sigmaRuleEngine: SigmaRuleEngine
) {
    // JVM unit tests construct this with a relaxed MockK Context — only
    // analyze(uri) touches it; analyzeEntries() is context-free by design.

    suspend fun analyze(uri: Uri): IntrusionLogAnalysisResult = withContext(Dispatchers.IO) {
        val uidCache = HashMap<String, Int>()
        val uidResolver: (String) -> Int = { pkg ->
            uidCache.getOrPut(pkg) {
                try {
                    context.packageManager.getPackageUid(pkg, 0)
                } catch (e: PackageManager.NameNotFoundException) {
                    -1
                }
            }
        }
        val stream = context.contentResolver.openInputStream(uri)
            ?: return@withContext emptyResult()
        stream.use { s ->
            ZipInputStream(s.buffered()).use { zip ->
                val entrySequence = sequence {
                    var entry = zip.nextEntry
                    while (entry != null) {
                        if (!entry.isDirectory) yield(entry.name to (zip as InputStream))
                        try { zip.closeEntry() } catch (_: Exception) { /* ignore */ }
                        entry = try { zip.nextEntry } catch (_: Exception) { null }
                    }
                }
                analyzeEntries(entrySequence, uidResolver, System.currentTimeMillis())
            }
        }
    }

    internal fun analyzeEntries(
        entries: Sequence<Pair<String, InputStream>>,
        uidResolver: (String) -> Int,
        capturedAt: Long
    ): IntrusionLogAnalysisResult {
        // One concatenated line sequence across all matching entries makes
        // cross-file event_id dedup inherent to a single parse() call.
        val lines = sequence {
            for ((name, input) in entries) {
                val base = name.substringAfterLast('/').lowercase()
                val matches = PER_DAY_ENTRY.matches(base) && name.count { it == '/' } <= 1
                if (!matches) continue
                // The ZipInputStream positions the shared stream at this
                // entry; consume it fully before the caller advances.
                input.bufferedReader().lineSequence().forEach { yield(it) }
            }
        }
        val parsed = IntrusionLogParser().parse(lines, uidResolver, capturedAt)

        val findings = buildList {
            addAll(sigmaRuleEngine.evaluateDns(parsed.dnsEvents.map { it.event }))
            addAll(sigmaRuleEngine.evaluateNetwork(parsed.networkEvents))
            addAll(sigmaRuleEngine.evaluateSecurityLog(parsed.securityEvents))
        }

        val allTimestamps = parsed.dnsEvents.asSequence().map { it.event.timestamp } +
            parsed.networkEvents.asSequence().map { it.timestamp } +
            parsed.securityEvents.asSequence().map { it.timestamp }
        val tsList = allTimestamps.toList()

        Log.d(
            TAG,
            "Parsed ${parsed.dnsEvents.size} dns / ${parsed.networkEvents.size} connect / " +
                "${parsed.securityEvents.size} security events " +
                "(${parsed.duplicatesCollapsed} dupes, ${parsed.malformedLines} malformed); " +
                "${findings.count { it.triggered }} findings"
        )

        return IntrusionLogAnalysisResult(
            findings = findings,
            dnsEvents = parsed.dnsEvents,
            networkEvents = parsed.networkEvents,
            securityEvents = parsed.securityEvents,
            stats = IntrusionLogStats(
                dnsEventCount = parsed.dnsEvents.size,
                connectEventCount = parsed.networkEvents.size,
                securityEventCount = parsed.securityEvents.size,
                duplicatesCollapsed = parsed.duplicatesCollapsed,
                malformedLines = parsed.malformedLines,
                earliestEventMs = tsList.minOrNull(),
                latestEventMs = tsList.maxOrNull()
            )
        )
    }

    private fun emptyResult() = IntrusionLogAnalysisResult(
        findings = emptyList(), dnsEvents = emptyList(), networkEvents = emptyList(),
        securityEvents = emptyList(),
        stats = IntrusionLogStats(0, 0, 0, 0, 0, null, null)
    )

    private companion object {
        private const val TAG = "IntrusionLogAnalyzer"
        private val PER_DAY_ENTRY = Regex("""\d{4}-\d{2}-\d{2}\.txt""")
    }
}
```

- [ ] **Step 4: Run tests to verify pass** — same command as Step 2. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/IntrusionLogAnalyzer.kt app/src/test/java/com/androdr/scanner/IntrusionLogAnalyzerTest.kt
git commit -m "feat(scanner): IntrusionLogAnalyzer streams, dedups, and evaluates the export (#342)"
```

---

### Task 9: Timeline adapters + orchestrator routing and persistence

**Files:**
- Modify: `app/src/main/java/com/androdr/data/db/TimelineAdapter.kt` (three new functions at the end)
- Modify: `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt` (`analyzeArtifact`, `analyzeIntrusionLog`, cap helper; inject `IntrusionLogAnalyzer`)
- Test: `app/src/test/java/com/androdr/data/db/IntrusionLogTimelineAdapterTest.kt`

**Interfaces:**
- Consumes: Task 8's result types; existing `ForensicTimelineEventDao.deleteBySource(source)`, `ScanRepository.saveScanWithCorrelation(scan, findingTimelineEvents, replaceUsageStatsEvents, lookbackEvents) { eventsWithIds -> ... }` (signature per the existing `analyzeBugReport` call at `ScanOrchestrator.kt:588`), `Finding.toForensicTimelineEvent(scanResult, isBugreport)` (TimelineAdapter).
- Produces: `ScanOrchestrator.analyzeArtifact(uri): ArtifactAnalysis` (sealed: `BugReport` / `IntrusionLog`), `UnrecognizedArtifactException`, timeline rows with `source = "intrusion_log"` (raw events) and `"intrusion_log_analysis"` (finding events), both `telemetrySource = INTRUSION_LOG_IMPORT`. Consumed by Task 10 (ViewModel) and Task 11 (report).

- [ ] **Step 1: Write the failing adapter tests**

```kotlin
package com.androdr.data.db

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.SecurityLogEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.scanner.intrusionlog.ImportedDnsEvent
import org.junit.Assert.assertEquals
import org.junit.Test

class IntrusionLogTimelineAdapterTest {

    @Test
    fun `imported dns event maps with unconditional dns correlation id`() {
        val row = ImportedDnsEvent(
            event = DnsEvent(
                timestamp = 5L, domain = "h.example.com", appUid = 100,
                appName = "com.a", isBlocked = false, reason = null
            ),
            resolvedIps = listOf("1.1.1.1", "2.2.2.2")
        ).toForensicTimelineEvent(scanResultId = 9L)
        assertEquals("intrusion_log", row.source)
        assertEquals("dns_query", row.category)
        assertEquals("dns:h.example.com", row.correlationId)
        assertEquals("resolved: 1.1.1.1, 2.2.2.2", row.details)
        assertEquals(TelemetrySource.INTRUSION_LOG_IMPORT, row.telemetrySource)
        assertEquals(9L, row.scanResultId)
        assertEquals(5L, row.startTimestamp)
    }

    @Test
    fun `connect event maps to network_connect with net correlation id`() {
        val row = NetworkTelemetry(
            destinationIp = "1.2.3.4", destinationPort = 853, protocol = null,
            appUid = -1, appName = "com.b", timestamp = 7L,
            source = TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt = 0L
        ).toForensicTimelineEvent(scanResultId = 9L)
        assertEquals("intrusion_log", row.source)
        assertEquals("network_connect", row.category)
        assertEquals("net:1.2.3.4:853", row.correlationId)
        assertEquals("com.b", row.packageName)
        assertEquals(7L, row.startTimestamp)
    }

    @Test
    fun `security event maps to security_event with sec correlation id`() {
        val row = SecurityLogEvent(
            timestamp = 3L, tag = 210002, tagName = "adb_shell_cmd",
            securityData = listOf("id"), source = TelemetrySource.INTRUSION_LOG_IMPORT,
            capturedAt = 0L
        ).toForensicTimelineEvent(scanResultId = 9L)
        assertEquals("intrusion_log", row.source)
        assertEquals("security_event", row.category)
        assertEquals("sec:210002", row.correlationId)
        assertEquals("Security: adb_shell_cmd", row.description)
        assertEquals("id", row.details)
    }
}
```

- [ ] **Step 2: Run to verify failure** — `./gradlew testDebugUnitTest --tests "com.androdr.data.db.IntrusionLogTimelineAdapterTest"` → compilation FAILURE.

- [ ] **Step 3: Add the adapters** (append to `TimelineAdapter.kt`; add imports for `NetworkTelemetry`, `SecurityLogEvent`, `TelemetrySource`, `ImportedDnsEvent`)

```kotlin
/** #342: imported Intrusion Logging dns_event → timeline row. Correlation id is
 *  stamped unconditionally (unlike the live path, which stamps only IOC matches)
 *  so dns_monitor findings on imported hostnames can join their raw evidence. */
fun ImportedDnsEvent.toForensicTimelineEvent(scanResultId: Long): ForensicTimelineEvent =
    event.toForensicTimelineEvent().copy(
        source = "intrusion_log",
        details = if (resolvedIps.isEmpty()) "" else "resolved: ${resolvedIps.joinToString(", ")}",
        correlationId = "dns:${event.domain}",
        scanResultId = scanResultId,
        telemetrySource = TelemetrySource.INTRUSION_LOG_IMPORT
    )

/** #342: imported Intrusion Logging connect_event → timeline row. */
fun NetworkTelemetry.toForensicTimelineEvent(scanResultId: Long): ForensicTimelineEvent =
    ForensicTimelineEvent(
        startTimestamp = timestamp,
        source = "intrusion_log",
        category = "network_connect",
        description = "Connect: $destinationIp:$destinationPort",
        packageName = appName ?: "",
        processUid = appUid,
        correlationId = "net:$destinationIp:$destinationPort",
        scanResultId = scanResultId,
        telemetrySource = source
    )

/** #342: imported Intrusion Logging security_event → timeline row. */
fun SecurityLogEvent.toForensicTimelineEvent(scanResultId: Long): ForensicTimelineEvent =
    ForensicTimelineEvent(
        startTimestamp = timestamp,
        source = "intrusion_log",
        category = "security_event",
        description = "Security: $tagName",
        details = securityData.joinToString(", "),
        correlationId = "sec:$tag",
        scanResultId = scanResultId,
        telemetrySource = source
    )
```

- [ ] **Step 4: Run adapter tests to verify pass** — same command as Step 2. Expected: PASS. Commit:

```bash
git add app/src/main/java/com/androdr/data/db/TimelineAdapter.kt app/src/test/java/com/androdr/data/db/IntrusionLogTimelineAdapterTest.kt
git commit -m "feat(timeline): adapters for imported intrusion-log events (#342)"
```

- [ ] **Step 5: Add orchestrator routing + persistence** (in `ScanOrchestrator.kt`; inject `private val intrusionLogAnalyzer: IntrusionLogAnalyzer` in the constructor; add imports for `ArtifactSniffer`, `ArtifactType`, `IntrusionLogAnalyzer`, `IntrusionLogAnalysisResult`, and the three adapter functions' types)

```kotlin
    class UnrecognizedArtifactException : Exception(
        "Not a recognized artifact: expected a bug report ZIP (dumpstate) or an " +
            "Advanced Protection intrusion log export (per-day YYYY-MM-DD.txt files)."
    )

    sealed interface ArtifactAnalysis {
        data class BugReport(val result: BugReportAnalyzer.BugReportAnalysisResult) : ArtifactAnalysis
        data class IntrusionLog(val result: IntrusionLogAnalysisResult) : ArtifactAnalysis
    }

    /** #342: single import entry point — sniff the ZIP, route to the right analyzer. */
    suspend fun analyzeArtifact(uri: Uri): ArtifactAnalysis = when (sniffArtifact(uri)) {
        ArtifactType.BUG_REPORT -> ArtifactAnalysis.BugReport(analyzeBugReport(uri))
        ArtifactType.INTRUSION_LOG -> ArtifactAnalysis.IntrusionLog(analyzeIntrusionLog(uri))
        ArtifactType.UNRECOGNIZED -> throw UnrecognizedArtifactException()
    }

    private suspend fun sniffArtifact(uri: Uri): ArtifactType = withContext(Dispatchers.IO) {
        val stream = context.contentResolver.openInputStream(uri)
            ?: return@withContext ArtifactType.UNRECOGNIZED
        stream.use { s ->
            java.util.zip.ZipInputStream(s.buffered()).use { zip ->
                val names = sequence {
                    var entry = zip.nextEntry
                    while (entry != null) {
                        if (!entry.isDirectory) yield(entry.name)
                        try { zip.closeEntry() } catch (_: Exception) { /* ignore */ }
                        entry = try { zip.nextEntry } catch (_: Exception) { null }
                    }
                }
                ArtifactSniffer.classify(names)
            }
        }
    }

    /**
     * #342: analyze an Advanced Protection Intrusion Logging export and persist
     * it. Replace-on-reimport: each import first deletes the previous import's
     * rows by source (spec §4.2). Rules saw the COMPLETE stream inside the
     * analyzer; only timeline persistence is capped (spec §7).
     */
    suspend fun analyzeIntrusionLog(uri: Uri): IntrusionLogAnalysisResult {
        initRuleEngine()
        val result = intrusionLogAnalyzer.analyze(uri)

        val now = System.currentTimeMillis()
        val scanResult = ScanResult(
            id = now,
            timestamp = now,
            findings = result.findings,
            bugReportFindings = emptyList(),
            riskySideloadCount = 0,
            knownMalwareCount = result.findings.count {
                it.level == "critical" && "known_malware" in it.impliesFlags
            },
            scannerErrors = emptyList()
        )

        val findingEvents = result.findings.filter { it.triggered }.map { finding ->
            finding.toForensicTimelineEvent(scanResult, isBugreport = true).copy(
                source = "intrusion_log_analysis",
                telemetrySource = com.androdr.data.model.TelemetrySource.INTRUSION_LOG_IMPORT,
                // network/security field maps carry "timestamp"; evaluator copies
                // scalar record fields into matchContext as strings.
                startTimestamp = finding.matchContext["timestamp"]?.toLongOrNull()
                    ?.takeIf { it > 0L } ?: 0L
            )
        }
        // Persistence caps (spec §7): security uncapped, DNS/connects newest-first.
        val cappedDns = result.dnsEvents.sortedByDescending { it.event.timestamp }.take(DNS_PERSIST_CAP)
        val cappedNet = result.networkEvents.sortedByDescending { it.timestamp }.take(CONNECT_PERSIST_CAP)
        val rawEvents =
            cappedDns.map { it.toForensicTimelineEvent(scanResult.id) } +
            cappedNet.map { it.toForensicTimelineEvent(scanResult.id) } +
            result.securityEvents.map { it.toForensicTimelineEvent(scanResult.id) }
        val allEvents = findingEvents + rawEvents

        // Replace-on-reimport, then persist with correlation (same transaction
        // shape as the bug-report path).
        forensicTimelineEventDao.deleteBySource("intrusion_log")
        forensicTimelineEventDao.deleteBySource("intrusion_log_analysis")
        val corrRules = sigmaRuleEngine.getCorrelationRules()
        runCatching {
            scanRepository.saveScanWithCorrelation(
                scan = scanResult,
                findingTimelineEvents = allEvents,
                replaceUsageStatsEvents = null,
                lookbackEvents = emptyList()
            ) { eventsWithIds ->
                if (corrRules.isEmpty() || eventsWithIds.isEmpty()) emptyList()
                else {
                    val bindings = sigmaRuleEngine.computeAtomBindings(eventsWithIds)
                    val atomRulesById = sigmaRuleEngine.getEnabledRules().associateBy { it.id }
                    sigmaCorrelationEngine.evaluate(corrRules, eventsWithIds, bindings, atomRulesById)
                        .map { it.copy(scanResultId = scanResult.id) }
                }
            }
        }.onFailure { Log.e(TAG, "Failed to persist intrusion log import", it) }

        return result
    }
```

Add to `ScanOrchestrator`'s companion object (Task 10's summary card reads these same constants):

```kotlin
        /** #342 spec §7: timeline persistence caps; rules always see the full stream. */
        const val DNS_PERSIST_CAP = 10_000
        const val CONNECT_PERSIST_CAP = 5_000
```

- [ ] **Step 6: Compile + run the touched suites**

```bash
./gradlew compileDebugKotlin testDebugUnitTest --tests "com.androdr.scanner.*" --tests "com.androdr.data.db.*"
```
Expected: BUILD SUCCESSFUL; all green. If `forensicTimelineEventDao` / `sigmaCorrelationEngine` / `scanRepository` are named differently in `ScanOrchestrator`'s constructor, match the existing names exactly (they all appear in the `analyzeBugReport` body at lines ~474–600).

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt
git commit -m "feat(scanner): artifact routing + intrusion-log persistence with caps and replace-on-reimport (#342)"
```

---

### Task 10: Import UI — ViewModel routing, summary card, timeline label

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/bugreport/BugReportViewModel.kt`
- Modify: `app/src/main/java/com/androdr/ui/bugreport/BugReportScreen.kt`
- Modify: `app/src/main/java/com/androdr/ui/timeline/TimelineViewModel.kt` (`ScanGroup.isFromBugreport` → `importSource`)
- Modify: `app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt` (~line 450 label `when`)
- Modify: `app/src/main/res/values/strings.xml` (one new string)

**Interfaces:**
- Consumes: `ScanOrchestrator.analyzeArtifact` + `ArtifactAnalysis` + `IntrusionLogStats` (Tasks 8–9).
- Produces: `BugReportViewModel.intrusionLogSummary: StateFlow<IntrusionLogStats?>`; `ScanGroup.importSource: TelemetrySource?` (replaces `isFromBugreport: Boolean` — update ALL usages).

- [ ] **Step 1: Route the ViewModel through `analyzeArtifact`**

In `BugReportViewModel`, add the state:

```kotlin
    private val _intrusionLogSummary = MutableStateFlow<IntrusionLogStats?>(null)
    val intrusionLogSummary: StateFlow<IntrusionLogStats?> = _intrusionLogSummary.asStateFlow()
```

(import `com.androdr.scanner.IntrusionLogStats`, `com.androdr.scanner.ScanOrchestrator` types). Replace the `try` block body of `analyzeUri` (currently `val result = orchestrator.analyzeBugReport(uri)` + two assignments) with:

```kotlin
                _intrusionLogSummary.value = null
                when (val analysis = orchestrator.analyzeArtifact(uri)) {
                    is ScanOrchestrator.ArtifactAnalysis.BugReport -> {
                        _findings.value = analysis.result.findings
                        _timeline.value = analysis.result.timeline
                    }
                    is ScanOrchestrator.ArtifactAnalysis.IntrusionLog -> {
                        _findings.value = analysis.result.findings.filter { it.triggered }
                        _timeline.value = emptyList()
                        _intrusionLogSummary.value = analysis.result.stats
                    }
                }
                _analysisFinished.value = true
```

(`UnrecognizedArtifactException` flows into the existing generic `catch` and renders its message on the error card — no extra handling needed.)

- [ ] **Step 2: Render the summary card in `BugReportScreen`**

Collect the state next to the existing ones (~line 74):

```kotlin
    val intrusionSummary by viewModel.intrusionLogSummary.collectAsStateWithLifecycle()
```

Inside the results `LazyColumn`, immediately before the findings items, add:

```kotlin
            intrusionSummary?.let { s ->
                item {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(
                                text = "Intrusion log analyzed",
                                style = MaterialTheme.typography.titleMedium
                            )
                            Text("DNS events: ${s.dnsEventCount}   Connections: ${s.connectEventCount}   Security events: ${s.securityEventCount}")
                            Text("Duplicates collapsed: ${s.duplicatesCollapsed}   Malformed lines skipped: ${s.malformedLines}")
                            val dnsCap = ScanOrchestrator.DNS_PERSIST_CAP
                            val netCap = ScanOrchestrator.CONNECT_PERSIST_CAP
                            if (s.dnsEventCount > dnsCap || s.connectEventCount > netCap) {
                                Text(
                                    "Timeline keeps the newest ${minOf(s.dnsEventCount, dnsCap)} of ${s.dnsEventCount} DNS " +
                                        "and ${minOf(s.connectEventCount, netCap)} of ${s.connectEventCount} connection events."
                                )
                            }
                            if (s.earliestEventMs != null && s.latestEventMs != null) {
                                val fmt = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.US)
                                Text("Covers ${fmt.format(java.util.Date(s.earliestEventMs))} → ${fmt.format(java.util.Date(s.latestEventMs))}")
                            }
                        }
                    }
                }
            }
```

Adapt spacing/color modifiers to match the neighbouring result cards in this file (copy the `CardDefaults.cardColors(...)` usage the existing cards at ~line 249/293 use).

- [ ] **Step 3: Timeline group label**

In `TimelineViewModel.kt`: change `ScanGroup`'s field `val isFromBugreport: Boolean` to `val importSource: com.androdr.data.model.TelemetrySource?`; at the two construction sites replace

```kotlin
                    isFromBugreport = scanEvents.any {
                        it.telemetrySource == com.androdr.data.model.TelemetrySource.BUGREPORT_IMPORT
                    },
```
with
```kotlin
                    importSource = scanEvents.firstOrNull {
                        it.telemetrySource != com.androdr.data.model.TelemetrySource.LIVE_SCAN
                    }?.telemetrySource,
```
and `isFromBugreport = false,` (~line 261) with `importSource = null,`.

In `TimelineEventCard.kt` (~line 450), replace the branch `group.isFromBugreport -> stringResource(R.string.timeline_scan_bugreport)` with:

```kotlin
        group.importSource == TelemetrySource.BUGREPORT_IMPORT ->
            stringResource(R.string.timeline_scan_bugreport)
        group.importSource == TelemetrySource.INTRUSION_LOG_IMPORT ->
            stringResource(R.string.timeline_scan_intrusion_log)
```

(add the `TelemetrySource` import). In `strings.xml`, next to `timeline_scan_bugreport`, add:

```xml
    <string name="timeline_scan_intrusion_log">Intrusion log import</string>
```

- [ ] **Step 4: Build + run unit tests**

```bash
./gradlew compileDebugKotlin testDebugUnitTest --tests "com.androdr.ui.*"
```
Expected: BUILD SUCCESSFUL, existing UI tests green (fix any other `isFromBugreport` references the compiler surfaces — the compiler is the authoritative list).

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/ui/ app/src/main/res/values/strings.xml
git commit -m "feat(ui): intrusion-log import summary + timeline import label (#342)"
```

---

### Task 11: Report section — INTRUSION LOG block

**Files:**
- Modify: `app/src/main/java/com/androdr/reporting/ReportFormatter.kt` (`formatScanReport` + `appendTelemetrySections` params; one new section)
- Modify: `app/src/main/java/com/androdr/reporting/ReportExporter.kt` (inject `ForensicTimelineEventDao`, fetch snapshot, pass through)
- Test: `app/src/test/java/com/androdr/reporting/IntrusionLogReportSectionTest.kt`

**Interfaces:**
- Consumes: `ForensicTimelineEventDao.getEventsBySource("intrusion_log", 500): Flow<List<ForensicTimelineEvent>>` (existing DAO), Task 9's persisted rows.
- Produces: `formatScanReport(..., intrusionEvents: List<ForensicTimelineEvent> = emptyList(), versionName: String)` — the new parameter goes directly before `versionName`, defaulted so existing callers compile unchanged.

- [ ] **Step 1: Write the failing test**

```kotlin
package com.androdr.reporting

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IntrusionLogReportSectionTest {

    private fun scan() = ScanResult(
        id = 1L, timestamp = 1787400345334L, findings = emptyList(),
        bugReportFindings = emptyList(), riskySideloadCount = 0, knownMalwareCount = 0
    )

    private fun row(category: String, description: String, pkg: String) = ForensicTimelineEvent(
        startTimestamp = 1787400345540L, source = "intrusion_log", category = category,
        description = description, packageName = pkg,
        telemetrySource = TelemetrySource.INTRUSION_LOG_IMPORT
    )

    @Test
    fun `intrusion events render a section with category, description and attribution`() {
        val text = ReportFormatter.formatScanReport(
            scan(), dnsEvents = emptyList(), logLines = emptyList(),
            intrusionEvents = listOf(
                row("network_connect", "Connect: 8.8.8.8:853", "com.samsung.wearable.watchuniteplugin"),
                row("security_event", "Security: adb_shell_cmd", "")
            ),
            versionName = "test"
        )
        assertTrue(text.contains("INTRUSION LOG"))
        assertTrue(text.contains("Connect: 8.8.8.8:853"))
        assertTrue(text.contains("com.samsung.wearable.watchuniteplugin"))
        assertTrue(text.contains("Security: adb_shell_cmd"))
    }

    @Test
    fun `no intrusion events - no section`() {
        val text = ReportFormatter.formatScanReport(
            scan(), dnsEvents = emptyList(), logLines = emptyList(), versionName = "test"
        )
        assertFalse(text.contains("INTRUSION LOG"))
    }

    @Test
    fun `findings-only mode omits the intrusion section`() {
        val text = ReportFormatter.formatScanReport(
            scan(), dnsEvents = emptyList(), logLines = emptyList(),
            mode = ExportMode.FINDINGS_ONLY,
            intrusionEvents = listOf(row("network_connect", "Connect: 1.2.3.4:80", "com.a")),
            versionName = "test"
        )
        assertFalse(text.contains("INTRUSION LOG"))
    }
}
```

If `ScanResult`'s constructor differs (e.g. requires `scannerErrors`), copy the construction style from an existing test in `app/src/test/java/com/androdr/reporting/`.

- [ ] **Step 2: Run to verify failure** — `./gradlew testDebugUnitTest --tests "com.androdr.reporting.IntrusionLogReportSectionTest"` → compilation FAILURE (no `intrusionEvents` parameter).

- [ ] **Step 3: Implement formatter + exporter changes**

`ReportFormatter.kt`: add `intrusionEvents: List<ForensicTimelineEvent> = emptyList(),` to `formatScanReport` (before `versionName`) and to `appendTelemetrySections` (at the end of its parameter list); pass it through at the call site inside `formatScanReport`; add the `ForensicTimelineEvent` import. In `appendTelemetrySections`, directly after the DNS-activity block:

```kotlin
        // -- Intrusion log (imported, #342) --------------------------------------
        if (intrusionEvents.isNotEmpty()) {
            section("INTRUSION LOG (imported, ${intrusionEvents.size} events)")
            val fullFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
            intrusionEvents.take(500).forEach { ev ->
                val time = fullFmt.format(Date(ev.startTimestamp))
                val app = ev.packageName.ifEmpty { "unknown" }
                appendLine("  $time  ${ev.description.padEnd(50)}  <- $app")
            }
        }
```

`ReportExporter.kt`: add `private val forensicTimelineEventDao: ForensicTimelineEventDao` to the constructor (import it plus `kotlinx.coroutines.flow.first`); in `export(...)` fetch and pass:

```kotlin
        val intrusionEvents = forensicTimelineEventDao
            .getEventsBySource("intrusion_log", 500).first()
```
and add `intrusionEvents = intrusionEvents,` to the `formatScanReport(...)` call.

- [ ] **Step 4: Run tests to verify pass**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.reporting.*"
```
Expected: new test PASS, existing reporting tests still green.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/reporting/ app/src/test/java/com/androdr/reporting/IntrusionLogReportSectionTest.kt
git commit -m "feat(report): INTRUSION LOG telemetry section from imported events (#342)"
```

---

### Task 12: End-to-end fixture test — ZIP → sniff → parse → rules fire

**Files:**
- Test: `app/src/test/java/com/androdr/scanner/intrusionlog/IntrusionLogEndToEndTest.kt`

**Interfaces:**
- Consumes: everything from Tasks 5–9. No production code changes — this task exists to prove the seams fit together and to encode the spec's E2E requirement (§10).

- [ ] **Step 1: Write the test (it should pass immediately — if it fails, a previous task has a real bug)**

```kotlin
package com.androdr.scanner.intrusionlog

import com.androdr.scanner.ArtifactSniffer
import com.androdr.scanner.ArtifactType
import com.androdr.scanner.IntrusionLogAnalyzer
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleEvaluator
import com.androdr.sigma.SigmaRuleParser
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

class IntrusionLogEndToEndTest {

    /** Build an export ZIP in memory: two per-day files with an overlapping event. */
    private fun exportZip(): ByteArray {
        val day1 = listOf(
            """{"dns_event":{"event_id":0,"event_time":1787400345334,"package_name":"com.evil.app","hostname":"api.flexispy.com","ip_addresses":["/34.160.125.113"],"ip_addresses_count":1}}""",
            """{"connect_event":{"event_id":1,"event_time":1787400345540,"package_name":"com.evil.app","port":5555,"ip_address":"/192.168.1.7"}}""",
        )
        val day2 = listOf(
            """{"connect_event":{"event_id":1,"event_time":1787400345540,"package_name":"com.evil.app","port":5555,"ip_address":"/192.168.1.7"}}""",
            """{"security_event":{"event_id":2,"event_time":1787400350000,"tag":210002,"data":["pm install /data/local/tmp/x.apk"]}}""",
        )
        val bytes = ByteArrayOutputStream()
        ZipOutputStream(bytes).use { zip ->
            for ((name, lines) in listOf("2026-08-21.txt" to day1, "2026-08-22.txt" to day2)) {
                zip.putNextEntry(ZipEntry(name))
                zip.write(lines.joinToString("\n").toByteArray())
                zip.closeEntry()
            }
        }
        return bytes.toByteArray()
    }

    private fun zipEntries(bytes: ByteArray) = sequence {
        val zip = ZipInputStream(ByteArrayInputStream(bytes))
        var entry = zip.nextEntry
        while (entry != null) {
            if (!entry.isDirectory) yield(entry.name to (zip as java.io.InputStream))
            zip.closeEntry()
            entry = zip.nextEntry
        }
    }

    @Test
    fun `sniffer classifies the export as an intrusion log`() {
        val names = zipEntries(exportZip()).map { it.first }.toList()
        assertEquals(ArtifactType.INTRUSION_LOG, ArtifactSniffer.classify(names.asSequence()))
    }

    @Test
    fun `full pipeline - parse, dedup, and fire rules on all three services`() {
        val dnsRule = SigmaRuleParser.parse("""
            title: Stalkerware C2 domain
            id: androdr-e2e-dns
            status: experimental
            description: Test
            category: incident
            logsource:
                product: androdr
                service: dns_monitor
            detection:
                selection:
                    domain|contains:
                        - flexispy.com
                condition: selection
            level: high
            tags:
                - attack.t1437
        """.trimIndent())!!
        val netRule = SigmaRuleParser.parse("""
            title: ADB over TCP connect
            id: androdr-e2e-net
            status: experimental
            description: Test
            category: incident
            logsource:
                product: androdr
                service: network_monitor
            detection:
                selection:
                    destination_port: 5555
                condition: selection
            level: medium
            tags:
                - attack.t1021
        """.trimIndent())!!
        val secRule = SigmaRuleParser.parse("""
            title: ADB shell command observed
            id: androdr-e2e-sec
            status: experimental
            description: Test
            category: incident
            logsource:
                product: androdr
                service: security_log
            detection:
                selection:
                    tag_name: adb_shell_cmd
                condition: selection
            level: low
            tags:
                - attack.t1059
        """.trimIndent())!!

        // Engine mock delegates to the real evaluator with the inline rules —
        // this keeps the test JVM-only while exercising real matching.
        val engine = mockk<SigmaRuleEngine>(relaxed = true)
        every { engine.evaluateDns(any()) } answers {
            SigmaRuleEvaluator.evaluate(
                listOf(dnsRule), firstArg<List<com.androdr.data.model.DnsEvent>>().map { it.toFieldMap() },
                "dns_monitor", emptyMap(), emptyMap()
            )
        }
        every { engine.evaluateNetwork(any()) } answers {
            SigmaRuleEvaluator.evaluate(
                listOf(netRule), firstArg<List<com.androdr.data.model.NetworkTelemetry>>().map { it.toFieldMap() },
                "network_monitor", emptyMap(), emptyMap()
            )
        }
        every { engine.evaluateSecurityLog(any()) } answers {
            SigmaRuleEvaluator.evaluate(
                listOf(secRule),
                firstArg<List<com.androdr.data.model.SecurityLogEvent>>().map {
                    // extension toFieldMap is internal to com.androdr.sigma —
                    // call through the engine-shaped helper below
                    securityFieldMap(it)
                },
                "security_log", emptyMap(), emptyMap()
            )
        }

        val result = IntrusionLogAnalyzer(null, engine).analyzeEntries(
            zipEntries(exportZip()), uidResolver = { -1 }, capturedAt = 0L
        )

        assertEquals(1, result.stats.dnsEventCount)
        assertEquals(1, result.stats.connectEventCount)      // event_id 1 deduped across files
        assertEquals(1, result.stats.securityEventCount)
        assertEquals(1, result.stats.duplicatesCollapsed)
        assertEquals(3, result.findings.count { it.triggered })
        assertTrue(result.findings.any { it.ruleId == "androdr-e2e-dns" && it.triggered })
        assertTrue(result.findings.any { it.ruleId == "androdr-e2e-net" && it.triggered })
        assertTrue(result.findings.any { it.ruleId == "androdr-e2e-sec" && it.triggered })
    }

    private fun securityFieldMap(e: com.androdr.data.model.SecurityLogEvent): Map<String, Any?> = mapOf(
        "timestamp" to e.timestamp, "tag" to e.tag, "tag_name" to e.tagName,
        "security_data" to e.securityData, "source" to e.source.name, "captured_at" to e.capturedAt,
    )
}
```

(If this test file lives outside `com.androdr.sigma`, it cannot call the internal `SecurityLogEvent.toFieldMap()` — the `securityFieldMap` mirror above is intentional and asserted equivalent by `LogsourceTaxonomyCrossCheckTest`. If `SigmaRuleEngine`'s constructor or the analyzer's constructor differ from Tasks 5/8 as landed, follow the landed code.)

- [ ] **Step 2: Run it**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.scanner.intrusionlog.IntrusionLogEndToEndTest"
```
Expected: PASS. A failure here is a real integration bug in Tasks 5–9 — debug there, do not weaken the assertions.

- [ ] **Step 3: Commit**

```bash
git add app/src/test/java/com/androdr/scanner/intrusionlog/IntrusionLogEndToEndTest.kt
git commit -m "test(intrusionlog): end-to-end fixture zip through sniffer, parser, and rules (#342)"
```

---

### Task 13: Docs — ARCHITECTURE section + privacy disclosure

**Files:**
- Modify: `docs/ARCHITECTURE.md` (new subsection in §8 "Bug-report analysis" area; entity table §5.1; module map)
- Modify: `docs/PRIVACY_POLICY.md` (one new disclosure paragraph)

**Interfaces:**
- Consumes: final landed behavior of Tasks 6–11 (write docs from the code, not from memory).

- [ ] **Step 1: ARCHITECTURE.md**

Add after the §8 bug-report flow description, a sibling subsection (match surrounding heading style):

```markdown
### 8.x Intrusion log import (#342)

Android 16's Advanced Protection → Intrusion Logging writes DNS, connection,
and security events that the user can export from Settings as a ZIP of
per-day `YYYY-MM-DD.txt` JSONL files. There is no app-read API — the logs
are E2E-encrypted and reachable only by user-initiated download — so AndroDR
supports them strictly as an import, through the same accept flow as bug
reports: `ArtifactSniffer` classifies the ZIP by entry names and routes to
`BugReportAnalyzer` (dumpstate entries) or `IntrusionLogAnalyzer` (per-day
entries, top-level or one directory deep).

`IntrusionLogAnalyzer` streams all matching entries as one line sequence,
dedups on the type-shared monotonic `event_id` (first-seen, across files),
counts malformed lines instead of failing, and maps records to typed
telemetry: `dns_event` → transient `DnsEvent` values evaluated through the
existing `dns_monitor` service (existing rules fire unchanged — including on
DNS-over-TLS resolutions the VPN monitor cannot observe), `connect_event` →
`NetworkTelemetry` (`network_monitor`, activated by this feature), and
`security_event` → `SecurityLogEvent` with a `SecurityLog` tag registry
(`security_log` service; unknown tags are emitted verbatim as
`unknown_<tag>`). Rules evaluate the complete parsed stream; only timeline
persistence is capped (`ScanOrchestrator.DNS_PERSIST_CAP` /
`CONNECT_PERSIST_CAP`, surfaced in the results UI). Rows persist as
`ForensicTimelineEvent` with `telemetrySource = INTRUSION_LOG_IMPORT`,
`source = "intrusion_log"` (raw) / `"intrusion_log_analysis"` (findings),
and correlation ids `dns:<domain>` / `net:<ip>:<port>` / `sec:<tag>`; each
import first deletes the previous import's rows (replace-on-reimport). The
raw ZIP is never retained.

**Relation to D3 (parked IP filtering):** D3 rejected *live VPN-based IP
inspection* (battery, MITM, breakage). This feature is offline import of
logs the platform already wrote — zero battery, no interception, no
allow/deny decisions — and was approved on its own merits; see
`docs/superpowers/specs/2026-08-22-intrusion-log-import-design.md` and
`docs/plans/2026-08-22-cellular-telemetry-tier1-spec.md` §11.
```

Also: add `SecurityLogEvent` to the §5.1-adjacent model/entity listing if that table enumerates telemetry models, and `scanner/intrusionlog/` to the module map beside `scanner/bugreport/`.

- [ ] **Step 2: PRIVACY_POLICY.md**

Next to the bug-report handling paragraph, add (match the document's voice):

```markdown
**Intrusion log imports.** If you choose to import an Android Advanced
Protection intrusion log export, AndroDR analyzes it entirely on your
device. The imported ZIP is read once and never stored; parsed events are
kept in the app's local database for at most 30 days from the import (or
until you import a newer export, which replaces them) and are never
transmitted anywhere.
```

- [ ] **Step 3: Commit**

```bash
git add docs/ARCHITECTURE.md docs/PRIVACY_POLICY.md
git commit -m "docs: intrusion log import architecture + privacy disclosure (#342)"
```

---

### Task 14: Full verification, PR, and the two-repo merge ceremony

**Files:** none new (verification + git/GitHub mechanics)

- [ ] **Step 1: Full local gates**

```bash
./gradlew testDebugUnitTest lintDebug
```
Expected: BUILD SUCCESSFUL, no new lint errors. Fix anything that fails before proceeding (detekt runs in CI's build job — if it fails there, fix and push).

- [ ] **Step 2: Push and open the AndroDR PR**

```bash
git push -u origin feat/342-intrusion-log-import
gh pr create --base main --title "feat: intrusion log import — Advanced Protection logs analyzed by rules (#342)" --body "Implements docs/superpowers/specs/2026-08-22-intrusion-log-import-design.md (plan: docs/superpowers/plans/2026-08-22-intrusion-log-import.md).

- ArtifactSniffer routes the existing import screen: dumpstate → BugReportAnalyzer, per-day JSONL → new IntrusionLogAnalyzer
- network_monitor activated end-to-end (evaluator + live caller + taxonomy + cross-checks); new security_log service + SecurityLog tag registry
- Imported DNS events evaluated through dns_monitor — existing rules fire, including on DoT-resolved hostnames the VPN cannot see
- ForensicTimelineEvent persistence with INTRUSION_LOG_IMPORT provenance, replace-on-reimport, capped raw rows (rules see the full stream)
- INTRUSION LOG report section; import summary card; timeline import label
- Submodule pinned to rules branch feat/security-log-service per safe ordering — submodule-check stays RED until the post-merge re-point (by design)

Closes #342"
```

- [ ] **Step 3: Run the 4-agent review ceremony** (project convention — correctness, code-quality, architect, code-security) on the branch diff; apply fixes; re-run Step 1; push.

- [ ] **Step 4: Wait for AndroDR CI `build-and-test` green** (submodule-check RED is expected at this stage). Never merge on a red build-and-test; never bypass with --admin (branch protection has enforce_admins).

- [ ] **Step 5: Open + merge the rules-repo PR**

```bash
cd /home/yasir/AndroDR/third-party/android-sigma-rules
gh pr create --base main --head feat/security-log-service --title "feat(taxonomy): activate network_monitor + add security_log service" --body "AndroDR #342. Safe ordering: AndroDR PR #<AndroDR-PR-number> is green against this branch commit. Taxonomy status flip network_monitor unwired→active; new security_log service; rule-schema service enum += security_log. No rules.txt-listed files touched — no rules.sha256 regen."
```
Wait for the rules repo's `validate` check to be green, then merge.

- [ ] **Step 6: Re-point the submodule at rules main**

```bash
cd /home/yasir/AndroDR/third-party/android-sigma-rules
git fetch origin && git checkout origin/main && cd ../..
git checkout feat/342-intrusion-log-import
git add third-party/android-sigma-rules
git commit -m "build(submodule): re-point android-sigma-rules at main after security_log merge (#342)"
git push
```

- [ ] **Step 7: Full CI green (including submodule-check), then merge the AndroDR PR.** Wait for `ci-success` — do not merge before it.

- [ ] **Step 8: Post-merge follow-ups (record, do not do now):** file the starter-rule candidates (`security_log`: adb_shell_cmd observed, non-market install; `network_monitor`: port-5555 connect) into the update-rules pipeline with per-candidate human review, and extract real `security_event` fixtures from the maintainer's full export to validate the tag registry (spec §11.1).

---

## Self-review notes (already applied)

- **Spec coverage:** §3 format facts → Tasks 6–7 tests; §4.1 sniffer → Task 7; §4.2 analyzer/streaming/dedup/fail-soft/replace-on-reimport → Tasks 8–9; §5.1–5.3 models → Tasks 3–4; §6.1–6.2 taxonomy ceremony → Tasks 1–2 + 14; §6.3 "no starter rules in this PR" → Global Constraints + Task 14 Step 8; §7 persistence/caps/correlation ids → Task 9; §8 UI/report → Tasks 10–11; §9 docs/privacy → Task 13; §10 testing incl. E2E → per-task tests + Task 12.
- **Known judgment calls encoded:** `SecurityLog.TAG_*` entries that fail to resolve at compileSdk 34 are deleted, not replaced with numeric literals (Task 4); the analyzer keeps a nullable context so its core is JVM-testable (Task 8); `Finding` timeline rows parse `matchContext["timestamp"]` because network/security field maps carry `timestamp`, not `event_time_ms` (Task 9).
- **Type consistency spot-checks:** `IntrusionLogStats`/`IntrusionLogAnalysisResult` names match across Tasks 8–10; `toForensicTimelineEvent(scanResultId)` overloads match between Task 9's adapters and orchestrator; `intrusionEvents` parameter name matches Task 11's formatter/exporter/test.

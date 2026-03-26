# SIGMA Rule Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace all hardcoded detection logic with a SIGMA-compatible YAML rule engine. Detection patterns become updatable YAML rules in a public repo.

**Architecture:** Two-phase scan: Phase 1 collects normalized telemetry (AppTelemetry, DeviceTelemetry). Phase 2 evaluates SIGMA YAML rules against telemetry and produces findings. Findings map to existing AppRisk/DeviceFlag models for the UI. Rules are bundled + fetched from `android-sigma-rules/rules` repo.

**Tech Stack:** Kotlin, SnakeYAML (YAML parsing), Hilt DI, kotlinx.serialization

**Spec:** `docs/superpowers/specs/2026-03-27-sigma-rule-engine-design.md`

---

## File Structure

```
# New files — Telemetry
app/src/main/java/com/androdr/data/model/AppTelemetry.kt
app/src/main/java/com/androdr/data/model/DeviceTelemetry.kt

# New files — Rule engine
app/src/main/java/com/androdr/sigma/SigmaRule.kt            # data classes
app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt      # YAML → SigmaRule
app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt   # evaluate rules against telemetry
app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt      # orchestrates parse + evaluate
app/src/main/java/com/androdr/sigma/FindingMapper.kt        # Finding → AppRisk/DeviceFlag
app/src/main/java/com/androdr/sigma/SigmaRuleFeed.kt        # fetches rules from public repo

# New test files
app/src/test/java/com/androdr/sigma/SigmaRuleParserTest.kt
app/src/test/java/com/androdr/sigma/SigmaRuleEvaluatorTest.kt
app/src/test/java/com/androdr/sigma/FindingMapperTest.kt

# New resources
app/src/main/res/raw/sigma_rules_manifest.yml               # bundled rules manifest
app/src/main/res/raw/sigma/                                  # bundled SIGMA YAML rules

# Modified files
app/build.gradle.kts                                         # add snakeyaml dependency
app/src/main/java/com/androdr/scanner/AppScanner.kt          # add collectTelemetry()
app/src/main/java/com/androdr/scanner/DeviceAuditor.kt       # add collectTelemetry()
app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt    # two-phase integration
app/src/main/java/com/androdr/di/AppModule.kt                # wire new components
app/src/main/java/com/androdr/ioc/IocUpdateWorker.kt         # add rule feed update
```

---

### Task 1: Add SnakeYAML dependency + telemetry data classes

**Files:**
- Modify: `app/build.gradle.kts`
- Create: `app/src/main/java/com/androdr/data/model/AppTelemetry.kt`
- Create: `app/src/main/java/com/androdr/data/model/DeviceTelemetry.kt`

- [ ] **Step 1: Add SnakeYAML to dependencies**

In `app/build.gradle.kts`, add to the `dependencies` block:
```kotlin
implementation("org.yaml:snakeyaml:2.2")
```

- [ ] **Step 2: Create `AppTelemetry.kt`**

```kotlin
// app/src/main/java/com/androdr/data/model/AppTelemetry.kt
package com.androdr.data.model

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
) {
    /** Converts fields to a flat map for SIGMA rule evaluation. */
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "package_name" to packageName,
        "app_name" to appName,
        "cert_hash" to certHash,
        "is_system_app" to isSystemApp,
        "from_trusted_store" to fromTrustedStore,
        "installer" to installer,
        "is_sideloaded" to isSideloaded,
        "is_known_oem_app" to isKnownOemApp,
        "permissions" to permissions,
        "surveillance_permission_count" to surveillancePermissionCount,
        "has_accessibility_service" to hasAccessibilityService,
        "has_device_admin" to hasDeviceAdmin,
        "known_app_category" to knownAppCategory
    )
}
```

- [ ] **Step 3: Create `DeviceTelemetry.kt`**

```kotlin
// app/src/main/java/com/androdr/data/model/DeviceTelemetry.kt
package com.androdr.data.model

data class DeviceTelemetry(
    val checkId: String,
    val isTriggered: Boolean,
    val adbEnabled: Boolean = false,
    val devOptionsEnabled: Boolean = false,
    val unknownSourcesEnabled: Boolean = false,
    val screenLockEnabled: Boolean = true,
    val patchLevel: String = "",
    val patchAgeDays: Int = 0,
    val bootloaderUnlocked: Boolean = false,
    val wifiAdbEnabled: Boolean = false
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "check_id" to checkId,
        "is_triggered" to isTriggered,
        "adb_enabled" to adbEnabled,
        "dev_options_enabled" to devOptionsEnabled,
        "unknown_sources_enabled" to unknownSourcesEnabled,
        "screen_lock_enabled" to screenLockEnabled,
        "patch_level" to patchLevel,
        "patch_age_days" to patchAgeDays,
        "bootloader_unlocked" to bootloaderUnlocked,
        "wifi_adb_enabled" to wifiAdbEnabled
    )
}
```

- [ ] **Step 4: Build**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 5: Commit**

```bash
git add app/build.gradle.kts \
       app/src/main/java/com/androdr/data/model/AppTelemetry.kt \
       app/src/main/java/com/androdr/data/model/DeviceTelemetry.kt
git commit -m "feat: add telemetry data classes and SnakeYAML dependency for SIGMA rule engine"
```

---

### Task 2: SIGMA rule data model + parser

**Files:**
- Create: `app/src/main/java/com/androdr/sigma/SigmaRule.kt`
- Create: `app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt`
- Create: `app/src/test/java/com/androdr/sigma/SigmaRuleParserTest.kt`

- [ ] **Step 1: Create `SigmaRule.kt`**

```kotlin
// app/src/main/java/com/androdr/sigma/SigmaRule.kt
package com.androdr.sigma

data class SigmaRule(
    val id: String,
    val title: String,
    val status: String,
    val description: String,
    val product: String,
    val service: String,
    val level: String,
    val tags: List<String>,
    val detection: SigmaDetection,
    val falsepositives: List<String>,
    val remediation: List<String>
)

data class SigmaDetection(
    val selections: Map<String, SigmaSelection>,
    val condition: String
)

data class SigmaSelection(
    val fieldMatchers: List<SigmaFieldMatcher>
)

data class SigmaFieldMatcher(
    val fieldName: String,
    val modifier: SigmaModifier,
    val values: List<Any>
)

enum class SigmaModifier {
    EQUALS,
    CONTAINS,
    STARTSWITH,
    ENDSWITH,
    RE,
    GTE,
    LTE,
    GT,
    LT,
    IOC_LOOKUP
}
```

- [ ] **Step 2: Create `SigmaRuleParser.kt`**

```kotlin
// app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt
package com.androdr.sigma

import org.yaml.snakeyaml.Yaml
import android.util.Log

object SigmaRuleParser {

    private const val TAG = "SigmaRuleParser"
    private val yaml = Yaml()

    fun parse(yamlContent: String): SigmaRule? {
        return try {
            val doc = yaml.load<Map<String, Any>>(yamlContent) ?: return null
            parseDocument(doc)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse SIGMA rule: ${e.message}")
            null
        }
    }

    fun parseAll(yamlContent: String): List<SigmaRule> {
        return try {
            yaml.loadAll(yamlContent)
                .filterIsInstance<Map<String, Any>>()
                .mapNotNull { parseDocument(it) }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse SIGMA rules: ${e.message}")
            emptyList()
        }
    }

    @Suppress("TooGenericExceptionCaught")
    private fun parseDocument(doc: Map<String, Any>): SigmaRule? {
        return try {
            val logsource = doc["logsource"] as? Map<*, *> ?: return null
            val detectionMap = doc["detection"] as? Map<*, *> ?: return null

            SigmaRule(
                id = doc["id"]?.toString() ?: return null,
                title = doc["title"]?.toString() ?: "",
                status = doc["status"]?.toString() ?: "experimental",
                description = doc["description"]?.toString() ?: "",
                product = logsource["product"]?.toString() ?: "",
                service = logsource["service"]?.toString() ?: "",
                level = doc["level"]?.toString() ?: "medium",
                tags = (doc["tags"] as? List<*>)?.map { it.toString() } ?: emptyList(),
                detection = parseDetection(detectionMap),
                falsepositives = (doc["falsepositives"] as? List<*>)?.map { it.toString() } ?: emptyList(),
                remediation = (doc["remediation"] as? List<*>)?.map { it.toString() } ?: emptyList()
            )
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse SIGMA document: ${e.message}")
            null
        }
    }

    private fun parseDetection(detectionMap: Map<*, *>): SigmaDetection {
        val condition = detectionMap["condition"]?.toString() ?: "selection"
        val selections = mutableMapOf<String, SigmaSelection>()

        for ((key, value) in detectionMap) {
            val keyStr = key.toString()
            if (keyStr == "condition") continue
            if (value is Map<*, *>) {
                selections[keyStr] = parseSelection(value)
            }
        }

        return SigmaDetection(selections = selections, condition = condition)
    }

    private fun parseSelection(selectionMap: Map<*, *>): SigmaSelection {
        val matchers = mutableListOf<SigmaFieldMatcher>()

        for ((key, value) in selectionMap) {
            val keyStr = key.toString()
            val (fieldName, modifier) = parseFieldAndModifier(keyStr)

            val values: List<Any> = when (value) {
                is List<*> -> value.filterNotNull()
                null -> emptyList()
                else -> listOf(value)
            }

            matchers.add(SigmaFieldMatcher(
                fieldName = fieldName,
                modifier = modifier,
                values = values
            ))
        }

        return SigmaSelection(fieldMatchers = matchers)
    }

    private fun parseFieldAndModifier(key: String): Pair<String, SigmaModifier> {
        val parts = key.split("|")
        val fieldName = parts[0]
        val modifier = if (parts.size > 1) {
            when (parts[1].lowercase()) {
                "contains" -> SigmaModifier.CONTAINS
                "startswith" -> SigmaModifier.STARTSWITH
                "endswith" -> SigmaModifier.ENDSWITH
                "re" -> SigmaModifier.RE
                "gte" -> SigmaModifier.GTE
                "lte" -> SigmaModifier.LTE
                "gt" -> SigmaModifier.GT
                "lt" -> SigmaModifier.LT
                "ioc_lookup" -> SigmaModifier.IOC_LOOKUP
                else -> SigmaModifier.EQUALS
            }
        } else {
            SigmaModifier.EQUALS
        }
        return fieldName to modifier
    }
}
```

- [ ] **Step 3: Create `SigmaRuleParserTest.kt`**

```kotlin
// app/src/test/java/com/androdr/sigma/SigmaRuleParserTest.kt
package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class SigmaRuleParserTest {

    @Test
    fun `parses basic SIGMA rule`() {
        val yaml = """
            title: Test rule
            id: test-001
            status: production
            logsource:
                product: androdr
                service: app_scanner
            detection:
                selection:
                    is_sideloaded: true
                condition: selection
            level: medium
            remediation:
                - "Uninstall the app"
        """.trimIndent()

        val rule = SigmaRuleParser.parse(yaml)
        assertNotNull(rule)
        assertEquals("test-001", rule!!.id)
        assertEquals("androdr", rule.product)
        assertEquals("app_scanner", rule.service)
        assertEquals("medium", rule.level)
        assertEquals(1, rule.detection.selections.size)
        assertEquals(1, rule.remediation.size)
    }

    @Test
    fun `parses field modifiers`() {
        val yaml = """
            title: Name contains System
            id: test-002
            logsource:
                product: androdr
                service: app_scanner
            detection:
                selection:
                    app_name|contains:
                        - System
                        - Google
                condition: selection
            level: high
        """.trimIndent()

        val rule = SigmaRuleParser.parse(yaml)
        assertNotNull(rule)
        val matcher = rule!!.detection.selections["selection"]!!.fieldMatchers[0]
        assertEquals("app_name", matcher.fieldName)
        assertEquals(SigmaModifier.CONTAINS, matcher.modifier)
        assertEquals(2, matcher.values.size)
    }

    @Test
    fun `parses compound condition`() {
        val yaml = """
            title: Compound test
            id: test-003
            logsource:
                product: androdr
                service: app_scanner
            detection:
                sel_untrusted:
                    from_trusted_store: false
                sel_name:
                    app_name|contains: System
                condition: sel_untrusted and sel_name
            level: high
        """.trimIndent()

        val rule = SigmaRuleParser.parse(yaml)
        assertNotNull(rule)
        assertEquals(2, rule!!.detection.selections.size)
        assertEquals("sel_untrusted and sel_name", rule.detection.condition)
    }

    @Test
    fun `returns null for invalid YAML`() {
        val rule = SigmaRuleParser.parse("not: valid: yaml: [[[")
        assertNull(rule)
    }

    @Test
    fun `parses tags and falsepositives`() {
        val yaml = """
            title: Tagged rule
            id: test-004
            logsource:
                product: androdr
                service: app_scanner
            detection:
                selection:
                    is_sideloaded: true
                condition: selection
            level: medium
            tags:
                - attack.t1036
                - attack.t1418
            falsepositives:
                - Developer tools
        """.trimIndent()

        val rule = SigmaRuleParser.parse(yaml)
        assertNotNull(rule)
        assertEquals(2, rule!!.tags.size)
        assertEquals("attack.t1036", rule.tags[0])
        assertEquals(1, rule.falsepositives.size)
    }
}
```

- [ ] **Step 4: Run tests**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew testDebugUnitTest --tests "com.androdr.sigma.SigmaRuleParserTest"`
Expected: 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/ \
       app/src/test/java/com/androdr/sigma/
git commit -m "feat: add SIGMA rule data model and YAML parser with tests"
```

---

### Task 3: SIGMA rule evaluator

**Files:**
- Create: `app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt`
- Create: `app/src/test/java/com/androdr/sigma/SigmaRuleEvaluatorTest.kt`

- [ ] **Step 1: Create `SigmaRuleEvaluator.kt`**

```kotlin
// app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt
package com.androdr.sigma

data class Finding(
    val ruleId: String,
    val title: String,
    val level: String,
    val tags: List<String>,
    val remediation: List<String>,
    val matchedRecord: Map<String, Any?>
)

/**
 * Evaluates SIGMA rules against telemetry field maps.
 * Pure function: (rules, telemetry) → findings.
 */
object SigmaRuleEvaluator {

    fun evaluate(
        rules: List<SigmaRule>,
        records: List<Map<String, Any?>>,
        service: String,
        iocLookups: Map<String, (Any) -> Boolean> = emptyMap()
    ): List<Finding> {
        val matchingRules = rules.filter { it.service == service }
        val findings = mutableListOf<Finding>()

        for (record in records) {
            for (rule in matchingRules) {
                if (evaluateCondition(rule.detection, record, iocLookups)) {
                    findings.add(Finding(
                        ruleId = rule.id,
                        title = rule.title,
                        level = rule.level,
                        tags = rule.tags,
                        remediation = rule.remediation,
                        matchedRecord = record
                    ))
                }
            }
        }

        return findings
    }

    private fun evaluateCondition(
        detection: SigmaDetection,
        record: Map<String, Any?>,
        iocLookups: Map<String, (Any) -> Boolean>
    ): Boolean {
        val selectionResults = detection.selections.mapValues { (_, selection) ->
            evaluateSelection(selection, record, iocLookups)
        }
        return evaluateConditionExpression(detection.condition, selectionResults)
    }

    private fun evaluateSelection(
        selection: SigmaSelection,
        record: Map<String, Any?>,
        iocLookups: Map<String, (Any) -> Boolean>
    ): Boolean {
        return selection.fieldMatchers.all { matcher ->
            evaluateFieldMatcher(matcher, record, iocLookups)
        }
    }

    @Suppress("CyclomaticComplexMethod")
    private fun evaluateFieldMatcher(
        matcher: SigmaFieldMatcher,
        record: Map<String, Any?>,
        iocLookups: Map<String, (Any) -> Boolean>
    ): Boolean {
        val fieldValue = record[matcher.fieldName]

        return when (matcher.modifier) {
            SigmaModifier.EQUALS -> {
                matcher.values.any { expected ->
                    matchEquals(fieldValue, expected)
                }
            }
            SigmaModifier.CONTAINS -> {
                val strValue = fieldValue?.toString()?.lowercase() ?: return false
                matcher.values.any { expected ->
                    strValue.contains(expected.toString().lowercase())
                }
            }
            SigmaModifier.STARTSWITH -> {
                val strValue = fieldValue?.toString()?.lowercase() ?: return false
                matcher.values.any { expected ->
                    strValue.startsWith(expected.toString().lowercase())
                }
            }
            SigmaModifier.ENDSWITH -> {
                val strValue = fieldValue?.toString()?.lowercase() ?: return false
                matcher.values.any { expected ->
                    strValue.endsWith(expected.toString().lowercase())
                }
            }
            SigmaModifier.RE -> {
                val strValue = fieldValue?.toString() ?: return false
                matcher.values.any { pattern ->
                    Regex(pattern.toString()).containsMatchIn(strValue)
                }
            }
            SigmaModifier.GTE -> {
                val numValue = (fieldValue as? Number)?.toDouble() ?: return false
                matcher.values.any { (it as? Number)?.toDouble()?.let { e -> numValue >= e } == true }
            }
            SigmaModifier.LTE -> {
                val numValue = (fieldValue as? Number)?.toDouble() ?: return false
                matcher.values.any { (it as? Number)?.toDouble()?.let { e -> numValue <= e } == true }
            }
            SigmaModifier.GT -> {
                val numValue = (fieldValue as? Number)?.toDouble() ?: return false
                matcher.values.any { (it as? Number)?.toDouble()?.let { e -> numValue > e } == true }
            }
            SigmaModifier.LT -> {
                val numValue = (fieldValue as? Number)?.toDouble() ?: return false
                matcher.values.any { (it as? Number)?.toDouble()?.let { e -> numValue < e } == true }
            }
            SigmaModifier.IOC_LOOKUP -> {
                val lookupName = matcher.values.firstOrNull()?.toString() ?: return false
                val lookup = iocLookups[lookupName] ?: return false
                fieldValue?.let { lookup(it) } ?: false
            }
        }
    }

    private fun matchEquals(fieldValue: Any?, expected: Any): Boolean {
        if (fieldValue == null) return false
        if (fieldValue is Boolean && expected is Boolean) return fieldValue == expected
        if (fieldValue is Boolean) return fieldValue == (expected.toString().toBoolean())
        if (fieldValue is Number && expected is Number) return fieldValue.toDouble() == expected.toDouble()
        return fieldValue.toString().lowercase() == expected.toString().lowercase()
    }

    internal fun evaluateConditionExpression(
        condition: String,
        selectionResults: Map<String, Boolean>
    ): Boolean {
        val tokens = condition.trim().split("\\s+".toRegex())

        if (tokens.size == 1) {
            return selectionResults[tokens[0]] ?: false
        }

        var result = selectionResults[tokens[0]] ?: false
        var i = 1
        while (i < tokens.size - 1) {
            val operator = tokens[i].lowercase()
            val operand = selectionResults[tokens[i + 1]] ?: false
            result = when (operator) {
                "and" -> result && operand
                "or" -> result || operand
                else -> result
            }
            i += 2
        }

        return result
    }
}
```

- [ ] **Step 2: Create `SigmaRuleEvaluatorTest.kt`**

```kotlin
// app/src/test/java/com/androdr/sigma/SigmaRuleEvaluatorTest.kt
package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SigmaRuleEvaluatorTest {

    private fun makeRule(
        id: String = "test",
        service: String = "app_scanner",
        selections: Map<String, SigmaSelection>,
        condition: String = "selection",
        level: String = "high"
    ) = SigmaRule(
        id = id, title = "Test", status = "production", description = "",
        product = "androdr", service = service, level = level,
        tags = emptyList(), detection = SigmaDetection(selections, condition),
        falsepositives = emptyList(), remediation = listOf("Fix it")
    )

    @Test
    fun `matches boolean field`() {
        val rule = makeRule(selections = mapOf(
            "selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("is_sideloaded", SigmaModifier.EQUALS, listOf(true))
            ))
        ))
        val record = mapOf<String, Any?>("is_sideloaded" to true)
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner")
        assertEquals(1, findings.size)
    }

    @Test
    fun `no match when field differs`() {
        val rule = makeRule(selections = mapOf(
            "selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("is_sideloaded", SigmaModifier.EQUALS, listOf(true))
            ))
        ))
        val record = mapOf<String, Any?>("is_sideloaded" to false)
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner")
        assertEquals(0, findings.size)
    }

    @Test
    fun `contains modifier matches substring`() {
        val rule = makeRule(selections = mapOf(
            "selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("app_name", SigmaModifier.CONTAINS, listOf("System"))
            ))
        ))
        val record = mapOf<String, Any?>("app_name" to "System Service")
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner")
        assertEquals(1, findings.size)
    }

    @Test
    fun `gte modifier matches numeric field`() {
        val rule = makeRule(selections = mapOf(
            "selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("surveillance_permission_count", SigmaModifier.GTE, listOf(4))
            ))
        ))
        val match = mapOf<String, Any?>("surveillance_permission_count" to 5)
        val noMatch = mapOf<String, Any?>("surveillance_permission_count" to 2)
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(match), "app_scanner").size)
        assertEquals(0, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(noMatch), "app_scanner").size)
    }

    @Test
    fun `compound AND condition`() {
        val rule = makeRule(
            selections = mapOf(
                "sel_a" to SigmaSelection(listOf(
                    SigmaFieldMatcher("is_sideloaded", SigmaModifier.EQUALS, listOf(true))
                )),
                "sel_b" to SigmaSelection(listOf(
                    SigmaFieldMatcher("has_accessibility_service", SigmaModifier.EQUALS, listOf(true))
                ))
            ),
            condition = "sel_a and sel_b"
        )
        val bothTrue = mapOf<String, Any?>("is_sideloaded" to true, "has_accessibility_service" to true)
        val oneTrue = mapOf<String, Any?>("is_sideloaded" to true, "has_accessibility_service" to false)
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(bothTrue), "app_scanner").size)
        assertEquals(0, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(oneTrue), "app_scanner").size)
    }

    @Test
    fun `ioc_lookup modifier delegates to lookup function`() {
        val rule = makeRule(selections = mapOf(
            "selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("cert_hash", SigmaModifier.IOC_LOOKUP, listOf("cert_hash_ioc_db"))
            ))
        ))
        val knownBad = setOf("abc123")
        val lookups = mapOf<String, (Any) -> Boolean>("cert_hash_ioc_db" to { v -> v.toString() in knownBad })

        val match = mapOf<String, Any?>("cert_hash" to "abc123")
        val noMatch = mapOf<String, Any?>("cert_hash" to "def456")
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(match), "app_scanner", lookups).size)
        assertEquals(0, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(noMatch), "app_scanner", lookups).size)
    }

    @Test
    fun `skips rules for different service`() {
        val rule = makeRule(service = "device_auditor", selections = mapOf(
            "selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("adb_enabled", SigmaModifier.EQUALS, listOf(true))
            ))
        ))
        val record = mapOf<String, Any?>("adb_enabled" to true)
        assertEquals(0, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner").size)
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "device_auditor").size)
    }

    @Test
    fun `condition expression evaluator`() {
        assertTrue(SigmaRuleEvaluator.evaluateConditionExpression("a and b", mapOf("a" to true, "b" to true)))
        assertFalse(SigmaRuleEvaluator.evaluateConditionExpression("a and b", mapOf("a" to true, "b" to false)))
        assertTrue(SigmaRuleEvaluator.evaluateConditionExpression("a or b", mapOf("a" to false, "b" to true)))
        assertFalse(SigmaRuleEvaluator.evaluateConditionExpression("a or b", mapOf("a" to false, "b" to false)))
    }
}
```

- [ ] **Step 3: Run tests**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew testDebugUnitTest --tests "com.androdr.sigma.SigmaRuleEvaluatorTest"`
Expected: 8 tests PASS

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt \
       app/src/test/java/com/androdr/sigma/SigmaRuleEvaluatorTest.kt
git commit -m "feat: add SIGMA rule evaluator with condition parsing and IOC lookup support"
```

---

### Task 4: AppScanner telemetry extraction

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/AppScanner.kt`

- [ ] **Step 1: Add `collectTelemetry()` method**

Read `AppScanner.kt` first. Add a new public method that extracts metadata WITHOUT any detection logic. This method collects the same package data as `scan()` but returns `List<AppTelemetry>` instead of `List<AppRisk>`.

The method should:
1. Call `getInstalledPackages()` with the same flags as `scan()`
2. For each package, extract: packageName, appName, certHash, isSystemApp, fromTrustedStore, installer, isSideloaded, isKnownOemApp, permissions, surveillancePermissionCount, hasAccessibilityService, hasDeviceAdmin, knownAppCategory
3. Return `List<AppTelemetry>`

Use the existing private helpers: `extractCertHash()`, `getInstallerPackageName()`, the `trustedInstallers` set, `knownOemPrefixes`, `samsungOemPrefixes`, `surveillancePermissions`.

Add import: `import com.androdr.data.model.AppTelemetry`

The existing `scan()` method stays unchanged for now (migration phase 1 — both paths coexist).

- [ ] **Step 2: Build and run all tests**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew testDebugUnitTest`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/AppScanner.kt
git commit -m "feat: add collectTelemetry() to AppScanner for SIGMA rule engine phase 1"
```

---

### Task 5: DeviceAuditor telemetry extraction

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/DeviceAuditor.kt`

- [ ] **Step 1: Add `collectTelemetry()` method**

Read `DeviceAuditor.kt` first. Add a new public method that returns `List<DeviceTelemetry>` — one entry per posture check with all field values populated.

The method reuses the same check logic as `audit()` but outputs `DeviceTelemetry` instead of `DeviceFlag`.

Add import: `import com.androdr.data.model.DeviceTelemetry`

The existing `audit()` method stays unchanged.

- [ ] **Step 2: Build and run all tests**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew testDebugUnitTest`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/DeviceAuditor.kt
git commit -m "feat: add collectTelemetry() to DeviceAuditor for SIGMA rule engine phase 1"
```

---

### Task 6: Finding → AppRisk/DeviceFlag mapper

**Files:**
- Create: `app/src/main/java/com/androdr/sigma/FindingMapper.kt`
- Create: `app/src/test/java/com/androdr/sigma/FindingMapperTest.kt`

- [ ] **Step 1: Create `FindingMapper.kt`**

```kotlin
// app/src/main/java/com/androdr/sigma/FindingMapper.kt
package com.androdr.sigma

import com.androdr.data.model.AppRisk
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.DeviceFlag
import com.androdr.data.model.DeviceTelemetry
import com.androdr.data.model.RiskLevel
import com.androdr.data.model.Severity

object FindingMapper {

    fun toAppRisks(
        telemetry: List<AppTelemetry>,
        findings: List<Finding>
    ): List<AppRisk> {
        val findingsByPackage = findings.groupBy {
            it.matchedRecord["package_name"]?.toString() ?: ""
        }

        return findingsByPackage.mapNotNull { (packageName, packageFindings) ->
            val app = telemetry.find { it.packageName == packageName } ?: return@mapNotNull null

            val reasons = packageFindings.flatMap { finding ->
                if (finding.remediation.isNotEmpty()) {
                    listOf(finding.title)
                } else {
                    listOf(finding.title)
                }
            }

            val highestLevel = packageFindings
                .map { sigmaLevelToRiskLevel(it.level) }
                .maxByOrNull { it.score } ?: RiskLevel.LOW

            val isKnownMalware = packageFindings.any { it.level == "critical" &&
                it.ruleId.startsWith("androdr-00") }

            AppRisk(
                packageName = packageName,
                appName = app.appName,
                riskLevel = highestLevel,
                reasons = reasons,
                isKnownMalware = isKnownMalware,
                isSideloaded = app.isSideloaded,
                dangerousPermissions = app.permissions
            )
        }.sortedByDescending { it.riskLevel.score }
    }

    fun toDeviceFlags(
        telemetry: List<DeviceTelemetry>,
        findings: List<Finding>
    ): List<DeviceFlag> {
        val triggeredIds = findings.map {
            it.matchedRecord["check_id"]?.toString() ?: ""
        }.toSet()

        return telemetry.map { check ->
            val isTriggered = check.checkId in triggeredIds
            DeviceFlag(
                id = check.checkId,
                title = CHECK_TITLES[check.checkId] ?: check.checkId,
                description = CHECK_DESCRIPTIONS[check.checkId] ?: "",
                severity = CHECK_SEVERITIES[check.checkId] ?: Severity.MEDIUM,
                isTriggered = isTriggered
            )
        }
    }

    private fun sigmaLevelToRiskLevel(level: String): RiskLevel = when (level.lowercase()) {
        "critical" -> RiskLevel.CRITICAL
        "high" -> RiskLevel.HIGH
        "medium" -> RiskLevel.MEDIUM
        "low" -> RiskLevel.LOW
        else -> RiskLevel.MEDIUM
    }

    private val CHECK_TITLES = mapOf(
        "adb_enabled" to "USB Debugging",
        "dev_options_enabled" to "Developer Options",
        "unknown_sources" to "Unknown Sources Installation",
        "no_screen_lock" to "Screen Lock",
        "stale_patch_level" to "Security Patch Level",
        "bootloader_unlocked" to "Bootloader",
        "wifi_adb_enabled" to "Wireless ADB"
    )

    private val CHECK_DESCRIPTIONS = mapOf(
        "adb_enabled" to "ADB (Android Debug Bridge) is currently enabled. This allows a connected computer to execute arbitrary commands on the device.",
        "dev_options_enabled" to "Developer Options are turned on. This exposes advanced settings that can weaken device security.",
        "unknown_sources" to "One or more apps are permitted to install APKs from outside the Play Store, increasing the risk of sideloaded malware.",
        "no_screen_lock" to "The device has no PIN, password, pattern, or biometric lock configured, leaving it fully accessible if lost or stolen.",
        "stale_patch_level" to "The device's security patch level is more than 90 days old and may be missing critical vulnerability fixes.",
        "bootloader_unlocked" to "The bootloader is unlocked, which disables Verified Boot and allows unsigned or modified system images to run.",
        "wifi_adb_enabled" to "ADB over Wi-Fi is active. Any device on the same network may be able to connect and issue debug commands."
    )

    private val CHECK_SEVERITIES = mapOf(
        "adb_enabled" to Severity.HIGH,
        "dev_options_enabled" to Severity.MEDIUM,
        "unknown_sources" to Severity.HIGH,
        "no_screen_lock" to Severity.CRITICAL,
        "stale_patch_level" to Severity.HIGH,
        "bootloader_unlocked" to Severity.CRITICAL,
        "wifi_adb_enabled" to Severity.HIGH
    )
}
```

- [ ] **Step 2: Create `FindingMapperTest.kt`**

```kotlin
// app/src/test/java/com/androdr/sigma/FindingMapperTest.kt
package com.androdr.sigma

import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.RiskLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FindingMapperTest {

    @Test
    fun `maps findings to AppRisk with correct risk level`() {
        val telemetry = listOf(AppTelemetry(
            packageName = "com.evil.app", appName = "Evil", certHash = null,
            isSystemApp = false, fromTrustedStore = false, installer = null,
            isSideloaded = true, isKnownOemApp = false,
            permissions = listOf("CAMERA"), surveillancePermissionCount = 1,
            hasAccessibilityService = false, hasDeviceAdmin = false,
            knownAppCategory = null
        ))
        val findings = listOf(Finding(
            ruleId = "androdr-010", title = "Sideloaded app",
            level = "medium", tags = emptyList(),
            remediation = listOf("Review this app"),
            matchedRecord = mapOf("package_name" to "com.evil.app")
        ))

        val risks = FindingMapper.toAppRisks(telemetry, findings)
        assertEquals(1, risks.size)
        assertEquals("com.evil.app", risks[0].packageName)
        assertEquals(RiskLevel.MEDIUM, risks[0].riskLevel)
        assertTrue(risks[0].isSideloaded)
    }

    @Test
    fun `multiple findings for same package merge into one AppRisk`() {
        val telemetry = listOf(AppTelemetry(
            packageName = "com.evil.app", appName = "Evil", certHash = "abc",
            isSystemApp = false, fromTrustedStore = false, installer = null,
            isSideloaded = true, isKnownOemApp = false,
            permissions = emptyList(), surveillancePermissionCount = 0,
            hasAccessibilityService = true, hasDeviceAdmin = false,
            knownAppCategory = null
        ))
        val findings = listOf(
            Finding("androdr-002", "Cert hash match", "critical", emptyList(), emptyList(),
                mapOf("package_name" to "com.evil.app")),
            Finding("androdr-012", "Accessibility abuse", "high", emptyList(), emptyList(),
                mapOf("package_name" to "com.evil.app"))
        )

        val risks = FindingMapper.toAppRisks(telemetry, findings)
        assertEquals(1, risks.size)
        assertEquals(RiskLevel.CRITICAL, risks[0].riskLevel)
        assertEquals(2, risks[0].reasons.size)
    }
}
```

- [ ] **Step 3: Run tests**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew testDebugUnitTest --tests "com.androdr.sigma.FindingMapperTest"`
Expected: 2 tests PASS

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/FindingMapper.kt \
       app/src/test/java/com/androdr/sigma/FindingMapperTest.kt
git commit -m "feat: add FindingMapper to convert SIGMA findings to AppRisk/DeviceFlag"
```

---

### Task 7: SigmaRuleEngine orchestrator + bundled rules

**Files:**
- Create: `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt`
- Create: `app/src/main/res/raw/sigma_rules_manifest.yml`

- [ ] **Step 1: Create `SigmaRuleEngine.kt`**

```kotlin
// app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt
package com.androdr.sigma

import android.content.Context
import android.util.Log
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.DeviceTelemetry
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class SigmaRuleEngine @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private var rules: List<SigmaRule> = emptyList()
    private var iocLookups: Map<String, (Any) -> Boolean> = emptyMap()

    fun loadBundledRules() {
        val loaded = mutableListOf<SigmaRule>()
        try {
            val fields = com.androdr.R.raw::class.java.fields
            for (field in fields) {
                if (field.name.startsWith("sigma_")) {
                    val resId = field.getInt(null)
                    val yaml = context.resources.openRawResource(resId)
                        .bufferedReader().use { it.readText() }
                    SigmaRuleParser.parse(yaml)?.let { loaded.add(it) }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to load bundled SIGMA rules: ${e.message}")
        }
        rules = loaded
        Log.i(TAG, "Loaded ${rules.size} bundled SIGMA rules")
    }

    fun setRemoteRules(remoteRules: List<SigmaRule>) {
        val bundledIds = rules.filter { it.id.startsWith("androdr-") }.map { it.id }.toSet()
        val merged = rules.toMutableList()
        for (rule in remoteRules) {
            if (rule.id !in bundledIds) {
                merged.add(rule)
            }
        }
        rules = merged
        Log.i(TAG, "Total rules after merge: ${rules.size}")
    }

    fun setIocLookups(lookups: Map<String, (Any) -> Boolean>) {
        iocLookups = lookups
    }

    fun evaluateApps(telemetry: List<AppTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(rules, records, "app_scanner", iocLookups)
    }

    fun evaluateDevice(telemetry: List<DeviceTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(rules, records, "device_auditor", iocLookups)
    }

    fun ruleCount(): Int = rules.size

    companion object {
        private const val TAG = "SigmaRuleEngine"
    }
}
```

- [ ] **Step 2: Create initial bundled rule**

Create `app/src/main/res/raw/sigma_androdr_016.yml` (system name impersonation — the rule that motivated the engine):

```yaml
title: Sideloaded app with system-impersonating name
id: androdr-016
status: production
description: >
    Detects apps installed from untrusted sources that use display names
    mimicking system components.
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
            - System
            - Service
            - Google
            - Android
            - Samsung
            - Update
            - Security
    condition: selection_untrusted and selection_name
level: high
falsepositives:
    - Legitimate developer tools with system-sounding names
remediation:
    - "This app's name impersonates a system component but was installed from an untrusted source."
    - "Uninstall it unless you specifically installed it."
```

- [ ] **Step 3: Build**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt \
       app/src/main/res/raw/
git commit -m "feat: add SigmaRuleEngine with bundled rule loading and system name impersonation rule"
```

---

### Task 8: ScanOrchestrator integration (two-phase)

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt`

- [ ] **Step 1: Add rule engine to ScanOrchestrator**

Read `ScanOrchestrator.kt` first. Add `SigmaRuleEngine` to the constructor. In `runFullScan()`, after the existing scan, also run the rule engine path:

1. Call `appScanner.collectTelemetry()` → `List<AppTelemetry>`
2. Call `sigmaRuleEngine.evaluateApps(telemetry)` → `List<Finding>`
3. Call `FindingMapper.toAppRisks(telemetry, findings)` → `List<AppRisk>`
4. Log the rule-based results alongside the hardcoded results for comparison

For now, the hardcoded results are still used for the `ScanResult`. The rule-based results are logged only. This is migration phase 1 — coexistence.

Add imports for `SigmaRuleEngine`, `FindingMapper`, `AppTelemetry`.

- [ ] **Step 2: Build and run all tests**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew testDebugUnitTest`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt
git commit -m "feat: integrate SIGMA rule engine into ScanOrchestrator (phase 1 — coexistence)"
```

---

### Task 9: DI wiring + rule engine initialization

**Files:**
- Modify: `app/src/main/java/com/androdr/di/AppModule.kt`

- [ ] **Step 1: Wire SigmaRuleEngine**

`SigmaRuleEngine` uses `@Inject` constructor with `@ApplicationContext` — Hilt provides it automatically. No `@Provides` needed.

Wire the IOC lookups: in `AppModule` or in `ScanOrchestrator`'s init, call:
```kotlin
sigmaRuleEngine.setIocLookups(mapOf(
    "package_ioc_db" to { v -> iocResolver.isKnownBadPackage(v.toString()) != null },
    "cert_hash_ioc_db" to { v -> certHashIocResolver.isKnownBadCert(v.toString()) != null },
    "domain_ioc_db" to { v -> domainIocResolver.isKnownBadDomain(v.toString()) != null }
))
sigmaRuleEngine.loadBundledRules()
```

This should be done in `ScanOrchestrator`'s init or in a startup method. Read the current code to decide the best location.

- [ ] **Step 2: Build and run all tests**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew detekt lintDebug testDebugUnitTest`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/di/AppModule.kt \
       app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt
git commit -m "feat: wire SIGMA rule engine into DI and initialize IOC lookups"
```

---

### Task 10: Seed public rules repo

**Files:**
- New repo: `android-sigma-rules/rules`

- [ ] **Step 1: Clone the public repo and add initial structure**

```bash
cd /tmp
git clone https://github.com/android-sigma-rules/rules
cd rules
mkdir -p app_scanner device_auditor dns_monitor
```

- [ ] **Step 2: Create README.md**

Create a README explaining the project, rule format, field vocabulary, how to contribute.

- [ ] **Step 3: Create seed rules from the detection rules catalog**

Convert each rule from `docs/detection-rules-catalog.md` into individual YAML files in the appropriate directory. Use the exact SIGMA format from the spec.

- [ ] **Step 4: Commit and push**

```bash
git add .
git commit -m "feat: seed repo with 24 SIGMA detection rules for Android"
git push origin main
```

---

### Task 11: Final verification + push

- [ ] **Step 1: Run full test suite**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew detekt lintDebug testDebugUnitTest assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 2: Install and verify on emulator**

Install debug APK, trigger scan, check logcat for SIGMA rule engine output alongside existing scan results. Verify the system name impersonation rule fires for TheTruthSpy ("Google services") sample.

- [ ] **Step 3: Push**

```bash
git push origin main
```

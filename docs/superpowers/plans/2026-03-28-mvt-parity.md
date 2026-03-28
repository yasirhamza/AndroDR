# MVT-Parity Forensic Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port MVT's structured bugreport analysis modules to Kotlin and add runtime scanner equivalents for AppOps, Receivers, and Accessibility — covering Tier 1 (#31, #32) and Tier 2 (#33, #34, #35).

**Architecture:** Module-based bugreport analysis pipeline with a shared `DumpsysSectionParser`, plus three new runtime scanners producing telemetry evaluated by existing SIGMA rule engine. `BugReportAnalyzer` is refactored from a monolithic scanner to a module dispatcher.

**Tech Stack:** Kotlin, Hilt (multibinding with `@IntoSet`), Android APIs (`AppOpsManager`, `PackageManager`, `AccessibilityManager`), SIGMA YAML rules, MockK for tests.

**Spec:** `docs/superpowers/specs/2026-03-28-mvt-parity-design.md`

---

## File Structure

### New Files
| File | Responsibility |
|------|---------------|
| `scanner/bugreport/BugreportModule.kt` | Interface + `ModuleResult` + `TimelineEvent` |
| `scanner/bugreport/DumpsysSectionParser.kt` | Extracts named sections from dumpstate streams |
| `scanner/bugreport/LegacyScanModule.kt` | Existing 6 regex checks, extracted from `BugReportAnalyzer` |
| `scanner/bugreport/AccessibilityModule.kt` | Parses `DUMP OF SERVICE accessibility:` |
| `scanner/bugreport/ReceiverModule.kt` | Parses receiver table from `DUMP OF SERVICE package:` |
| `scanner/bugreport/AppOpsModule.kt` | Parses `DUMP OF SERVICE appops:` |
| `scanner/AccessibilityAuditScanner.kt` | Runtime scanner via `AccessibilityManager` |
| `scanner/ReceiverAuditScanner.kt` | Runtime scanner via `PackageManager.queryBroadcastReceivers()` |
| `scanner/AppOpsScanner.kt` | Runtime scanner via `AppOpsManager` |
| `data/model/TimelineEvent.kt` | Timeline event data class |
| `data/model/AccessibilityTelemetry.kt` | Runtime telemetry for SIGMA evaluation |
| `data/model/ReceiverTelemetry.kt` | Runtime telemetry for SIGMA evaluation |
| `data/model/AppOpsTelemetry.kt` | Runtime telemetry for SIGMA evaluation |
| `di/BugreportModuleBindings.kt` | Hilt multibinding module |
| `res/raw/sigma_androdr_060_active_accessibility.yml` | SIGMA rule |
| `res/raw/sigma_androdr_061_sms_receiver.yml` | SIGMA rule |
| `res/raw/sigma_androdr_062_call_receiver.yml` | SIGMA rule |
| `res/raw/sigma_androdr_063_appops_microphone.yml` | SIGMA rule |
| `res/raw/sigma_androdr_064_appops_camera.yml` | SIGMA rule |
| `res/raw/sigma_androdr_065_appops_install_packages.yml` | SIGMA rule |
| Tests for each new file (see tasks) | |

### Modified Files
| File | Change |
|------|--------|
| `ui/dashboard/DashboardScreen.kt` | Add bug report analysis card |
| `res/values/strings.xml` | Add `dashboard_bugreport_*` string resources |
| `scanner/BugReportAnalyzer.kt` | Refactor to module dispatcher |
| `scanner/ScanOrchestrator.kt` | Add 3 runtime scanner calls + SIGMA evaluation |
| `sigma/SigmaRuleEngine.kt` | Add `evaluateAccessibility()`, `evaluateReceivers()`, `evaluateAppOps()` |

---

## Task 1: Dashboard Bug Report Entry Point (#31)

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt:188` (after DNS/Last Scan row)
- Modify: `app/src/main/res/values/strings.xml`

- [ ] **Step 1: Add string resources**

In `app/src/main/res/values/strings.xml`, add after the `<!-- Bug Report -->` comment block (after line 60):

```xml
    <string name="dashboard_bugreport_title">Bug Report Analysis</string>
    <string name="dashboard_bugreport_hint">Analyze a bug report .zip for spyware indicators</string>
```

- [ ] **Step 2: Add the bug report card to DashboardScreen**

In `app/src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt`, add `BugReport` to the Icons import:

```kotlin
import androidx.compose.material.icons.filled.BugReport
```

Then add the following card after the second `Row` of summary cards (after line 188, before the closing `}` of the `Column`):

```kotlin
            // Bug Report Analysis entry point
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onNavigate("bugreport") },
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
                )
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Icon(
                        imageVector = Icons.Filled.BugReport,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(28.dp)
                    )
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.dashboard_bugreport_title),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold
                        )
                        Text(
                            text = stringResource(R.string.dashboard_bugreport_hint),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
```

- [ ] **Step 3: Build and verify**

Run: `./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt app/src/main/res/values/strings.xml
git commit -m "feat: add bug report analysis card to dashboard (#31)"
```

---

## Task 2: Data Models — TimelineEvent and Telemetry Types

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/TimelineEvent.kt`
- Create: `app/src/main/java/com/androdr/data/model/AccessibilityTelemetry.kt`
- Create: `app/src/main/java/com/androdr/data/model/ReceiverTelemetry.kt`
- Create: `app/src/main/java/com/androdr/data/model/AppOpsTelemetry.kt`

- [ ] **Step 1: Create TimelineEvent**

Create `app/src/main/java/com/androdr/data/model/TimelineEvent.kt`:

```kotlin
package com.androdr.data.model

data class TimelineEvent(
    val timestamp: Long,
    val source: String,
    val category: String,
    val description: String,
    val severity: String
)
```

- [ ] **Step 2: Create AccessibilityTelemetry**

Create `app/src/main/java/com/androdr/data/model/AccessibilityTelemetry.kt`:

```kotlin
package com.androdr.data.model

data class AccessibilityTelemetry(
    val packageName: String,
    val serviceName: String,
    val isSystemApp: Boolean,
    val isEnabled: Boolean
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "package_name" to packageName,
        "service_name" to serviceName,
        "is_system_app" to isSystemApp,
        "is_enabled" to isEnabled
    )
}
```

- [ ] **Step 3: Create ReceiverTelemetry**

Create `app/src/main/java/com/androdr/data/model/ReceiverTelemetry.kt`:

```kotlin
package com.androdr.data.model

data class ReceiverTelemetry(
    val packageName: String,
    val intentAction: String,
    val componentName: String,
    val isSystemApp: Boolean
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "package_name" to packageName,
        "intent_action" to intentAction,
        "component_name" to componentName,
        "is_system_app" to isSystemApp
    )
}
```

- [ ] **Step 4: Create AppOpsTelemetry**

Create `app/src/main/java/com/androdr/data/model/AppOpsTelemetry.kt`:

```kotlin
package com.androdr.data.model

data class AppOpsTelemetry(
    val packageName: String,
    val operation: String,
    val lastAccessTime: Long,
    val lastRejectTime: Long,
    val accessCount: Int,
    val isSystemApp: Boolean
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "package_name" to packageName,
        "operation" to operation,
        "last_access_time" to lastAccessTime,
        "last_reject_time" to lastRejectTime,
        "access_count" to accessCount,
        "is_system_app" to isSystemApp
    )
}
```

- [ ] **Step 5: Build and verify**

Run: `./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/data/model/TimelineEvent.kt \
       app/src/main/java/com/androdr/data/model/AccessibilityTelemetry.kt \
       app/src/main/java/com/androdr/data/model/ReceiverTelemetry.kt \
       app/src/main/java/com/androdr/data/model/AppOpsTelemetry.kt
git commit -m "feat: add TimelineEvent and telemetry models for MVT-parity scanners"
```

---

## Task 3: BugreportModule Interface

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/bugreport/BugreportModule.kt`

- [ ] **Step 1: Create the interface**

Create `app/src/main/java/com/androdr/scanner/bugreport/BugreportModule.kt`:

```kotlin
package com.androdr.scanner.bugreport

import com.androdr.data.model.TimelineEvent
import com.androdr.ioc.IocResolver
import com.androdr.scanner.BugReportAnalyzer.BugReportFinding
import java.io.InputStream

data class ModuleResult(
    val findings: List<BugReportFinding>,
    val timeline: List<TimelineEvent>
)

interface BugreportModule {
    /** Dumpsys service names this module needs, or null for raw ZIP entries. */
    val targetSections: List<String>?

    /** Analyze a dumpsys section. Override for section-targeted modules. */
    suspend fun analyze(
        sectionText: String,
        iocResolver: IocResolver
    ): ModuleResult = ModuleResult(emptyList(), emptyList())

    /** Analyze raw ZIP entries. Override for modules with targetSections == null. */
    suspend fun analyzeRaw(
        entries: Sequence<Pair<String, InputStream>>,
        iocResolver: IocResolver
    ): ModuleResult = ModuleResult(emptyList(), emptyList())
}
```

- [ ] **Step 2: Build and verify**

Run: `./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/bugreport/BugreportModule.kt
git commit -m "feat: add BugreportModule interface with ModuleResult"
```

---

## Task 4: DumpsysSectionParser (#32)

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/bugreport/DumpsysSectionParser.kt`
- Create: `app/src/test/java/com/androdr/scanner/bugreport/DumpsysSectionParserTest.kt`

- [ ] **Step 1: Write failing tests**

Create `app/src/test/java/com/androdr/scanner/bugreport/DumpsysSectionParserTest.kt`:

```kotlin
package com.androdr.scanner.bugreport

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class DumpsysSectionParserTest {

    private val parser = DumpsysSectionParser()

    private fun streamOf(text: String) =
        ByteArrayInputStream(text.toByteArray(Charsets.UTF_8))

    // ── Single section extraction ────────────────────────────────────────

    @Test
    fun `extracts section with DUMP OF SERVICE header`() {
        val dumpstate = """
            Some preamble text
            -------------------------------------------------------------------------------
            DUMP OF SERVICE accessibility:
            enabled services:
              com.evil.spy/.SpyService
            -------------------------------------------------------------------------------
            DUMP OF SERVICE package:
            Packages:
              Package [com.example]
        """.trimIndent()

        val section = parser.extractSection(streamOf(dumpstate), "accessibility")
        assertNotNull(section)
        assertTrue(section!!.contains("com.evil.spy/.SpyService"))
        assertTrue(!section.contains("Package [com.example]"))
    }

    @Test
    fun `extracts section with dashed SERVICE header format`() {
        val dumpstate = """
            ---------- SERVICE accessibility ----------
            enabled services:
              com.evil.spy/.SpyService
            ---------- SERVICE package ----------
            Packages:
              Package [com.example]
        """.trimIndent()

        val section = parser.extractSection(streamOf(dumpstate), "accessibility")
        assertNotNull(section)
        assertTrue(section!!.contains("com.evil.spy/.SpyService"))
    }

    @Test
    fun `returns null for missing section`() {
        val dumpstate = """
            DUMP OF SERVICE package:
            Packages:
              Package [com.example]
        """.trimIndent()

        val section = parser.extractSection(streamOf(dumpstate), "nonexistent")
        assertNull(section)
    }

    @Test
    fun `extracts last section (no trailing delimiter)`() {
        val dumpstate = """
            DUMP OF SERVICE package:
            Packages:
              Package [com.example]
            DUMP OF SERVICE appops:
            Uid 10050:
              CAMERA: allow
        """.trimIndent()

        val section = parser.extractSection(streamOf(dumpstate), "appops")
        assertNotNull(section)
        assertTrue(section!!.contains("CAMERA: allow"))
    }

    // ── Multi-section extraction ─────────────────────────────────────────

    @Test
    fun `extractSections returns multiple sections in one pass`() {
        val dumpstate = """
            DUMP OF SERVICE accessibility:
            service1
            DUMP OF SERVICE package:
            packages here
            DUMP OF SERVICE appops:
            ops here
        """.trimIndent()

        val sections = parser.extractSections(
            streamOf(dumpstate),
            setOf("accessibility", "appops")
        )

        assertEquals(2, sections.size)
        assertTrue(sections["accessibility"]!!.contains("service1"))
        assertTrue(sections["appops"]!!.contains("ops here"))
        assertNull(sections["package"]) // not requested
    }

    @Test
    fun `extractSections handles missing requested sections gracefully`() {
        val dumpstate = """
            DUMP OF SERVICE package:
            packages here
        """.trimIndent()

        val sections = parser.extractSections(
            streamOf(dumpstate),
            setOf("accessibility", "package")
        )

        assertEquals(1, sections.size)
        assertNotNull(sections["package"])
        assertNull(sections["accessibility"])
    }

    // ── SYSTEM PROPERTIES extraction ─────────────────────────────────────

    @Test
    fun `extractSystemProperties returns properties section`() {
        val dumpstate = """
            some header
            ------ SYSTEM PROPERTIES ------
            [ro.build.version.sdk]: [34]
            [ro.build.display.id]: [AP1A.240305.019]
            ------ SECTION AFTER ------
            other stuff
        """.trimIndent()

        val props = parser.extractSystemProperties(streamOf(dumpstate))
        assertNotNull(props)
        assertTrue(props!!.contains("ro.build.version.sdk"))
        assertTrue(!props.contains("other stuff"))
    }

    // ── Edge cases ───────────────────────────────────────────────────────

    @Test
    fun `empty stream returns null`() {
        val section = parser.extractSection(streamOf(""), "accessibility")
        assertNull(section)
    }

    @Test
    fun `section with only whitespace content is returned`() {
        val dumpstate = """
            DUMP OF SERVICE accessibility:

            DUMP OF SERVICE package:
            stuff
        """.trimIndent()

        val section = parser.extractSection(streamOf(dumpstate), "accessibility")
        assertNotNull(section)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.scanner.bugreport.DumpsysSectionParserTest" 2>&1 | tail -5`
Expected: FAILED (class not found)

- [ ] **Step 3: Implement DumpsysSectionParser**

Create `app/src/main/java/com/androdr/scanner/bugreport/DumpsysSectionParser.kt`:

```kotlin
package com.androdr.scanner.bugreport

import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.util.zip.ZipInputStream

class DumpsysSectionParser {

    companion object {
        /** Matches "DUMP OF SERVICE <name>:" header format. */
        private val DUMP_HEADER = Regex("""^-*\s*DUMP OF SERVICE (\S+?):\s*$""")

        /** Matches "---------- SERVICE <name> ----------" header format. */
        private val DASHED_HEADER = Regex("""^-+ SERVICE (\S+?) -+$""")

        /** Matches "------ SYSTEM PROPERTIES ------". */
        private val SYSTEM_PROPS_HEADER = Regex("""^-+\s*SYSTEM PROPERTIES\s*-+$""")

        /** Any section-ending delimiter (start of a new section). */
        private fun isDelimiter(line: String): Boolean =
            DUMP_HEADER.containsMatchIn(line) || DASHED_HEADER.containsMatchIn(line)

        private fun extractServiceName(line: String): String? =
            DUMP_HEADER.find(line)?.groupValues?.get(1)
                ?: DASHED_HEADER.find(line)?.groupValues?.get(1)
    }

    /**
     * Extracts a single named section from the dumpstate stream.
     * Returns null if the section is not found.
     */
    fun extractSection(stream: InputStream, serviceName: String): String? =
        extractSections(stream, setOf(serviceName))[serviceName]

    /**
     * Extracts multiple sections in a single pass. Returns a map of
     * serviceName → section text for each requested section that was found.
     */
    fun extractSections(
        stream: InputStream,
        serviceNames: Set<String>
    ): Map<String, String> {
        val results = mutableMapOf<String, StringBuilder>()
        var currentSection: String? = null

        BufferedReader(InputStreamReader(stream, Charsets.UTF_8)).use { reader ->
            reader.forEachLine { line ->
                val name = extractServiceName(line)
                if (name != null) {
                    currentSection = if (name in serviceNames) {
                        results[name] = StringBuilder()
                        name
                    } else {
                        null
                    }
                } else if (currentSection != null) {
                    results[currentSection!!]!!.appendLine(line)
                }
            }
        }

        return results.mapValues { it.value.toString() }
    }

    /**
     * Extracts the SYSTEM PROPERTIES section from a dumpstate stream.
     */
    fun extractSystemProperties(stream: InputStream): String? {
        val sb = StringBuilder()
        var inSection = false

        BufferedReader(InputStreamReader(stream, Charsets.UTF_8)).use { reader ->
            reader.forEachLine { line ->
                when {
                    !inSection && SYSTEM_PROPS_HEADER.containsMatchIn(line) -> inSection = true
                    inSection && (isDelimiter(line) || SYSTEM_PROPS_HEADER.containsMatchIn(line)) -> {
                        return sb.toString()
                    }
                    inSection -> sb.appendLine(line)
                }
            }
        }

        return if (inSection) sb.toString() else null
    }

    /**
     * Iterates ZIP entries whose names match [namePattern].
     * Each pair is (entryName, entryInputStream). The caller must NOT close
     * the individual entry streams — the ZipInputStream manages them.
     */
    fun iterateZipEntries(
        zipStream: ZipInputStream,
        namePattern: Regex
    ): Sequence<Pair<String, InputStream>> = sequence {
        var entry = try { zipStream.nextEntry } catch (_: Exception) { null }
        while (entry != null) {
            if (!entry.isDirectory && namePattern.containsMatchIn(entry.name)) {
                yield(entry.name to (zipStream as InputStream))
            }
            try { zipStream.closeEntry() } catch (_: Exception) { }
            entry = try { zipStream.nextEntry } catch (_: Exception) { null }
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.scanner.bugreport.DumpsysSectionParserTest" 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL, all tests pass

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/bugreport/DumpsysSectionParser.kt \
       app/src/test/java/com/androdr/scanner/bugreport/DumpsysSectionParserTest.kt
git commit -m "feat: add DumpsysSectionParser for structured bugreport analysis (#32)"
```

---

## Task 5: LegacyScanModule — Extract Existing Logic

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/bugreport/LegacyScanModule.kt`
- Create: `app/src/test/java/com/androdr/scanner/bugreport/LegacyScanModuleTest.kt`

- [ ] **Step 1: Write failing tests**

These mirror the existing `BugReportAnalyzerTest` patterns but target `LegacyScanModule` directly. Create `app/src/test/java/com/androdr/scanner/bugreport/LegacyScanModuleTest.kt`:

```kotlin
package com.androdr.scanner.bugreport

import com.androdr.ioc.BadPackageInfo
import com.androdr.ioc.IocResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.InputStream

class LegacyScanModuleTest {

    private val mockIocResolver: IocResolver = mockk()
    private lateinit var module: LegacyScanModule

    @Before
    fun setUp() {
        every { mockIocResolver.isKnownBadPackage(any()) } returns null
        module = LegacyScanModule()
    }

    private fun entriesOf(vararg texts: Pair<String, String>): Sequence<Pair<String, InputStream>> =
        texts.asSequence().map { (name, text) ->
            name to ByteArrayInputStream(text.toByteArray(Charsets.UTF_8)) as InputStream
        }

    @Test
    fun `targetSections is null for raw entry scanning`() {
        assertTrue(module.targetSections == null)
    }

    @Test
    fun `spyware keyword triggers CRITICAL finding`() = runBlocking {
        val result = module.analyzeRaw(
            entriesOf("logcat" to "I/ActivityManager: Start proc com.pegasus.spyservice"),
            mockIocResolver
        )
        assertTrue(result.findings.any { it.severity == "CRITICAL" && it.category == "KnownMalware" })
    }

    @Test
    fun `base64 blob triggers HIGH finding`() = runBlocking {
        val blob = "A".repeat(120)
        val result = module.analyzeRaw(
            entriesOf("dumpstate" to "D/Upload: payload=$blob"),
            mockIocResolver
        )
        assertTrue(result.findings.any { it.severity == "HIGH" && it.category == "SuspiciousData" })
    }

    @Test
    fun `C2 beacon triggers CRITICAL finding`() = runBlocking {
        val result = module.analyzeRaw(
            entriesOf("bugreport" to "D/Network: HTTP POST to c2.evil.com every 300 seconds"),
            mockIocResolver
        )
        assertTrue(result.findings.any { it.severity == "CRITICAL" && it.category == "C2Beacon" })
    }

    @Test
    fun `crash loop triggers HIGH finding at threshold of 3`() = runBlocking {
        val text = (1..3).joinToString("\n") { "E/AndroidRuntime: FATAL EXCEPTION: com.evil.proc" }
        val result = module.analyzeRaw(entriesOf("logcat" to text), mockIocResolver)
        assertTrue(result.findings.any { it.severity == "HIGH" && it.category == "CrashLoop" })
    }

    @Test
    fun `IOC package match triggers finding with DB severity`() = runBlocking {
        every { mockIocResolver.isKnownBadPackage("com.flexispy.android") } returns BadPackageInfo(
            packageName = "com.flexispy.android",
            name = "FlexiSPY",
            category = "STALKERWARE",
            severity = "CRITICAL",
            description = "Commercial stalkerware."
        )
        val result = module.analyzeRaw(
            entriesOf("dumpstate" to "    package:com.flexispy.android"),
            mockIocResolver
        )
        assertEquals(1, result.findings.size)
        assertTrue(result.findings[0].description.contains("FlexiSPY"))
    }

    @Test
    fun `clean input produces empty result`() = runBlocking {
        val result = module.analyzeRaw(
            entriesOf("logcat" to "I/System: Boot completed"),
            mockIocResolver
        )
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `timeline is always empty for legacy module`() = runBlocking {
        val result = module.analyzeRaw(
            entriesOf("logcat" to "I/ActivityManager: Start proc com.pegasus.spy"),
            mockIocResolver
        )
        assertTrue(result.timeline.isEmpty())
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.scanner.bugreport.LegacyScanModuleTest" 2>&1 | tail -5`
Expected: FAILED (class not found)

- [ ] **Step 3: Implement LegacyScanModule**

Create `app/src/main/java/com/androdr/scanner/bugreport/LegacyScanModule.kt`. This extracts the logic from `BugReportAnalyzer.analyzeTextEntry()`:

```kotlin
package com.androdr.scanner.bugreport

import com.androdr.ioc.IocResolver
import com.androdr.scanner.BugReportAnalyzer.BugReportFinding
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class LegacyScanModule @Inject constructor() : BugreportModule {

    override val targetSections: List<String>? = null

    private val spywareProcessRegex = Regex(
        """pegasus|spyware|flexispy|mspy|cerberus|droiddream|BIGPRETZEL|graphite""",
        RegexOption.IGNORE_CASE
    )
    private val base64BlobRegex = Regex("""[A-Za-z0-9+/]{100,}={0,2}""")
    private val c2BeaconRegex = Regex("""HTTP.*POST.*every\s+[0-9]+""", RegexOption.IGNORE_CASE)
    private val fatalExceptionRegex = Regex("""FATAL EXCEPTION:\s*(\S+)""", RegexOption.IGNORE_CASE)
    private val wakelockRegex = Regex("""WakeLock.*acquired""", RegexOption.IGNORE_CASE)
    private val installedPackageRegex = Regex("""^.*package:([a-zA-Z][a-zA-Z0-9._]+)""", RegexOption.MULTILINE)

    private val relevantEntryNames = listOf("dumpstate", "logcat", "bugreport")

    override suspend fun analyzeRaw(
        entries: Sequence<Pair<String, InputStream>>,
        iocResolver: IocResolver
    ): ModuleResult {
        val findings = mutableListOf<BugReportFinding>()
        for ((entryName, stream) in entries) {
            val name = entryName.lowercase()
            if (relevantEntryNames.any { name.contains(it) }) {
                findings.addAll(analyzeTextEntry(entryName, stream, iocResolver))
            }
        }
        return ModuleResult(findings = findings, timeline = emptyList())
    }

    @Suppress("LongMethod", "CyclomaticComplexMethod")
    internal fun analyzeTextEntry(
        entryName: String,
        stream: InputStream,
        iocResolver: IocResolver
    ): List<BugReportFinding> {
        val findings = mutableListOf<BugReportFinding>()
        val fatalCrashCounts = mutableMapOf<String, Int>()
        var wakelockCount = 0
        var firstWakelockLine = -1
        var lastWakelockLine = -1
        var lineNumber = 0

        try {
            BufferedReader(InputStreamReader(stream, Charsets.UTF_8)).forEachLine { line ->
                lineNumber++

                var iocHitOnLine = false
                installedPackageRegex.findAll(line).forEach { match ->
                    val pkgName = match.groupValues[1]
                    val iocHit = iocResolver.isKnownBadPackage(pkgName)
                    if (iocHit != null) {
                        iocHitOnLine = true
                        findings.add(BugReportFinding(
                            severity = iocHit.severity,
                            category = "KnownMalware",
                            description = "Known ${iocHit.category} package '$pkgName' " +
                                "(${iocHit.name}) found in installed package list within " +
                                "$entryName — ${iocHit.description}"
                        ))
                    }
                }

                if (!iocHitOnLine) {
                    val spyMatch = spywareProcessRegex.find(line)
                    if (spyMatch != null) {
                        findings.add(BugReportFinding(
                            severity = "CRITICAL",
                            category = "KnownMalware",
                            description = "Known spyware/stalkerware keyword '${spyMatch.value}' " +
                                "detected in $entryName at line $lineNumber: " +
                                line.take(200).trim()
                        ))
                    }
                }

                val b64Match = base64BlobRegex.find(line)
                if (b64Match != null) {
                    findings.add(BugReportFinding(
                        severity = "HIGH",
                        category = "SuspiciousData",
                        description = "Suspicious large base64 blob (${b64Match.value.length} chars) " +
                            "in $entryName at line $lineNumber — possible exfiltration payload"
                    ))
                }

                if (c2BeaconRegex.containsMatchIn(line)) {
                    findings.add(BugReportFinding(
                        severity = "CRITICAL",
                        category = "C2Beacon",
                        description = "Potential C2 beacon pattern in $entryName at line $lineNumber: " +
                            line.take(200).trim()
                    ))
                }

                val crashMatch = fatalExceptionRegex.find(line)
                if (crashMatch != null) {
                    val processName = crashMatch.groupValues[1].ifBlank { "unknown" }
                    fatalCrashCounts[processName] = (fatalCrashCounts[processName] ?: 0) + 1
                }

                if (wakelockRegex.containsMatchIn(line)) {
                    wakelockCount++
                    if (firstWakelockLine < 0) firstWakelockLine = lineNumber
                    lastWakelockLine = lineNumber
                }
            }
        } catch (e: Exception) {
            findings.add(BugReportFinding(
                severity = "ERROR",
                category = "IO",
                description = "Error while reading entry '$entryName': ${e.message}"
            ))
        }

        for ((processName, count) in fatalCrashCounts) {
            if (count >= 3) {
                findings.add(BugReportFinding(
                    severity = "HIGH",
                    category = "CrashLoop",
                    description = "Process '$processName' crashed $count times in $entryName — " +
                        "possible crash-loop from aggressive respawn (common in stalkerware)"
                ))
            }
        }

        if (wakelockCount >= 10 && lastWakelockLine > firstWakelockLine) {
            val lineSpan = lastWakelockLine - firstWakelockLine
            val density = wakelockCount.toDouble() / lineSpan.coerceAtLeast(1)
            if (density > 0.2) {
                findings.add(BugReportFinding(
                    severity = "MEDIUM",
                    category = "AbnormalWakelock",
                    description = "$wakelockCount WakeLock acquisitions over $lineSpan lines " +
                        "in $entryName — abnormally high density may indicate persistent " +
                        "background surveillance activity"
                ))
            }
        }

        return findings
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.scanner.bugreport.LegacyScanModuleTest" 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL, all tests pass

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/bugreport/LegacyScanModule.kt \
       app/src/test/java/com/androdr/scanner/bugreport/LegacyScanModuleTest.kt
git commit -m "feat: extract LegacyScanModule from BugReportAnalyzer"
```

---

## Task 6: Refactor BugReportAnalyzer to Module Dispatcher

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/BugReportAnalyzer.kt`
- Create: `app/src/main/java/com/androdr/di/BugreportModuleBindings.kt`
- Existing test: `app/src/test/java/com/androdr/scanner/BugReportAnalyzerTest.kt` (must still pass)

- [ ] **Step 1: Create Hilt multibinding module**

Create `app/src/main/java/com/androdr/di/BugreportModuleBindings.kt`:

```kotlin
package com.androdr.di

import com.androdr.scanner.bugreport.BugreportModule
import com.androdr.scanner.bugreport.LegacyScanModule
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dagger.multibindings.IntoSet

@Module
@InstallIn(SingletonComponent::class)
abstract class BugreportModuleBindings {
    @Binds @IntoSet abstract fun legacy(m: LegacyScanModule): BugreportModule
}
```

- [ ] **Step 2: Refactor BugReportAnalyzer**

Replace the entire content of `app/src/main/java/com/androdr/scanner/BugReportAnalyzer.kt`:

```kotlin
package com.androdr.scanner

import android.content.Context
import android.net.Uri
import android.util.Log
import com.androdr.data.model.TimelineEvent
import com.androdr.ioc.IocResolver
import com.androdr.scanner.bugreport.BugreportModule
import com.androdr.scanner.bugreport.DumpsysSectionParser
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.util.zip.ZipInputStream
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class BugReportAnalyzer @Inject constructor(
    @ApplicationContext private val context: Context,
    private val iocResolver: IocResolver,
    private val modules: Set<@JvmSuppressWildcards BugreportModule>
) {

    data class BugReportFinding(
        val severity: String,
        val category: String,
        val description: String
    )

    private val sectionParser = DumpsysSectionParser()

    /** Entry names that are the main dumpstate file. */
    private val dumpstateEntryPattern = Regex("dumpstate|bugreport", RegexOption.IGNORE_CASE)

    @Suppress("TooGenericExceptionCaught")
    suspend fun analyze(bugReportUri: Uri): List<BugReportFinding> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<BugReportFinding>()
        val timelineEvents = mutableListOf<TimelineEvent>()

        val inputStream = try {
            context.contentResolver.openInputStream(bugReportUri)
        } catch (e: Exception) {
            findings.add(BugReportFinding("ERROR", "IO",
                "Could not open bug report file: ${e.message}"))
            return@withContext findings
        } ?: run {
            findings.add(BugReportFinding("ERROR", "IO",
                "ContentResolver returned null stream for the provided URI"))
            return@withContext findings
        }

        try {
            val sectionModules = modules.filter { it.targetSections != null }
            val rawModules = modules.filter { it.targetSections == null }

            // Collect all needed section names
            val neededSections = sectionModules
                .flatMap { it.targetSections!! }
                .toSet()

            // First pass: extract dumpsys sections from the dumpstate entry
            var extractedSections: Map<String, String> = emptyMap()
            // Collect raw entries for raw modules
            val rawEntries = mutableListOf<Pair<String, ByteArray>>()

            ZipInputStream(inputStream.buffered()).use { zip ->
                var entry = zip.nextEntry
                while (entry != null) {
                    if (!entry.isDirectory) {
                        val name = entry.name
                        if (dumpstateEntryPattern.containsMatchIn(name.substringAfterLast("/"))) {
                            // This is a dumpstate file — extract sections
                            val content = zip.readBytes()
                            if (neededSections.isNotEmpty()) {
                                extractedSections = sectionParser.extractSections(
                                    content.inputStream(), neededSections
                                )
                            }
                            // Also save for raw modules
                            rawEntries.add(name to content)
                        } else {
                            // Non-dumpstate entry — save for raw modules
                            rawEntries.add(name to zip.readBytes())
                        }
                    }
                    try { zip.closeEntry() } catch (_: Exception) { }
                    entry = try { zip.nextEntry } catch (_: Exception) { null }
                }
            }

            // Run section-targeted modules
            for (module in sectionModules) {
                for (sectionName in module.targetSections!!) {
                    val sectionText = extractedSections[sectionName] ?: continue
                    try {
                        val result = module.analyze(sectionText, iocResolver)
                        findings.addAll(result.findings)
                        timelineEvents.addAll(result.timeline)
                    } catch (e: Exception) {
                        Log.w(TAG, "Module failed on section $sectionName: ${e.message}")
                    }
                }
            }

            // Run raw-entry modules
            if (rawModules.isNotEmpty()) {
                val entrySequence = rawEntries.asSequence().map { (name, bytes) ->
                    name to bytes.inputStream() as InputStream
                }
                for (module in rawModules) {
                    try {
                        val result = module.analyzeRaw(entrySequence, iocResolver)
                        findings.addAll(result.findings)
                        timelineEvents.addAll(result.timeline)
                    } catch (e: Exception) {
                        Log.w(TAG, "Raw module failed: ${e.message}")
                    }
                }
            }

        } catch (e: Exception) {
            findings.add(BugReportFinding("ERROR", "IO",
                "Failed to read zip contents: ${e.message}"))
        }

        // Timeline events stored for future use (issue #41)
        if (timelineEvents.isNotEmpty()) {
            Log.d(TAG, "Collected ${timelineEvents.size} timeline events")
        }

        findings
    }

    fun getInstructions(): String = """
        How to generate an Android Bug Report for AndroDR analysis:

        1. Enable Developer Options (if not already enabled):
           • Open Settings → About Phone
           • Tap "Build Number" seven times until you see "You are now a developer!"

        2. Open Developer Options:
           • Go to Settings → System → Developer Options
             (on some devices: Settings → Developer Options)

        3. Generate the bug report:
           • Scroll down to find "Take Bug Report"
           • Tap it, then select "Full Report" for the most complete analysis
           • Wait for the report to be compiled (this can take 1–3 minutes)
           • When notified, tap the notification to share the report

        4. Import into AndroDR:
           • In the share sheet, choose "AndroDR" to import directly
           • Or save the .zip file and use the "Analyze Bug Report" button in AndroDR

        Note: Bug reports contain extensive system information. Only share them
        with applications you trust. AndroDR processes the report entirely on
        your device — nothing is uploaded to external servers.
    """.trimIndent()

    companion object {
        private const val TAG = "BugReportAnalyzer"
    }
}
```

- [ ] **Step 3: Update BugReportAnalyzerTest for new constructor**

In `app/src/test/java/com/androdr/scanner/BugReportAnalyzerTest.kt`, the `setUp()` method needs to pass the modules set. Update line 22 (`analyzer = BugReportAnalyzer(mockContext, mockIocResolver)`):

Replace:
```kotlin
    private lateinit var analyzer: BugReportAnalyzer

    @Before
    fun setUp() {
        every { mockIocResolver.isKnownBadPackage(any()) } returns null
        analyzer = BugReportAnalyzer(mockContext, mockIocResolver)
    }
```

With:
```kotlin
    private lateinit var analyzer: BugReportAnalyzer
    private lateinit var legacyModule: com.androdr.scanner.bugreport.LegacyScanModule

    @Before
    fun setUp() {
        every { mockIocResolver.isKnownBadPackage(any()) } returns null
        legacyModule = com.androdr.scanner.bugreport.LegacyScanModule()
        analyzer = BugReportAnalyzer(mockContext, mockIocResolver, setOf(legacyModule))
    }
```

The existing `analyzeTextEntry` tests call `analyzer.analyzeTextEntry()` directly — that method no longer exists on `BugReportAnalyzer`. These tests should be redirected to `legacyModule.analyzeTextEntry()`. Replace all occurrences of `analyzer.analyzeTextEntry(` with `legacyModule.analyzeTextEntry(`:

```kotlin
    // Every test that calls analyzer.analyzeTextEntry should now call:
    // legacyModule.analyzeTextEntry("logcat", streamOf(text), mockIocResolver)
```

Specifically, update the method signature — `legacyModule.analyzeTextEntry` takes 3 params `(entryName, stream, iocResolver)` vs the old 2 params. Add `mockIocResolver` as the third argument to every call. For example:

```kotlin
    @Test
    fun `spyware keyword triggers CRITICAL KnownMalware finding`() {
        val text = "I/ActivityManager: Start proc com.pegasus.spyservice for service"
        val findings = legacyModule.analyzeTextEntry("logcat", streamOf(text), mockIocResolver)
        assertTrue(findings.any { it.severity == "CRITICAL" && it.category == "KnownMalware" })
    }
```

Apply the same pattern to all 13 test methods: replace `analyzer.analyzeTextEntry("xxx", streamOf(text))` with `legacyModule.analyzeTextEntry("xxx", streamOf(text), mockIocResolver)`.

- [ ] **Step 4: Run existing tests to verify backward compatibility**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.scanner.BugReportAnalyzerTest" 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL, all 13 tests pass

Run: `./gradlew testDebugUnitTest 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL, full test suite passes

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/BugReportAnalyzer.kt \
       app/src/main/java/com/androdr/di/BugreportModuleBindings.kt \
       app/src/test/java/com/androdr/scanner/BugReportAnalyzerTest.kt
git commit -m "refactor: convert BugReportAnalyzer to module dispatcher with Hilt multibinding"
```

---

## Task 7: AccessibilityModule (Bugreport) (#35 — part 1)

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/bugreport/AccessibilityModule.kt`
- Create: `app/src/test/java/com/androdr/scanner/bugreport/AccessibilityModuleTest.kt`
- Modify: `app/src/main/java/com/androdr/di/BugreportModuleBindings.kt`

- [ ] **Step 1: Write failing tests**

Create `app/src/test/java/com/androdr/scanner/bugreport/AccessibilityModuleTest.kt`:

```kotlin
package com.androdr.scanner.bugreport

import com.androdr.ioc.IocResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class AccessibilityModuleTest {

    private val mockIocResolver: IocResolver = mockk()
    private lateinit var module: AccessibilityModule

    @Before
    fun setUp() {
        every { mockIocResolver.isKnownBadPackage(any()) } returns null
        module = AccessibilityModule()
    }

    @Test
    fun `targetSections is accessibility`() {
        assertEquals(listOf("accessibility"), module.targetSections)
    }

    @Test
    fun `detects enabled accessibility service`() = runBlocking {
        val section = """
            User state[userData:0 currentUser:0]:
              isEnabled=1
              Enabled services:
                com.evil.spy/.SpyAccessibilityService
                com.google.android.marvin.talkback/.TalkBackService
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.any {
            it.category == "AccessibilityAbuse" &&
                it.description.contains("com.evil.spy")
        })
    }

    @Test
    fun `ignores known system accessibility services`() = runBlocking {
        val section = """
            User state[userData:0 currentUser:0]:
              isEnabled=1
              Enabled services:
                com.google.android.marvin.talkback/.TalkBackService
                com.samsung.accessibility/.universalswitch.UniversalSwitchService
                com.android.talkback/.TalkBackService
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `flags IOC-matched accessibility service as CRITICAL`() = runBlocking {
        val iocInfo = com.androdr.ioc.BadPackageInfo(
            packageName = "com.flexispy.android",
            name = "FlexiSPY",
            category = "STALKERWARE",
            severity = "CRITICAL",
            description = "Commercial stalkerware"
        )
        every { mockIocResolver.isKnownBadPackage("com.flexispy.android") } returns iocInfo

        val section = """
            Enabled services:
                com.flexispy.android/.AccessibilityHelper
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.any {
            it.severity == "CRITICAL" && it.description.contains("FlexiSPY")
        })
    }

    @Test
    fun `empty section produces no findings`() = runBlocking {
        val result = module.analyze("", mockIocResolver)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `section without Enabled services line produces no findings`() = runBlocking {
        val section = """
            User state[userData:0 currentUser:0]:
              isEnabled=0
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.isEmpty())
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.scanner.bugreport.AccessibilityModuleTest" 2>&1 | tail -5`
Expected: FAILED (class not found)

- [ ] **Step 3: Implement AccessibilityModule**

Create `app/src/main/java/com/androdr/scanner/bugreport/AccessibilityModule.kt`:

```kotlin
package com.androdr.scanner.bugreport

import com.androdr.ioc.IocResolver
import com.androdr.scanner.BugReportAnalyzer.BugReportFinding
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AccessibilityModule @Inject constructor() : BugreportModule {

    override val targetSections: List<String> = listOf("accessibility")

    /** Known-good system accessibility service package prefixes. */
    private val systemServicePrefixes = listOf(
        "com.google.android.marvin.talkback",
        "com.google.android.accessibility",
        "com.android.talkback",
        "com.samsung.accessibility",
        "com.samsung.android.accessibility",
        "com.android.switchaccess",
        "com.google.android.apps.accessibility"
    )

    /** Matches "com.package.name/.ServiceName" in the enabled services list. */
    private val enabledServiceRegex = Regex(
        """^\s+([a-zA-Z][a-zA-Z0-9._]+)/(\.\w+)""",
        RegexOption.MULTILINE
    )

    override suspend fun analyze(sectionText: String, iocResolver: IocResolver): ModuleResult {
        val findings = mutableListOf<BugReportFinding>()

        enabledServiceRegex.findAll(sectionText).forEach { match ->
            val packageName = match.groupValues[1]
            val serviceName = match.groupValues[2]

            // Check IOC database first
            val iocHit = iocResolver.isKnownBadPackage(packageName)
            if (iocHit != null) {
                findings.add(BugReportFinding(
                    severity = iocHit.severity,
                    category = "AccessibilityAbuse",
                    description = "Known ${iocHit.category} package '$packageName' " +
                        "(${iocHit.name}) has an active accessibility service " +
                        "'$serviceName' — ${iocHit.description}"
                ))
                return@forEach
            }

            // Skip known system services
            if (systemServicePrefixes.any { packageName.startsWith(it) }) {
                return@forEach
            }

            // Flag unknown non-system accessibility services
            findings.add(BugReportFinding(
                severity = "HIGH",
                category = "AccessibilityAbuse",
                description = "Non-system accessibility service enabled: " +
                    "$packageName/$serviceName — accessibility services can read " +
                    "screen content and perform actions on behalf of the user"
            ))
        }

        return ModuleResult(findings = findings, timeline = emptyList())
    }
}
```

- [ ] **Step 4: Register in Hilt bindings**

In `app/src/main/java/com/androdr/di/BugreportModuleBindings.kt`, add the binding:

```kotlin
import com.androdr.scanner.bugreport.AccessibilityModule

    @Binds @IntoSet abstract fun accessibility(m: AccessibilityModule): BugreportModule
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.scanner.bugreport.AccessibilityModuleTest" 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL, all tests pass

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/bugreport/AccessibilityModule.kt \
       app/src/test/java/com/androdr/scanner/bugreport/AccessibilityModuleTest.kt \
       app/src/main/java/com/androdr/di/BugreportModuleBindings.kt
git commit -m "feat: add AccessibilityModule for bugreport analysis (#35)"
```

---

## Task 8: ReceiverModule (Bugreport) (#34 — part 1)

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/bugreport/ReceiverModule.kt`
- Create: `app/src/test/java/com/androdr/scanner/bugreport/ReceiverModuleTest.kt`
- Modify: `app/src/main/java/com/androdr/di/BugreportModuleBindings.kt`

- [ ] **Step 1: Write failing tests**

Create `app/src/test/java/com/androdr/scanner/bugreport/ReceiverModuleTest.kt`:

```kotlin
package com.androdr.scanner.bugreport

import com.androdr.ioc.IocResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ReceiverModuleTest {

    private val mockIocResolver: IocResolver = mockk()
    private lateinit var module: ReceiverModule

    @Before
    fun setUp() {
        every { mockIocResolver.isKnownBadPackage(any()) } returns null
        module = ReceiverModule()
    }

    @Test
    fun `targetSections is package`() {
        assertEquals(listOf("package"), module.targetSections)
    }

    @Test
    fun `detects non-system SMS_RECEIVED receiver`() = runBlocking {
        val section = """
            Receiver Resolver Table:
              Non-Data Actions:
                  android.provider.Telephony.SMS_RECEIVED:
                    12345 com.evil.sms/.SmsReceiver filter abcdef
                      Action: "android.provider.Telephony.SMS_RECEIVED"
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.any {
            it.category == "ReceiverAbuse" &&
                it.description.contains("com.evil.sms") &&
                it.description.contains("SMS_RECEIVED")
        })
    }

    @Test
    fun `detects PHONE_STATE receiver`() = runBlocking {
        val section = """
            Receiver Resolver Table:
              Non-Data Actions:
                  android.intent.action.PHONE_STATE:
                    12345 com.spy.calls/.CallReceiver filter abcdef
                      Action: "android.intent.action.PHONE_STATE"
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.any {
            it.category == "ReceiverAbuse" &&
                it.description.contains("com.spy.calls")
        })
    }

    @Test
    fun `ignores system package receivers`() = runBlocking {
        val section = """
            Receiver Resolver Table:
              Non-Data Actions:
                  android.provider.Telephony.SMS_RECEIVED:
                    1000 com.android.phone/.SmsReceiver filter abcdef
                      Action: "android.provider.Telephony.SMS_RECEIVED"
                    1000 com.google.android.gms/.SmsReceiver filter abcdef
                      Action: "android.provider.Telephony.SMS_RECEIVED"
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `flags IOC-matched receiver as CRITICAL`() = runBlocking {
        val iocInfo = com.androdr.ioc.BadPackageInfo(
            packageName = "com.stalker.app",
            name = "StalkerApp",
            category = "STALKERWARE",
            severity = "CRITICAL",
            description = "Known stalkerware"
        )
        every { mockIocResolver.isKnownBadPackage("com.stalker.app") } returns iocInfo

        val section = """
            Receiver Resolver Table:
              Non-Data Actions:
                  android.provider.Telephony.SMS_RECEIVED:
                    12345 com.stalker.app/.SmsInterceptor filter abcdef
                      Action: "android.provider.Telephony.SMS_RECEIVED"
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.any {
            it.severity == "CRITICAL" && it.description.contains("StalkerApp")
        })
    }

    @Test
    fun `detects all 5 sensitive intents`() = runBlocking {
        val intents = listOf(
            "android.provider.Telephony.SMS_RECEIVED",
            "android.provider.Telephony.NEW_OUTGOING_SMS",
            "android.intent.action.DATA_SMS_RECEIVED",
            "android.intent.action.PHONE_STATE",
            "android.intent.action.NEW_OUTGOING_CALL"
        )
        for (intent in intents) {
            val section = """
                Receiver Resolver Table:
                  Non-Data Actions:
                      $intent:
                        12345 com.evil.app/.Receiver filter abcdef
                          Action: "$intent"
            """.trimIndent()

            val result = module.analyze(section, mockIocResolver)
            assertTrue("Expected detection for $intent",
                result.findings.any { it.category == "ReceiverAbuse" })
        }
    }

    @Test
    fun `empty section produces no findings`() = runBlocking {
        val result = module.analyze("", mockIocResolver)
        assertTrue(result.findings.isEmpty())
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.scanner.bugreport.ReceiverModuleTest" 2>&1 | tail -5`
Expected: FAILED (class not found)

- [ ] **Step 3: Implement ReceiverModule**

Create `app/src/main/java/com/androdr/scanner/bugreport/ReceiverModule.kt`:

```kotlin
package com.androdr.scanner.bugreport

import com.androdr.ioc.IocResolver
import com.androdr.scanner.BugReportAnalyzer.BugReportFinding
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ReceiverModule @Inject constructor() : BugreportModule {

    override val targetSections: List<String> = listOf("package")

    /** The 5 sensitive broadcast intents that stalkerware commonly intercepts. */
    private val sensitiveIntents = setOf(
        "android.provider.Telephony.SMS_RECEIVED",
        "android.provider.Telephony.NEW_OUTGOING_SMS",
        "android.intent.action.DATA_SMS_RECEIVED",
        "android.intent.action.PHONE_STATE",
        "android.intent.action.NEW_OUTGOING_CALL"
    )

    /** Known system packages that legitimately handle SMS/call broadcasts. */
    private val systemPackagePrefixes = listOf(
        "com.android.",
        "com.google.android.",
        "com.samsung.android.",
        "com.sec.android.",
        "com.qualcomm.",
        "com.mediatek."
    )

    /**
     * Matches package entries under a sensitive intent in the Receiver Resolver Table.
     * Format: "    12345 com.package.name/.ReceiverName filter abcdef"
     */
    private val receiverEntryRegex = Regex(
        """^\s+\d+\s+([a-zA-Z][a-zA-Z0-9._]+)/(\.?\w+)""",
        RegexOption.MULTILINE
    )

    override suspend fun analyze(sectionText: String, iocResolver: IocResolver): ModuleResult {
        val findings = mutableListOf<BugReportFinding>()

        // Find the Receiver Resolver Table section
        val receiverTableStart = sectionText.indexOf("Receiver Resolver Table:")
        if (receiverTableStart < 0) return ModuleResult(findings, emptyList())

        // Find Non-Data Actions subsection
        val nonDataStart = sectionText.indexOf("Non-Data Actions:", receiverTableStart)
        if (nonDataStart < 0) return ModuleResult(findings, emptyList())

        // Parse each sensitive intent's receiver list
        for (intent in sensitiveIntents) {
            val intentStart = sectionText.indexOf("$intent:", nonDataStart)
            if (intentStart < 0) continue

            // Find end of this intent's block (next intent or end of section)
            val blockEnd = findNextIntentOrSectionEnd(sectionText, intentStart + intent.length)
            val block = sectionText.substring(intentStart, blockEnd)

            receiverEntryRegex.findAll(block).forEach { match ->
                val packageName = match.groupValues[1]
                val componentName = match.groupValues[2]

                // Check IOC database
                val iocHit = iocResolver.isKnownBadPackage(packageName)
                if (iocHit != null) {
                    findings.add(BugReportFinding(
                        severity = iocHit.severity,
                        category = "ReceiverAbuse",
                        description = "Known ${iocHit.category} package '$packageName' " +
                            "(${iocHit.name}) registered for $intent broadcast — " +
                            iocHit.description
                    ))
                    return@forEach
                }

                // Skip system packages
                if (systemPackagePrefixes.any { packageName.startsWith(it) }) {
                    return@forEach
                }

                findings.add(BugReportFinding(
                    severity = "CRITICAL",
                    category = "ReceiverAbuse",
                    description = "Non-system app '$packageName/$componentName' " +
                        "registered for $intent broadcast — this is a strong " +
                        "stalkerware indicator"
                ))
            }
        }

        return ModuleResult(findings = findings, timeline = emptyList())
    }

    private fun findNextIntentOrSectionEnd(text: String, fromIndex: Int): Int {
        // Look for next line that starts a new intent (non-whitespace-indented line with ":")
        val nextIntent = Regex("""^\s{18,}\S""", RegexOption.MULTILINE)
            .find(text, fromIndex)
        // Also look for next major section header
        val nextSection = text.indexOf("\n  ", fromIndex + 1)
            .takeIf { it > 0 && it < text.length - 3 && !text[it + 3].isWhitespace() }

        val candidates = listOfNotNull(
            nextIntent?.range?.first,
            nextSection,
            text.length
        )
        return candidates.min()
    }
}
```

- [ ] **Step 4: Register in Hilt bindings**

In `app/src/main/java/com/androdr/di/BugreportModuleBindings.kt`, add:

```kotlin
import com.androdr.scanner.bugreport.ReceiverModule

    @Binds @IntoSet abstract fun receivers(m: ReceiverModule): BugreportModule
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.scanner.bugreport.ReceiverModuleTest" 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL, all tests pass

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/bugreport/ReceiverModule.kt \
       app/src/test/java/com/androdr/scanner/bugreport/ReceiverModuleTest.kt \
       app/src/main/java/com/androdr/di/BugreportModuleBindings.kt
git commit -m "feat: add ReceiverModule for SMS/call broadcast interception detection (#34)"
```

---

## Task 9: AppOpsModule (Bugreport) (#33 — part 1)

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/bugreport/AppOpsModule.kt`
- Create: `app/src/test/java/com/androdr/scanner/bugreport/AppOpsModuleTest.kt`
- Modify: `app/src/main/java/com/androdr/di/BugreportModuleBindings.kt`

- [ ] **Step 1: Write failing tests**

Create `app/src/test/java/com/androdr/scanner/bugreport/AppOpsModuleTest.kt`:

```kotlin
package com.androdr.scanner.bugreport

import com.androdr.ioc.IocResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class AppOpsModuleTest {

    private val mockIocResolver: IocResolver = mockk()
    private lateinit var module: AppOpsModule

    @Before
    fun setUp() {
        every { mockIocResolver.isKnownBadPackage(any()) } returns null
        module = AppOpsModule()
    }

    @Test
    fun `targetSections is appops`() {
        assertEquals(listOf("appops"), module.targetSections)
    }

    @Test
    fun `detects REQUEST_INSTALL_PACKAGES usage`() = runBlocking {
        val section = """
            Uid 10150:
              Package com.suspicious.installer:
                REQUEST_INSTALL_PACKAGES (allow):
                  Access: [fg-s] 2026-03-27 14:30:00
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.any {
            it.category == "AppOpsAbuse" &&
                it.description.contains("REQUEST_INSTALL_PACKAGES") &&
                it.description.contains("com.suspicious.installer")
        })
    }

    @Test
    fun `detects shell package permission usage`() = runBlocking {
        val section = """
            Uid 2000:
              Package com.android.shell:
                CAMERA (allow):
                  Access: [fg-s] 2026-03-27 14:30:00
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.any {
            it.category == "AppOpsAbuse" &&
                it.description.contains("com.android.shell")
        })
    }

    @Test
    fun `flags IOC-matched package as CRITICAL`() = runBlocking {
        val iocInfo = com.androdr.ioc.BadPackageInfo(
            packageName = "com.flexispy.android",
            name = "FlexiSPY",
            category = "STALKERWARE",
            severity = "CRITICAL",
            description = "Commercial stalkerware"
        )
        every { mockIocResolver.isKnownBadPackage("com.flexispy.android") } returns iocInfo

        val section = """
            Uid 10200:
              Package com.flexispy.android:
                CAMERA (allow):
                  Access: [fg-s] 2026-03-27 14:30:00
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.any {
            it.severity == "CRITICAL" && it.description.contains("FlexiSPY")
        })
    }

    @Test
    fun `generates timeline events for permission access`() = runBlocking {
        val section = """
            Uid 10150:
              Package com.some.app:
                CAMERA (allow):
                  Access: [fg-s] 2026-03-27 14:30:00
                RECORD_AUDIO (allow):
                  Access: [fg-s] 2026-03-27 14:35:00
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.timeline.any { it.category == "permission_use" })
    }

    @Test
    fun `normal system app ops do not trigger findings`() = runBlocking {
        val section = """
            Uid 1000:
              Package com.android.systemui:
                WAKE_LOCK (allow):
                  Access: [fg-s] 2026-03-27 14:30:00
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `empty section produces no findings`() = runBlocking {
        val result = module.analyze("", mockIocResolver)
        assertTrue(result.findings.isEmpty())
        assertTrue(result.timeline.isEmpty())
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.scanner.bugreport.AppOpsModuleTest" 2>&1 | tail -5`
Expected: FAILED (class not found)

- [ ] **Step 3: Implement AppOpsModule**

Create `app/src/main/java/com/androdr/scanner/bugreport/AppOpsModule.kt`:

```kotlin
package com.androdr.scanner.bugreport

import com.androdr.data.model.TimelineEvent
import com.androdr.ioc.IocResolver
import com.androdr.scanner.BugReportAnalyzer.BugReportFinding
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AppOpsModule @Inject constructor() : BugreportModule {

    override val targetSections: List<String> = listOf("appops")

    /** Operations that are risky when used by non-system apps. */
    private val riskyOps = setOf("REQUEST_INSTALL_PACKAGES")

    /** Packages whose op usage is inherently suspicious. */
    private val riskyPackages = setOf("com.android.shell")

    /** Dangerous operations worth tracking in the timeline. */
    private val dangerousOps = setOf(
        "CAMERA", "RECORD_AUDIO", "READ_SMS", "RECEIVE_SMS", "SEND_SMS",
        "READ_CONTACTS", "READ_CALL_LOG", "ACCESS_FINE_LOCATION",
        "READ_EXTERNAL_STORAGE", "REQUEST_INSTALL_PACKAGES"
    )

    /** Matches "Package <name>:" lines under a Uid block. */
    private val packageLineRegex = Regex("""^\s+Package\s+(\S+):""", RegexOption.MULTILINE)

    /** Matches "<OP_NAME> (allow|deny|...):" lines. */
    private val opLineRegex = Regex("""^\s+(\w+)\s+\((\w+)\):""", RegexOption.MULTILINE)

    /** Matches "Access: [mode] <timestamp>" lines. */
    private val accessLineRegex = Regex(
        """Access:\s+\[\S+]\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"""
    )

    /** Matches "Uid <number>:" to detect UID for system vs user classification. */
    private val uidLineRegex = Regex("""^Uid\s+(\d+):""", RegexOption.MULTILINE)

    override suspend fun analyze(sectionText: String, iocResolver: IocResolver): ModuleResult {
        val findings = mutableListOf<BugReportFinding>()
        val timeline = mutableListOf<TimelineEvent>()

        // Split into per-UID blocks
        val uidBlocks = splitByUid(sectionText)

        for ((uid, block) in uidBlocks) {
            val isSystemUid = uid < 10000

            // Find all packages in this UID block
            packageLineRegex.findAll(block).forEach pkgLoop@{ pkgMatch ->
                val packageName = pkgMatch.groupValues[1]
                val pkgStart = pkgMatch.range.last
                val pkgEnd = findNextPackageOrEnd(block, pkgStart)
                val pkgBlock = block.substring(pkgStart, pkgEnd)

                // IOC check
                val iocHit = iocResolver.isKnownBadPackage(packageName)
                if (iocHit != null) {
                    findings.add(BugReportFinding(
                        severity = iocHit.severity,
                        category = "AppOpsAbuse",
                        description = "Known ${iocHit.category} package '$packageName' " +
                            "(${iocHit.name}) has recorded permission usage — " +
                            iocHit.description
                    ))
                }

                // Check for risky package
                if (packageName in riskyPackages) {
                    opLineRegex.findAll(pkgBlock).forEach { opMatch ->
                        val opName = opMatch.groupValues[1]
                        findings.add(BugReportFinding(
                            severity = "HIGH",
                            category = "AppOpsAbuse",
                            description = "Shell process (com.android.shell) used " +
                                "permission '$opName' — may indicate ADB exploitation"
                        ))
                    }
                    return@pkgLoop
                }

                // Skip system UIDs for op-level checks (they legitimately use many ops)
                if (isSystemUid) return@pkgLoop

                // Check each op
                opLineRegex.findAll(pkgBlock).forEach { opMatch ->
                    val opName = opMatch.groupValues[1]

                    // Risky op check
                    if (opName in riskyOps) {
                        findings.add(BugReportFinding(
                            severity = "HIGH",
                            category = "AppOpsAbuse",
                            description = "App '$packageName' has $opName " +
                                "permission — can install APKs from unknown sources"
                        ))
                    }

                    // Timeline entry for dangerous ops
                    if (opName in dangerousOps) {
                        val opStart = opMatch.range.last
                        val accessMatch = accessLineRegex.find(pkgBlock, opStart)
                        timeline.add(TimelineEvent(
                            timestamp = -1, // raw text timestamp, not parsed to epoch
                            source = "appops",
                            category = "permission_use",
                            description = "$packageName used $opName" +
                                (accessMatch?.let { " at ${it.groupValues[1]}" } ?: ""),
                            severity = if (opName in riskyOps) "HIGH" else "INFO"
                        ))
                    }
                }
            }
        }

        return ModuleResult(findings = findings, timeline = timeline)
    }

    private fun splitByUid(text: String): List<Pair<Int, String>> {
        val matches = uidLineRegex.findAll(text).toList()
        if (matches.isEmpty()) return emptyList()

        return matches.mapIndexed { index, match ->
            val uid = match.groupValues[1].toIntOrNull() ?: 0
            val start = match.range.first
            val end = if (index + 1 < matches.size) matches[index + 1].range.first else text.length
            uid to text.substring(start, end)
        }
    }

    private fun findNextPackageOrEnd(block: String, fromIndex: Int): Int {
        val next = packageLineRegex.find(block, fromIndex + 1)
        return next?.range?.first ?: block.length
    }
}
```

- [ ] **Step 4: Register in Hilt bindings**

In `app/src/main/java/com/androdr/di/BugreportModuleBindings.kt`, add:

```kotlin
import com.androdr.scanner.bugreport.AppOpsModule

    @Binds @IntoSet abstract fun appOps(m: AppOpsModule): BugreportModule
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.scanner.bugreport.AppOpsModuleTest" 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL, all tests pass

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/bugreport/AppOpsModule.kt \
       app/src/test/java/com/androdr/scanner/bugreport/AppOpsModuleTest.kt \
       app/src/main/java/com/androdr/di/BugreportModuleBindings.kt
git commit -m "feat: add AppOpsModule for permission usage analysis (#33)"
```

---

## Task 10: Runtime Scanners — Accessibility, Receiver, AppOps

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/AccessibilityAuditScanner.kt`
- Create: `app/src/main/java/com/androdr/scanner/ReceiverAuditScanner.kt`
- Create: `app/src/main/java/com/androdr/scanner/AppOpsScanner.kt`
- Create: `app/src/test/java/com/androdr/scanner/AccessibilityAuditScannerTest.kt`
- Create: `app/src/test/java/com/androdr/scanner/ReceiverAuditScannerTest.kt`
- Create: `app/src/test/java/com/androdr/scanner/AppOpsScannerTest.kt`

- [ ] **Step 1: Write AccessibilityAuditScanner test**

Create `app/src/test/java/com/androdr/scanner/AccessibilityAuditScannerTest.kt`:

```kotlin
package com.androdr.scanner

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.content.pm.ServiceInfo
import android.view.accessibility.AccessibilityManager
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AccessibilityAuditScannerTest {

    private val mockContext: Context = mockk(relaxed = true)
    private val mockAccessibilityManager: AccessibilityManager = mockk()
    private val mockPackageManager: PackageManager = mockk(relaxed = true)

    private fun createScanner(): AccessibilityAuditScanner {
        every {
            mockContext.getSystemService(Context.ACCESSIBILITY_SERVICE)
        } returns mockAccessibilityManager
        every { mockContext.packageManager } returns mockPackageManager
        return AccessibilityAuditScanner(mockContext)
    }

    private fun mockServiceInfo(
        packageName: String,
        serviceName: String,
        isSystem: Boolean = false
    ): AccessibilityServiceInfo {
        val info = mockk<AccessibilityServiceInfo>()
        val resolveInfo = mockk<ResolveInfo>()
        val serviceInfo = ServiceInfo()
        serviceInfo.packageName = packageName
        serviceInfo.name = serviceName
        serviceInfo.applicationInfo = ApplicationInfo().apply {
            this.packageName = packageName
            flags = if (isSystem) ApplicationInfo.FLAG_SYSTEM else 0
        }
        resolveInfo.serviceInfo = serviceInfo
        every { info.resolveInfo } returns resolveInfo
        return info
    }

    @Test
    fun `returns telemetry for enabled accessibility services`() = runBlocking {
        val services = listOf(
            mockServiceInfo("com.evil.spy", ".SpyService"),
            mockServiceInfo("com.google.android.marvin.talkback", ".TalkBackService", isSystem = true)
        )
        every {
            mockAccessibilityManager.getEnabledAccessibilityServiceList(
                AccessibilityServiceInfo.FEEDBACK_ALL_MASK
            )
        } returns services

        val scanner = createScanner()
        val telemetry = scanner.collectTelemetry()

        assertEquals(2, telemetry.size)
        assertTrue(telemetry.any { it.packageName == "com.evil.spy" && !it.isSystemApp && it.isEnabled })
        assertTrue(telemetry.any { it.packageName == "com.google.android.marvin.talkback" && it.isSystemApp })
    }

    @Test
    fun `returns empty list when no accessibility services enabled`() = runBlocking {
        every {
            mockAccessibilityManager.getEnabledAccessibilityServiceList(
                AccessibilityServiceInfo.FEEDBACK_ALL_MASK
            )
        } returns emptyList()

        val scanner = createScanner()
        val telemetry = scanner.collectTelemetry()
        assertTrue(telemetry.isEmpty())
    }

    @Test
    fun `returns empty list when AccessibilityManager unavailable`() = runBlocking {
        every { mockContext.getSystemService(Context.ACCESSIBILITY_SERVICE) } returns null
        val scanner = AccessibilityAuditScanner(mockContext)
        val telemetry = scanner.collectTelemetry()
        assertTrue(telemetry.isEmpty())
    }
}
```

- [ ] **Step 2: Implement AccessibilityAuditScanner**

Create `app/src/main/java/com/androdr/scanner/AccessibilityAuditScanner.kt`:

```kotlin
package com.androdr.scanner

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.pm.ApplicationInfo
import android.util.Log
import android.view.accessibility.AccessibilityManager
import com.androdr.data.model.AccessibilityTelemetry
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AccessibilityAuditScanner @Inject constructor(
    @ApplicationContext private val context: Context
) {
    suspend fun collectTelemetry(): List<AccessibilityTelemetry> = withContext(Dispatchers.IO) {
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
            ?: return@withContext emptyList()

        val services = am.getEnabledAccessibilityServiceList(
            AccessibilityServiceInfo.FEEDBACK_ALL_MASK
        ) ?: return@withContext emptyList()

        services.mapNotNull { info ->
            val serviceInfo = info.resolveInfo?.serviceInfo ?: return@mapNotNull null
            val isSystem = serviceInfo.applicationInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM) != 0
            AccessibilityTelemetry(
                packageName = serviceInfo.packageName,
                serviceName = serviceInfo.name,
                isSystemApp = isSystem,
                isEnabled = true
            )
        }.also {
            Log.d(TAG, "Collected ${it.size} enabled accessibility services")
        }
    }

    companion object {
        private const val TAG = "AccessibilityAuditScanner"
    }
}
```

- [ ] **Step 3: Write ReceiverAuditScanner test**

Create `app/src/test/java/com/androdr/scanner/ReceiverAuditScannerTest.kt`:

```kotlin
package com.androdr.scanner

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.content.pm.ActivityInfo
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ReceiverAuditScannerTest {

    private val mockContext: Context = mockk(relaxed = true)
    private val mockPackageManager: PackageManager = mockk(relaxed = true)

    private fun createScanner(): ReceiverAuditScanner {
        every { mockContext.packageManager } returns mockPackageManager
        return ReceiverAuditScanner(mockContext)
    }

    private fun mockResolveInfo(packageName: String, name: String, isSystem: Boolean): ResolveInfo {
        val ri = ResolveInfo()
        ri.activityInfo = ActivityInfo()
        ri.activityInfo.packageName = packageName
        ri.activityInfo.name = name
        ri.activityInfo.applicationInfo = ApplicationInfo().apply {
            this.packageName = packageName
            flags = if (isSystem) ApplicationInfo.FLAG_SYSTEM else 0
        }
        return ri
    }

    @Test
    fun `returns telemetry for broadcast receivers on sensitive intents`() = runBlocking {
        val intentSlot = slot<Intent>()
        every {
            mockPackageManager.queryBroadcastReceivers(capture(intentSlot), any<Int>())
        } answers {
            val action = intentSlot.captured.action
            if (action == "android.provider.Telephony.SMS_RECEIVED") {
                listOf(mockResolveInfo("com.evil.sms", ".SmsReceiver", false))
            } else {
                emptyList()
            }
        }

        val scanner = createScanner()
        val telemetry = scanner.collectTelemetry()

        assertTrue(telemetry.any {
            it.packageName == "com.evil.sms" &&
                it.intentAction == "android.provider.Telephony.SMS_RECEIVED" &&
                !it.isSystemApp
        })
    }

    @Test
    fun `returns empty list when no receivers found`() = runBlocking {
        every {
            mockPackageManager.queryBroadcastReceivers(any(), any<Int>())
        } returns emptyList()

        val scanner = createScanner()
        val telemetry = scanner.collectTelemetry()
        assertTrue(telemetry.isEmpty())
    }
}
```

- [ ] **Step 4: Implement ReceiverAuditScanner**

Create `app/src/main/java/com/androdr/scanner/ReceiverAuditScanner.kt`:

```kotlin
package com.androdr.scanner

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.util.Log
import com.androdr.data.model.ReceiverTelemetry
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ReceiverAuditScanner @Inject constructor(
    @ApplicationContext private val context: Context
) {

    private val sensitiveIntents = listOf(
        "android.provider.Telephony.SMS_RECEIVED",
        "android.provider.Telephony.NEW_OUTGOING_SMS",
        "android.intent.action.DATA_SMS_RECEIVED",
        "android.intent.action.PHONE_STATE",
        "android.intent.action.NEW_OUTGOING_CALL"
    )

    suspend fun collectTelemetry(): List<ReceiverTelemetry> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val results = mutableListOf<ReceiverTelemetry>()

        for (action in sensitiveIntents) {
            val intent = Intent(action)
            @Suppress("QueryPermissionsNeeded") // QUERY_ALL_PACKAGES already declared
            val receivers = pm.queryBroadcastReceivers(intent, PackageManager.GET_META_DATA)
            for (ri in receivers) {
                val ai = ri.activityInfo ?: continue
                val isSystem = ai.applicationInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM) != 0
                results.add(ReceiverTelemetry(
                    packageName = ai.packageName,
                    intentAction = action,
                    componentName = ai.name,
                    isSystemApp = isSystem
                ))
            }
        }

        Log.d(TAG, "Collected ${results.size} broadcast receiver records")
        results
    }

    companion object {
        private const val TAG = "ReceiverAuditScanner"
    }
}
```

- [ ] **Step 5: Write AppOpsScanner test**

Create `app/src/test/java/com/androdr/scanner/AppOpsScannerTest.kt`:

```kotlin
package com.androdr.scanner

import android.app.AppOpsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Test

class AppOpsScannerTest {

    private val mockContext: Context = mockk(relaxed = true)

    @Test
    fun `returns empty list when AppOpsManager unavailable`() = runBlocking {
        every { mockContext.getSystemService(Context.APP_OPS_SERVICE) } returns null
        val scanner = AppOpsScanner(mockContext)
        val telemetry = scanner.collectTelemetry()
        assertTrue(telemetry.isEmpty())
    }

    @Test
    fun `returns empty list when no packages have ops`() = runBlocking {
        val mockOps: AppOpsManager = mockk(relaxed = true)
        every { mockContext.getSystemService(Context.APP_OPS_SERVICE) } returns mockOps
        every { mockContext.packageManager } returns mockk(relaxed = true)
        // getPackagesForOps returns null when no packages match
        every { mockOps.getPackagesForOps(any()) } returns null

        val scanner = AppOpsScanner(mockContext)
        val telemetry = scanner.collectTelemetry()
        assertTrue(telemetry.isEmpty())
    }
}
```

- [ ] **Step 6: Implement AppOpsScanner**

Create `app/src/main/java/com/androdr/scanner/AppOpsScanner.kt`:

```kotlin
package com.androdr.scanner

import android.app.AppOpsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.util.Log
import com.androdr.data.model.AppOpsTelemetry
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AppOpsScanner @Inject constructor(
    @ApplicationContext private val context: Context
) {

    /** Dangerous AppOps we query for. String names map to AppOpsManager.OPSTR_* constants. */
    private val dangerousOps = arrayOf(
        AppOpsManager.OPSTR_CAMERA,
        AppOpsManager.OPSTR_RECORD_AUDIO,
        AppOpsManager.OPSTR_READ_CONTACTS,
        AppOpsManager.OPSTR_READ_CALL_LOG,
        AppOpsManager.OPSTR_FINE_LOCATION,
        AppOpsManager.OPSTR_READ_SMS,
        AppOpsManager.OPSTR_READ_EXTERNAL_STORAGE
    )

    @Suppress("TooGenericExceptionCaught")
    suspend fun collectTelemetry(): List<AppOpsTelemetry> = withContext(Dispatchers.IO) {
        val opsManager = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
            ?: return@withContext emptyList()
        val pm = context.packageManager

        val results = mutableListOf<AppOpsTelemetry>()

        try {
            val packages = opsManager.getPackagesForOps(dangerousOps)
                ?: return@withContext emptyList()

            for (pkg in packages) {
                val packageName = pkg.packageName ?: continue
                val isSystem = try {
                    val appInfo = pm.getApplicationInfo(packageName, 0)
                    appInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0
                } catch (_: Exception) {
                    false
                }

                val ops = pkg.ops ?: continue
                for (op in ops) {
                    val opName = op.opStr ?: continue

                    // On API 29+, we can get detailed entries with timestamps
                    var lastAccess = 0L
                    var lastReject = 0L
                    var accessCount = 0

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        try {
                            val entries = op.attributedOpEntries
                            for ((_, entry) in entries) {
                                val access = entry.getLastAccessTime(
                                    AppOpsManager.OP_FLAGS_ALL
                                )
                                val reject = entry.getLastRejectTime(
                                    AppOpsManager.OP_FLAGS_ALL
                                )
                                if (access > lastAccess) lastAccess = access
                                if (reject > lastReject) lastReject = reject
                                accessCount++ // approximate
                            }
                        } catch (_: Exception) {
                            // Fall back to basic info
                        }
                    }

                    results.add(AppOpsTelemetry(
                        packageName = packageName,
                        operation = opName,
                        lastAccessTime = lastAccess,
                        lastRejectTime = lastReject,
                        accessCount = accessCount,
                        isSystemApp = isSystem
                    ))
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "AppOps query failed: ${e.message}")
        }

        Log.d(TAG, "Collected ${results.size} app ops records")
        results
    }

    companion object {
        private const val TAG = "AppOpsScanner"
    }
}
```

- [ ] **Step 7: Run all tests**

Run: `./gradlew testDebugUnitTest 2>&1 | tail -10`
Expected: BUILD SUCCESSFUL, all tests pass

- [ ] **Step 8: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/AccessibilityAuditScanner.kt \
       app/src/main/java/com/androdr/scanner/ReceiverAuditScanner.kt \
       app/src/main/java/com/androdr/scanner/AppOpsScanner.kt \
       app/src/test/java/com/androdr/scanner/AccessibilityAuditScannerTest.kt \
       app/src/test/java/com/androdr/scanner/ReceiverAuditScannerTest.kt \
       app/src/test/java/com/androdr/scanner/AppOpsScannerTest.kt
git commit -m "feat: add runtime scanners for accessibility, receivers, and AppOps (#33 #34 #35)"
```

---

## Task 11: SIGMA Rules for New Telemetry Types

**Files:**
- Create: `app/src/main/res/raw/sigma_androdr_060_active_accessibility.yml`
- Create: `app/src/main/res/raw/sigma_androdr_061_sms_receiver.yml`
- Create: `app/src/main/res/raw/sigma_androdr_062_call_receiver.yml`
- Create: `app/src/main/res/raw/sigma_androdr_063_appops_microphone.yml`
- Create: `app/src/main/res/raw/sigma_androdr_064_appops_camera.yml`
- Create: `app/src/main/res/raw/sigma_androdr_065_appops_install_packages.yml`

- [ ] **Step 1: Create accessibility SIGMA rule**

Create `app/src/main/res/raw/sigma_androdr_060_active_accessibility.yml`:

```yaml
title: Non-system app with active accessibility service
id: androdr-060
status: production
description: A non-system app has an accessibility service currently enabled. Accessibility services can read screen content, capture keystrokes, and perform UI actions.
author: AndroDR
date: 2026/03/28
tags:
    - attack.t1626
logsource:
    product: androdr
    service: accessibility_audit
detection:
    selection:
        is_system_app: false
        is_enabled: true
    condition: selection
level: high
display:
    category: app_risk
    icon: accessibility
    triggered_title: "Active Accessibility Service"
    evidence_type: none
remediation:
    - "This app has an active accessibility service that can read your screen. Go to Settings > Accessibility and disable it."
    - "If you did not intentionally enable this service, it may be stalkerware."
```

- [ ] **Step 2: Create SMS receiver SIGMA rule**

Create `app/src/main/res/raw/sigma_androdr_061_sms_receiver.yml`:

```yaml
title: App intercepting incoming SMS
id: androdr-061
status: production
description: A non-system app is registered to receive incoming SMS messages. Legitimate apps rarely need this — it is a strong stalkerware/spyware indicator.
author: AndroDR
date: 2026/03/28
tags:
    - attack.t1636
logsource:
    product: androdr
    service: receiver_audit
detection:
    selection:
        intent_action: "android.provider.Telephony.SMS_RECEIVED"
        is_system_app: false
    condition: selection
level: critical
display:
    category: app_risk
    icon: sms
    triggered_title: "SMS Interception"
    evidence_type: none
remediation:
    - "This app can read your incoming text messages. If you did not grant this explicitly, uninstall it immediately."
```

- [ ] **Step 3: Create call receiver SIGMA rule**

Create `app/src/main/res/raw/sigma_androdr_062_call_receiver.yml`:

```yaml
title: App monitoring phone call state
id: androdr-062
status: production
description: A non-system app is registered for PHONE_STATE or NEW_OUTGOING_CALL broadcasts, enabling it to monitor incoming and outgoing calls.
author: AndroDR
date: 2026/03/28
tags:
    - attack.t1636
logsource:
    product: androdr
    service: receiver_audit
detection:
    selection_phone_state:
        intent_action: "android.intent.action.PHONE_STATE"
        is_system_app: false
    selection_outgoing_call:
        intent_action: "android.intent.action.NEW_OUTGOING_CALL"
        is_system_app: false
    condition: selection_phone_state or selection_outgoing_call
level: critical
display:
    category: app_risk
    icon: phone
    triggered_title: "Call Monitoring"
    evidence_type: none
remediation:
    - "This app can monitor your phone calls. If you did not grant this permission, uninstall it immediately."
```

- [ ] **Step 4: Create AppOps microphone SIGMA rule**

Create `app/src/main/res/raw/sigma_androdr_063_appops_microphone.yml`:

```yaml
title: Non-system app accessed microphone
id: androdr-063
status: production
description: A non-system app has used the microphone (RECORD_AUDIO). This is expected for phone/messaging apps but suspicious for utilities or background apps.
author: AndroDR
date: 2026/03/28
tags:
    - attack.t1429
logsource:
    product: androdr
    service: appops_audit
detection:
    selection:
        operation: "android:record_audio"
        is_system_app: false
    condition: selection
level: high
display:
    category: app_risk
    icon: mic
    triggered_title: "Microphone Access"
    evidence_type: none
remediation:
    - "This app has accessed your microphone. Review whether this is expected behavior."
    - "Check Settings > Privacy > Permission manager > Microphone to see and revoke access."
```

- [ ] **Step 5: Create AppOps camera SIGMA rule**

Create `app/src/main/res/raw/sigma_androdr_064_appops_camera.yml`:

```yaml
title: Non-system app accessed camera
id: androdr-064
status: production
description: A non-system app has used the camera. Expected for camera/messaging apps but suspicious for background utilities.
author: AndroDR
date: 2026/03/28
tags:
    - attack.t1429
logsource:
    product: androdr
    service: appops_audit
detection:
    selection:
        operation: "android:camera"
        is_system_app: false
    condition: selection
level: high
display:
    category: app_risk
    icon: camera
    triggered_title: "Camera Access"
    evidence_type: none
remediation:
    - "This app has accessed your camera. Review whether this is expected behavior."
    - "Check Settings > Privacy > Permission manager > Camera to see and revoke access."
```

- [ ] **Step 6: Create AppOps install packages SIGMA rule**

Create `app/src/main/res/raw/sigma_androdr_065_appops_install_packages.yml`:

```yaml
title: App can install packages from unknown sources
id: androdr-065
status: production
description: A non-system app has REQUEST_INSTALL_PACKAGES permission, allowing it to install APKs. This is a sideloading vector that malware uses to install additional payloads.
author: AndroDR
date: 2026/03/28
tags:
    - attack.t1476
logsource:
    product: androdr
    service: appops_audit
detection:
    selection:
        operation: "android:request_install_packages"
        is_system_app: false
    condition: selection
level: high
display:
    category: app_risk
    icon: download
    triggered_title: "Can Install APKs"
    evidence_type: none
remediation:
    - "This app can install other apps. Go to Settings > Apps > Special access > Install unknown apps and revoke this permission."
```

- [ ] **Step 7: Build to verify YAML is valid**

Run: `./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 8: Commit**

```bash
git add app/src/main/res/raw/sigma_androdr_06*.yml
git commit -m "feat: add SIGMA rules for accessibility, receiver, and AppOps detection (#33 #34 #35)"
```

---

## Task 12: SigmaRuleEngine + ScanOrchestrator Integration

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt`
- Modify: `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt`

- [ ] **Step 1: Add evaluation methods to SigmaRuleEngine**

In `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt`, add these three methods before the `ruleCount()` method (after `evaluateFiles` at line 92):

```kotlin
    fun evaluateAccessibility(telemetry: List<com.androdr.data.model.AccessibilityTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(rules, records, "accessibility_audit", iocLookups, evidenceProviders)
    }

    fun evaluateReceivers(telemetry: List<com.androdr.data.model.ReceiverTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(rules, records, "receiver_audit", iocLookups, evidenceProviders)
    }

    fun evaluateAppOps(telemetry: List<com.androdr.data.model.AppOpsTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(rules, records, "appops_audit", iocLookups, evidenceProviders)
    }
```

Also add the imports at the top of the file:

```kotlin
import com.androdr.data.model.AccessibilityTelemetry
import com.androdr.data.model.ReceiverTelemetry
import com.androdr.data.model.AppOpsTelemetry
```

- [ ] **Step 2: Wire runtime scanners into ScanOrchestrator**

In `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt`, add constructor parameters. After `private val fileArtifactScanner: FileArtifactScanner,` add:

```kotlin
    private val accessibilityAuditScanner: AccessibilityAuditScanner,
    private val receiverAuditScanner: ReceiverAuditScanner,
    private val appOpsScanner: AppOpsScanner,
```

In the `runFullScan()` method, add three new async calls after `fileTelemetryDeferred` (after line 89):

```kotlin
        val accessibilityTelemetryDeferred = async {
            runCatching { accessibilityAuditScanner.collectTelemetry() }.getOrDefault(emptyList())
        }
        val receiverTelemetryDeferred = async {
            runCatching { receiverAuditScanner.collectTelemetry() }.getOrDefault(emptyList())
        }
        val appOpsTelemetryDeferred = async {
            runCatching { appOpsScanner.collectTelemetry() }.getOrDefault(emptyList())
        }
```

After `val fileTelemetry = fileTelemetryDeferred.await()` (after line 95), add:

```kotlin
        val accessibilityTelemetry = accessibilityTelemetryDeferred.await()
        val receiverTelemetry = receiverTelemetryDeferred.await()
        val appOpsTelemetry = appOpsTelemetryDeferred.await()
```

After `allFindings.addAll(sigmaRuleEngine.evaluateFiles(fileTelemetry))` (after line 102), add:

```kotlin
        allFindings.addAll(sigmaRuleEngine.evaluateAccessibility(accessibilityTelemetry))
        allFindings.addAll(sigmaRuleEngine.evaluateReceivers(receiverTelemetry))
        allFindings.addAll(sigmaRuleEngine.evaluateAppOps(appOpsTelemetry))
```

- [ ] **Step 3: Build and run full test suite**

Run: `./gradlew testDebugUnitTest 2>&1 | tail -10`
Expected: BUILD SUCCESSFUL, all tests pass

Run: `./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt \
       app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt
git commit -m "feat: wire accessibility, receiver, and AppOps scanners into scan pipeline (#33 #34 #35)"
```

---

## Task 13: Final Integration Verification

- [ ] **Step 1: Run full test suite**

Run: `./gradlew testDebugUnitTest 2>&1 | tail -20`
Expected: BUILD SUCCESSFUL, all tests pass

- [ ] **Step 2: Run lint**

Run: `./gradlew lintDebug 2>&1 | tail -20`
Expected: No new errors introduced

- [ ] **Step 3: Build release APK**

Run: `./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 4: Final commit if any fixes were needed**

```bash
git add -A
git commit -m "fix: resolve lint/test issues from MVT-parity integration"
```

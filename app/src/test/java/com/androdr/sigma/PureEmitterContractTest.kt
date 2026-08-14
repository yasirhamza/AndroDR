package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Pure-emitter contract build gates (#136 checks 1+2, spec B1/B2).
 * Source-scanning, matching the repo's cross-check-test convention.
 */
class PureEmitterContractTest {

    private fun mainSourceRoot(): File = listOf(
        File("app/src/main/java"),
        File("../app/src/main/java"),
        File("/home/yasir/AndroDR/app/src/main/java"),
    ).firstOrNull { it.isDirectory } ?: error("main source root not found")

    // B1: Finding may only be constructed — or severity-mutated via copy —
    // in the evaluator. The data class itself is declared there (pinned:
    // moving the declaration means revisiting this gate, not allowlisting).
    private val findingConstructionAllowlist = setOf(
        "com/androdr/sigma/SigmaRuleEvaluator.kt",
    )
    private val constructionPattern = Regex("""(?<![\w.])Finding\(""")
    private val severityCopyPattern = Regex("""\.copy\([^)]*\blevel\s*=""")

    @Test
    fun `Finding is constructed and severity-mutated only inside the evaluator`() {
        val offenders = mainSourceRoot().walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .filter { f -> findingConstructionAllowlist.none { f.path.replace('\\', '/').endsWith(it) } }
            .filter { f ->
                f.readLines().any { line ->
                    val code = line.substringBefore("//")
                    constructionPattern.containsMatchIn(code) ||
                        severityCopyPattern.containsMatchIn(code)
                }
            }
            .map { it.path }.toList()
        assertTrue(
            "Finding construction / level-copy outside the evaluator (findings are " +
                "derived only by the rule engines — #84/#136): $offenders",
            offenders.isEmpty()
        )
    }

    // B2: the telemetry emitter surface = every type with a toFieldMap().
    // Enumerated set asserted for equality so a NEW emitter fails loudly and
    // gets classified here, and severity-like fields are checked both as
    // property declarations and as emitted field-map keys.
    private val expectedEmitterFiles = setOf(
        // Verified real set via the toFieldMapDeclarationPattern below
        // (2026-08-14). Re-verify at implementation time; do not trust blindly.
        "AccessibilityTelemetry.kt", "AppOpsTelemetry.kt", "AppTelemetry.kt",
        "DeviceTelemetry.kt", "DnsEvent.kt", "FileArtifactTelemetry.kt",
        "NetworkTelemetry.kt", "ProcessTelemetry.kt", "ReceiverTelemetry.kt",
        // extension emitters
        "TelemetryFieldMaps.kt",
    )

    // Matches both member declarations (`fun toFieldMap(`) and extension
    // declarations (`fun TypeName.toFieldMap(`, used by TelemetryFieldMaps.kt).
    // A plain `.contains("fun toFieldMap")` literal check misses the latter —
    // verified by direct grep at implementation time, so the emitter surface
    // silently shrank to 9/10 files. Do not revert to the literal-string form.
    private val toFieldMapDeclarationPattern = Regex("""fun\s+(\w+\.)?toFieldMap\(""")
    private val forbiddenProperty = Regex("""\b(val|var)\s+(severity|level|priority)\b""")
    private val forbiddenKey = Regex(""""(severity|level|priority)"\s+to\b""")

    @Test
    fun `telemetry emitters declare no severity - as property or field-map key`() {
        val root = mainSourceRoot()
        val actual = root.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .filter { toFieldMapDeclarationPattern.containsMatchIn(it.readText()) }
            .map { it.name }.toSet()
        assertEquals(
            "Emitter set changed — classify the new/removed toFieldMap type here " +
                "AND in logsource-taxonomy.yml (every emitted field needs a kind)",
            expectedEmitterFiles, actual
        )
        val offenders = root.walkTopDown()
            .filter { it.isFile && it.name in expectedEmitterFiles }
            .filter { f ->
                f.readLines().any { line ->
                    val code = line.substringBefore("//")
                    forbiddenProperty.containsMatchIn(code) || forbiddenKey.containsMatchIn(code)
                }
            }
            .map { it.name }.toList()
        assertTrue(
            "Telemetry emitters must stay severity-free (findings own severity — #84/#136): $offenders",
            offenders.isEmpty()
        )
    }
}

package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-emitter contract build gates (#136 checks 1+2, spec B1/B2).
 * Source-scanning, matching the repo's cross-check-test convention.
 *
 * Both gates scan COMMENT-STRIPPED WHOLE-FILE text, never line by line. A
 * line-oriented gate is trivially evaded by the formatting style that is
 * already live in this codebase — e.g. `SigmaCorrelationEngine.evaluate`'s
 *
 *     val effectiveRule = rule.copy(
 *         severity = effectiveSeverity,
 *     )
 *
 * — where the `.copy(` and the field assignment sit on different lines, so a
 * per-line regex sees neither half. Stripping comments first is what makes
 * whole-file matching viable: KDoc and `//` prose mention `Finding(` freely and
 * would otherwise light the gate up.
 */
class PureEmitterContractTest {

    /** Shared source-scan helper - see [TestRuleRepo.stripKotlinComments]. */
    private fun stripComments(source: String): String = TestRuleRepo.stripKotlinComments(source)

    // B1: Finding may only be constructed — or severity-mutated via copy —
    // in the evaluator. The data class itself is declared there (pinned:
    // moving the declaration means revisiting this gate, not allowlisting).
    private val findingConstructionAllowlist = setOf(
        "com/androdr/sigma/SigmaRuleEvaluator.kt",
    )

    /**
     * `Finding(` / `Finding (`, including the fully-qualified
     * `com.androdr.sigma.Finding(` spelling. The lookbehind excludes only word
     * characters (NOT `.`) so `SomeOtherFinding(` and `toFinding(` are ignored
     * while a package-qualified constructor call is caught — qualifying the
     * name was otherwise a one-character bypass of this gate.
     */
    private val constructionPattern = Regex("""(?<!\w)Finding\s*\(""")

    /**
     * `.copy(… level = …)` in any formatting. `[^)]*` crosses newlines by
     * construction (a negated class matches `\n`) yet still cannot escape the
     * argument list it started in, since the first `)` ends the match attempt.
     */
    private val severityCopyPattern = Regex("""\.copy\([^)]*\blevel\s*=""")

    @Test
    fun `Finding is constructed and severity-mutated only inside the evaluator`() {
        val offenders = TestRuleRepo.mainSourceRoot().walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .filter { f -> findingConstructionAllowlist.none { f.path.replace('\\', '/').endsWith(it) } }
            .filter { f ->
                val code = stripComments(f.readText())
                constructionPattern.containsMatchIn(code) ||
                    severityCopyPattern.containsMatchIn(code)
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
        "CellularSnapshot.kt", "DeviceTelemetry.kt", "DnsEvent.kt",
        "FileArtifactTelemetry.kt",
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
        val root = TestRuleRepo.mainSourceRoot()
        val actual = root.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .filter { toFieldMapDeclarationPattern.containsMatchIn(stripComments(it.readText())) }
            .map { it.name }.toSet()
        assertEquals(
            "Emitter set changed — classify the new/removed toFieldMap type here " +
                "AND in logsource-taxonomy.yml (every emitted field needs a kind)",
            expectedEmitterFiles, actual
        )
        val offenders = root.walkTopDown()
            .filter { it.isFile && it.name in expectedEmitterFiles }
            .filter { f ->
                val code = stripComments(f.readText())
                forbiddenProperty.containsMatchIn(code) || forbiddenKey.containsMatchIn(code)
            }
            .map { it.name }.toList()
        assertTrue(
            "Telemetry emitters must stay severity-free (findings own severity — #84/#136): $offenders",
            offenders.isEmpty()
        )
    }

    /**
     * Self-test for [stripComments]: a comment stripper that over-strips turns
     * both gates above vacuous, and one that under-strips makes them noisy. The
     * cases below are exactly the ones the gates depend on.
     */
    @Test
    fun `comment stripper removes comments, keeps code and string literals`() {
        val sample = """
            // Finding( in a LINE_COMMENT
            /* Finding( in a BLOCK_COMMENT
               spanning lines, with a nested /* Finding( */ NESTED_TAIL */
            /** KDOC_TEXT mentioning Finding( and .copy(level = "x") */
            val url = "https://example.com/api" // TRAILING_COMMENT
            val real = Finding(ruleId = "r")
            val mutated = other.copy(
                level = "low",
            )
        """.trimIndent()
        val stripped = stripComments(sample)

        assertFalse("line comments must be stripped", "LINE_COMMENT" in stripped)
        assertFalse("block comments must be stripped", "BLOCK_COMMENT" in stripped)
        assertFalse("KDoc must be stripped", "KDOC_TEXT" in stripped)
        assertFalse("trailing line comments must be stripped", "TRAILING_COMMENT" in stripped)
        assertFalse(
            "nested block comments must not terminate the outer comment early",
            "NESTED_TAIL" in stripped
        )
        assertTrue("code must survive", "val real = Finding(ruleId = " in stripped)
        assertTrue(
            "string literals must survive verbatim — a `//` inside one is not a comment, " +
                "and B2's field-map-key pattern matches inside string literals",
            """"https://example.com/api"""" in stripped
        )
        // The two hardenings, asserted on the stripper's output.
        assertEquals(
            "exactly one Finding( construction survives — the six in comments do not",
            1, constructionPattern.findAll(stripped).count()
        )
        assertTrue(
            "a .copy( ... ) with `level =` on a later line must be matched",
            severityCopyPattern.containsMatchIn(stripped)
        )
    }
}

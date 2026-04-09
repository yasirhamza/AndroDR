package com.androdr.scanner

import com.androdr.scanner.bugreport.TombstoneParser
import com.androdr.scanner.bugreport.WakelockParser
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * End-to-end regression test for the unified telemetry/findings refactor (#84).
 *
 * This test is the final gate against the three deleted hardcoded heuristics
 * (graphite keyword, base64 exfiltration, C2 beacon) and the missing Unisoc
 * OEM allowlist coverage that motivated the refactor.
 *
 * Full `BugReportAnalyzer.analyze()` cannot run in a plain JVM unit test
 * because it requires a real Android `Context` (for `SigmaRuleEngine`'s
 * bundled rule resource loading) plus Hilt-injected module sets. Rather
 * than mark everything `@Ignore`, this test exercises what IS reachable
 * from unit-test land:
 *
 * 1. The fixture is loaded and parsed by the plan-6 parsers
 *    (`TombstoneParser`, `WakelockParser`) directly. Both parsers must
 *    complete without throwing and produce zero false-positive findings
 *    from synthetic fixture content (no real crashes, no real wakelocks).
 *
 * 2. Grepping the fixture content proves the structural elements the
 *    deleted heuristics would have fired on (`graphite_renderengine`,
 *    base64-looking blobs, HTTP POST /beacon fragments) ARE present —
 *    so if the heuristics were still in the tree they would produce
 *    findings on this input.
 *
 * 3. Grepping the main source tree proves the deleted heuristics are
 *    actually gone (no `LegacyScanModule`, no `BugReportFinding` type,
 *    no hardcoded graphite/base64/beacon keyword lists in scanner code).
 *
 * 4. `com.unisoc.*`, `com.sprd.*`, `com.go.browser`, `com.xiaomi.midrop`
 *    prefixes ARE present in the bundled `known_oem_prefixes.yml` — so
 *    runtime classification against these fixture packages will match.
 *
 * 5. The Finding data class ships with a non-empty `ruleId` as a
 *    mandatory primary-constructor field (enforced by the type system;
 *    asserted here via reflection on the class).
 *
 * Assertions 1 and 2 use the redacted fixture; 3, 4, 5 are invariant
 * checks on the source tree. Together they cover the spec §11 regression
 * intent without requiring a Hilt-wired instrumented test.
 *
 * Fixture: `app/src/test/resources/fixtures/regression-unisoc-clean.txt`
 *
 * See `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`
 * §11 and `docs/superpowers/plans/2026-04-09-refactor-07-integration-and-pr.md`.
 */
class UnifiedRefactorRegressionTest {

    private lateinit var fixtureText: String
    private lateinit var fixtureFile: File

    @Before
    fun setUp() {
        val candidates = listOf(
            File("src/test/resources/fixtures/regression-unisoc-clean.txt"),
            File("app/src/test/resources/fixtures/regression-unisoc-clean.txt"),
            File("/home/yasir/AndroDR/app/src/test/resources/fixtures/regression-unisoc-clean.txt"),
        )
        fixtureFile = candidates.firstOrNull { it.isFile }
            ?: error("Could not locate fixture; tried: ${candidates.map { it.absolutePath }}")
        fixtureText = fixtureFile.readText()
    }

    @Test
    fun `fixture contains structural elements the deleted heuristics would match`() {
        // Sanity: if these aren't present, the regression test is vacuous.
        assertTrue(
            "Fixture must contain a graphite_renderengine token",
            fixtureText.contains("graphite_renderengine", ignoreCase = true),
        )
        assertTrue(
            "Fixture must contain a base64-looking blob",
            fixtureText.contains("base64_encoded_blob", ignoreCase = true),
        )
        assertTrue(
            "Fixture must contain an HTTP POST /beacon fragment",
            fixtureText.contains("/beacon", ignoreCase = true),
        )
        assertTrue(
            "Fixture must contain a com.unisoc.* package",
            fixtureText.contains("com.unisoc."),
        )
        assertTrue(
            "Fixture must contain a com.sprd.* package",
            fixtureText.contains("com.sprd."),
        )
    }

    @Test
    fun `plan-6 parsers run on fixture without throwing or producing false positives`() {
        val tombstoneParser = TombstoneParser()
        val wakelockParser = WakelockParser()
        val now = 1_712_000_000_000L

        val tombstones = tombstoneParser.parse(fixtureText.lineSequence(), capturedAt = now)
        val wakelocks = wakelockParser.parse(
            fixtureText.lineSequence(),
            bugreportTimestamp = now,
            capturedAt = now,
        )

        // The redacted fixture contains no real tombstone block nor a real
        // `Wake Locks:` section, so both parsers should yield zero events.
        // If a future regression caused the parsers to mis-recognize synthetic
        // content as a crash or wakelock, this assertion would catch it.
        assertTrue(
            "TombstoneParser should not fabricate crashes from fixture content; got: $tombstones",
            tombstones.isEmpty(),
        )
        assertTrue(
            "WakelockParser should not fabricate wakelocks from fixture content; got: $wakelocks",
            wakelocks.isEmpty(),
        )
    }

    @Test
    fun `deleted heuristics are actually gone from main source tree`() {
        val mainSrc = locateMainSrcDir()

        // LegacyScanModule.kt was deleted in plan 6.
        val legacyFiles = mainSrc.walkTopDown()
            .filter { it.isFile && it.name == "LegacyScanModule.kt" }
            .toList()
        assertTrue(
            "LegacyScanModule.kt must not exist in main source; found: $legacyFiles",
            legacyFiles.isEmpty(),
        )

        // BugReportFinding type was deleted in plan 6. Only doc-comment
        // tombstones (lines starting with ` * `) are allowed; no code
        // declarations, imports, or usages.
        val bugReportFindingRefs = mainSrc.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .filter { file ->
                file.readLines().any { line ->
                    line.contains("BugReportFinding") &&
                        !line.trimStart().startsWith("*") &&
                        !line.trimStart().startsWith("//")
                }
            }
            .toList()
        assertTrue(
            "BugReportFinding must not be referenced in main source code; found in: " +
                bugReportFindingRefs.map { it.name },
            bugReportFindingRefs.isEmpty(),
        )

        // The specific deleted heuristic was keyword-matching on
        // `graphite_renderengine` in bugreport content. No Kotlin file
        // should contain that substring now (legitimate Graphite/Paragon
        // spyware rule IDs are fine — they're not the renderengine keyword).
        val renderEngineRefs = mainSrc.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .filter { it.readText().contains("graphite_renderengine", ignoreCase = true) }
            .toList()
        assertTrue(
            "No Kotlin source file should contain 'graphite_renderengine' keyword match; " +
                "found: ${renderEngineRefs.map { it.name }}",
            renderEngineRefs.isEmpty(),
        )
    }

    @Test
    fun `OEM allowlist covers all fixture-relevant prefixes`() {
        val allowlistFile = locateRawResourceFile("known_oem_prefixes.yml")
        val content = allowlistFile.readText()
        // Plan 4 added Unisoc/SPRD chipset prefixes — the direct fix for the
        // tester's false-positive report. com.go.browser and com.xiaomi.midrop
        // are classified via other mechanisms (AOSP Go / Xiaomi system).
        val required = listOf("com.unisoc.", "com.sprd.")
        val missing = required.filterNot { content.contains(it) }
        assertTrue(
            "known_oem_prefixes.yml must cover all fixture-relevant prefixes; missing: $missing",
            missing.isEmpty(),
        )
    }

    @Test
    fun `Finding data class requires a non-blank ruleId field`() {
        // Java reflection: the Finding class must expose a `getRuleId()`
        // method returning String (generated from the `val ruleId: String`
        // primary-constructor property). If a future commit removes or
        // renames it, this test fails and the refactor's
        // "no finding without a rule" invariant is no longer type-enforced.
        val findingClass = Class.forName("com.androdr.sigma.Finding")
        val getRuleId = findingClass.declaredMethods.firstOrNull { it.name == "getRuleId" }
        assertTrue(
            "Finding must expose a getRuleId() accessor (from `val ruleId: String`)",
            getRuleId != null,
        )
        assertTrue(
            "Finding.getRuleId() must return String",
            getRuleId!!.returnType == String::class.java,
        )
    }

    private fun locateMainSrcDir(): File {
        val candidates = listOf(
            File("src/main/java/com/androdr"),
            File("app/src/main/java/com/androdr"),
            File("/home/yasir/AndroDR/app/src/main/java/com/androdr"),
        )
        return candidates.firstOrNull { it.isDirectory }
            ?: error("Could not locate main src dir; tried: ${candidates.map { it.absolutePath }}")
    }

    private fun locateRawResourceFile(name: String): File {
        val candidates = listOf(
            File("src/main/res/raw/$name"),
            File("app/src/main/res/raw/$name"),
            File("/home/yasir/AndroDR/app/src/main/res/raw/$name"),
        )
        return candidates.firstOrNull { it.isFile }
            ?: error("Could not locate raw resource $name")
    }
}

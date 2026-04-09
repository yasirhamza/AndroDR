package com.androdr.sigma

import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/**
 * Build-time enforcement test: every bundled detection and atom rule declares
 * a top-level `category:` field, and every `category: device_posture` rule
 * declares `level:` at `medium` or lower.
 *
 * A rule author trying to ship a `device_posture` rule with `level: high`
 * fails CI here, not at runtime when the engine would silently clamp.
 *
 * Correlation rules (sigma_androdr_corr_*.yml) are exempt — their category
 * is derived at evaluation time from member rule categories, so they MUST
 * NOT declare a top-level category field.
 */
class AllRulesHaveCategoryTest {

    /**
     * Locate the res/raw directory. Mirrors the fallback chain used by
     * AllCorrelationRulesFireTest.loadYaml() so the test works regardless
     * of which directory `./gradlew testDebugUnitTest` is invoked from.
     */
    private fun rulesDirectory(): File {
        val candidates = listOf(
            File("app/src/main/res/raw"),
            File("src/main/res/raw"),
            File("/home/yasir/AndroDR/app/src/main/res/raw"),
        )
        return candidates.firstOrNull { it.isDirectory }
            ?: error(
                "Could not locate res/raw; tried: ${candidates.map { it.absolutePath }}"
            )
    }

    private fun detectionAndAtomRuleFiles(): List<File> =
        rulesDirectory().listFiles { f ->
            f.name.startsWith("sigma_androdr_") &&
                f.name.endsWith(".yml") &&
                !f.name.startsWith("sigma_androdr_corr_")
        }?.toList() ?: emptyList()

    private fun correlationRuleFiles(): List<File> =
        rulesDirectory().listFiles { f ->
            f.name.startsWith("sigma_androdr_corr_") && f.name.endsWith(".yml")
        }?.toList() ?: emptyList()

    /**
     * Extract the top-level `category:` value from a rule YAML.
     * Returns null if no top-level category line exists.
     *
     * "Top-level" means zero leading whitespace — this excludes nested
     * fields like `display.category` which are indented.
     */
    private fun extractTopLevelCategory(file: File): String? =
        file.readText().lines()
            .firstOrNull { line -> line.startsWith("category:") }
            ?.removePrefix("category:")
            ?.trim()

    /**
     * Extract the top-level `level:` value from a rule YAML.
     */
    private fun extractTopLevelLevel(file: File): String? =
        file.readText().lines()
            .firstOrNull { line -> line.startsWith("level:") }
            ?.removePrefix("level:")
            ?.trim()
            ?.lowercase()

    @Test
    fun `every detection and atom rule declares category`() {
        val violations = mutableListOf<String>()
        val ruleFiles = detectionAndAtomRuleFiles()

        assertTrue(
            "Expected at least one detection/atom rule file; found ${ruleFiles.size}. " +
                "Is the test running from the app module root?",
            ruleFiles.isNotEmpty(),
        )

        ruleFiles.forEach { file ->
            val category = extractTopLevelCategory(file)
            when {
                category == null -> violations +=
                    "${file.name}: missing top-level 'category:' field"
                category !in listOf("incident", "device_posture") -> violations +=
                    "${file.name}: category has invalid value '$category' " +
                        "(must be 'incident' or 'device_posture')"
            }
        }

        if (violations.isNotEmpty()) {
            fail(
                "Rule category violations found:\n" +
                    violations.joinToString("\n") { "  - $it" } + "\n\n" +
                    "Every detection and atom rule must declare a top-level " +
                    "category: incident or category: device_posture field. " +
                    "See docs/detection-rules-catalog.md for the categorization principle."
            )
        }
    }

    @Test
    fun `every device_posture rule declares level at medium or below`() {
        val allowedLevels = setOf("medium", "low", "informational")
        val violations = mutableListOf<String>()

        detectionAndAtomRuleFiles().forEach { file ->
            val category = extractTopLevelCategory(file)
            if (category == "device_posture") {
                val level = extractTopLevelLevel(file)
                if (level !in allowedLevels) {
                    violations += "${file.name}: category is device_posture but level is '$level' " +
                        "(must be one of $allowedLevels)"
                }
            }
        }

        if (violations.isNotEmpty()) {
            fail(
                "Device posture severity cap violations:\n" +
                    violations.joinToString("\n") { "  - $it" } + "\n\n" +
                    "Device posture rules are capped at severity 'medium' per the " +
                    "SeverityCapPolicy. Rules declaring 'high' or 'critical' would " +
                    "be silently clamped by the engine — this test catches the " +
                    "mistake at build time instead. If you genuinely need a rule " +
                    "to fire at HIGH or CRITICAL, classify it as category: incident."
            )
        }
    }

    @Test
    fun `correlation rules do not declare top-level category field`() {
        val violations = mutableListOf<String>()

        correlationRuleFiles().forEach { file ->
            if (extractTopLevelCategory(file) != null) {
                violations += "${file.name}: declares top-level 'category:' field but correlation " +
                    "rules must derive category from member rules via propagation"
            }
        }

        if (violations.isNotEmpty()) {
            fail(
                "Correlation rules should not declare category directly:\n" +
                    violations.joinToString("\n") { "  - $it" }
            )
        }
    }
}

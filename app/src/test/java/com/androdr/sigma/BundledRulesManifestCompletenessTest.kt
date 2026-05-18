package com.androdr.sigma

import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/**
 * Build-time gate: verifies every `sigma_androdr_*.yml` file in
 * `app/src/main/res/raw/` is registered in [SigmaRuleEngine]'s explicit
 * `R.raw.*` manifest list. The manifest is R8-safe (no reflection), so a
 * missing entry silently drops the rule from the loader — the rule lives
 * in the bundle but never fires on device.
 *
 * Surfaced by AndroDR #168 PR #189 / PR #190: four broker-SDK rule YAMLs
 * shipped to `res/raw/` but were not registered in the manifest, so the
 * engine loaded 45 SIGMA rules instead of 49 and none of the new rules
 * could fire. This test catches that class of gap automatically.
 *
 * Companion to [BundledRulesSchemaCrossCheckTest] (Kotlin parser vs JSON
 * schema). That test verifies that every loaded rule is well-formed; this
 * one verifies that every rule on disk gets loaded in the first place.
 */
class BundledRulesManifestCompletenessTest {

    private fun rulesDirectory(): File {
        val candidates = listOf(
            File("app/src/main/res/raw"),
            File("src/main/res/raw"),
            File("/home/yasir/AndroDR/app/src/main/res/raw"),
        )
        return candidates.firstOrNull { it.isDirectory }
            ?: error("Could not locate res/raw; tried: ${candidates.map { it.absolutePath }}")
    }

    private fun engineSourceFile(): File {
        val candidates = listOf(
            File("app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt"),
            File("src/main/java/com/androdr/sigma/SigmaRuleEngine.kt"),
            File("/home/yasir/AndroDR/app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt"),
        )
        return candidates.firstOrNull { it.isFile }
            ?: error("Could not locate SigmaRuleEngine.kt; tried: ${candidates.map { it.absolutePath }}")
    }

    private fun yamlsOnDisk(): Set<String> =
        rulesDirectory().listFiles { f ->
            f.name.startsWith("sigma_androdr_") && f.name.endsWith(".yml")
        }?.map { it.nameWithoutExtension }?.toSortedSet()
            ?: emptySet()

    private fun manifestReferences(): List<String> {
        val pattern = Regex("""R\.raw\.(sigma_androdr_[A-Za-z0-9_]+)""")
        return pattern.findAll(engineSourceFile().readText())
            .map { it.groupValues[1] }
            .toList()
    }

    @Test
    fun `every yaml on disk is registered in the SigmaRuleEngine manifest`() {
        val onDisk = yamlsOnDisk()
        assertTrue(
            "Expected at least 40 sigma_androdr_*.yml files but found ${onDisk.size}. " +
                "Is the test running from the correct working directory?",
            onDisk.size >= 40,
        )

        val registered = manifestReferences().toSet()
        val missingFromManifest = (onDisk - registered).sorted()

        if (missingFromManifest.isNotEmpty()) {
            fail(
                "Loader-manifest completeness gate FAILED: ${missingFromManifest.size} rule YAML(s) " +
                    "exist in res/raw/ but are NOT registered in SigmaRuleEngine.kt:\n" +
                    missingFromManifest.joinToString("\n") { "  - $it" } + "\n\n" +
                    "These rules ship in the APK but never load at runtime. Add their R.raw " +
                    "references to the BUNDLED_RAW_RES_IDS list in SigmaRuleEngine.kt to fix."
            )
        }
    }

    @Test
    fun `every SigmaRuleEngine manifest reference points to an existing yaml`() {
        val onDisk = yamlsOnDisk()
        val registered = manifestReferences().toSet()
        val dangling = (registered - onDisk).sorted()

        if (dangling.isNotEmpty()) {
            fail(
                "Loader-manifest completeness gate FAILED: ${dangling.size} R.raw reference(s) " +
                    "in SigmaRuleEngine.kt have no matching file in res/raw/:\n" +
                    dangling.joinToString("\n") { "  - $it" } + "\n\n" +
                    "These references would compile only because R8 doesn't validate resource " +
                    "existence at compile time; they should be removed or the file added."
            )
        }
    }

    @Test
    fun `SigmaRuleEngine manifest contains no duplicate references`() {
        val references = manifestReferences()
        val duplicates = references.groupingBy { it }.eachCount().filter { it.value > 1 }

        if (duplicates.isNotEmpty()) {
            fail(
                "Loader-manifest completeness gate FAILED: ${duplicates.size} duplicate " +
                    "reference(s) in SigmaRuleEngine.kt's BUNDLED_RAW_RES_IDS:\n" +
                    duplicates.entries.joinToString("\n") { (ref, count) -> "  - $ref (x$count)" }
            )
        }
    }
}

package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Build-time cross-check: the ioc_lookup database names declared in
 * validation/ioc-lookup-definitions.yml MUST match the hardcoded map in
 * ScanOrchestrator.initRuleEngine(). Drift fails the build.
 */
class IocLookupDefinitionsCrossCheckTest {

    // Single source of truth for the *expected* set on the Kotlin side.
    // Mirrors the keys set in ScanOrchestrator.setIocLookups(...).
    private val kotlinLookupNames = setOf(
        "package_ioc_db",
        "cert_hash_ioc_db",
        "domain_ioc_db",
        "apk_hash_ioc_db",
        "known_good_app_db",
        "trusted_installer_db",
    )

    private fun definitionsFile(): File {
        val candidates = listOf(
            File("third-party/android-sigma-rules/validation/ioc-lookup-definitions.yml"),
            File("../third-party/android-sigma-rules/validation/ioc-lookup-definitions.yml"),
            File("/home/yasir/AndroDR/third-party/android-sigma-rules/validation/ioc-lookup-definitions.yml"),
        )
        return candidates.firstOrNull { it.isFile }
            ?: error("ioc-lookup-definitions.yml not found. Run: git submodule update --init")
    }

    @Test
    fun `ioc-lookup-definitions keys match kotlin lookup names`() {
        val settings = LoadSettings.builder().setAllowDuplicateKeys(false).build()
        val load = Load(settings)

        @Suppress("UNCHECKED_CAST")
        val doc = load.loadFromString(definitionsFile().readText()) as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val lookups = doc["lookups"] as Map<String, Any?>

        val yamlLookupNames = lookups.keys
        assertEquals(
            "Set of lookup names must match exactly between Kotlin and ioc-lookup-definitions.yml.\n" +
                "Kotlin:   $kotlinLookupNames\n" +
                "YAML:     $yamlLookupNames\n" +
                "Missing from YAML: ${kotlinLookupNames - yamlLookupNames}\n" +
                "Extra in YAML:     ${yamlLookupNames - kotlinLookupNames}",
            kotlinLookupNames,
            yamlLookupNames,
        )
    }

    @Test
    fun `every lookup entry references at least one existing ioc-data file`() {
        val settings = LoadSettings.builder().setAllowDuplicateKeys(false).build()
        val load = Load(settings)

        @Suppress("UNCHECKED_CAST")
        val doc = load.loadFromString(definitionsFile().readText()) as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val lookups = doc["lookups"] as Map<String, Map<String, Any?>>

        val submoduleRoot = definitionsFile().parentFile!!.parentFile!!
        val failures = mutableListOf<String>()

        for ((name, def) in lookups) {
            // Pure-emitter lookups (e.g. trusted_installer_db) are computed at
            // runtime from an emitted field and are not backed by any ioc-data
            // file, so they legitimately have no `files:` entry.
            if (def["pure_emitter"] == true) continue

            @Suppress("UNCHECKED_CAST")
            val files = def["files"] as List<String>
            for (relPath in files) {
                val iocFile = File(submoduleRoot, relPath)
                if (!iocFile.isFile) {
                    failures += "lookup '$name' references missing file: $relPath"
                }
            }
        }

        assertTrue(
            "ioc-lookup-definitions.yml references ioc-data files that do not exist:\n" +
                failures.joinToString("\n"),
            failures.isEmpty(),
        )
    }

    @Test
    fun `every ioc_lookup name used by a bundled rule is registered in ioc-lookup-definitions`() {
        val settings = LoadSettings.builder().setAllowDuplicateKeys(false).build()
        @Suppress("UNCHECKED_CAST")
        val defined = ((Load(settings).loadFromString(definitionsFile().readText()) as Map<String, Any?>)
            ["lookups"] as Map<String, Any?>).keys
        val ruleDir = listOf(
            File("app/src/main/res/raw"),
            File(
                "/home/yasir/AndroDR/.claude/worktrees/phase2-from-trusted-store/" +
                    "app/src/main/res/raw",
            ),
        ).firstOrNull { it.isDirectory } ?: error("res/raw not found")
        val ruleFiles = ruleDir.listFiles { f ->
            f.name.startsWith("sigma_androdr_") && f.name.endsWith(".yml")
        }.orEmpty()
        val lookupRegex = Regex("""\|ioc_lookup:\s*([a-zA-Z0-9_]+)""")
        val used = ruleFiles
            .flatMap { lookupRegex.findAll(it.readText()).map { m -> m.groupValues[1] } }
            .toSet()
        val unknown = used - defined
        assertTrue("Bundled rules reference ioc_lookup names not registered in ioc-lookup-definitions.yml " +
            "(a typo in a negated selection over-fires on every app): $unknown", unknown.isEmpty())
    }
}

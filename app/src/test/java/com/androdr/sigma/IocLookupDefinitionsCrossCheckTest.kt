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
 *
 * Since #136 R1 the evaluator is FAIL-CLOSED — a rule naming an unregistered
 * `ioc_lookup` is skipped whole rather than evaluated with that matcher forced
 * false. That makes a registration the single point of failure for every rule
 * naming it, so two further gates live here (the AndroDR half of rules-repo
 * #275):
 *  - [`registered lookup names in ScanOrchestrator source match the expected set`]
 *    reads the ACTUAL keys out of the production source, so the expected set
 *    below can no longer drift away from the map it claims to mirror.
 *  - [`every delivered and bundled rule's ioc_lookup resolves on this build`]
 *    sweeps the whole shipped corpus through the real
 *    [SigmaRuleEvaluator.unevaluableRules].
 *
 * Fail-vs-skip: unlike the assume-skip sweeps, a missing submodule FAILS here.
 * These gates exist because a silently dropped registration disables live
 * detections; a checkout that cannot run them must say so, not pass.
 */
class IocLookupDefinitionsCrossCheckTest {

    // Single source of truth for the *expected* set on the Kotlin side.
    // Mirrors the keys set in ScanOrchestrator.setIocLookups(...) — and, since
    // #275, that mirroring is itself asserted against the production source.
    private val kotlinLookupNames = setOf(
        "package_ioc_db",
        "cert_hash_ioc_db",
        "domain_ioc_db",
        "apk_hash_ioc_db",
        "known_good_app_db",
        "trusted_installer_db",
        "brand_name_db",
        "brand_domain_db",
    )

    /** Shared locator (its KDoc mandates it) — fail-loud for this test class. */
    private fun submoduleRoot(): File = TestRuleRepo.submoduleRoot()
        ?: error("android-sigma-rules submodule not checked out. Run: git submodule update --init")

    private fun definitionsFile(): File {
        val file = File(submoduleRoot(), "validation/ioc-lookup-definitions.yml")
        assertTrue("Submodule present but ioc-lookup-definitions.yml missing: ${file.path}", file.isFile)
        return file
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

        val submoduleRoot = submoduleRoot()
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
            File("src/main/res/raw"),
            File("/home/yasir/AndroDR/app/src/main/res/raw"),
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

    /**
     * The keys ACTUALLY registered by `ScanOrchestrator.initRuleEngine()`,
     * read out of the production source.
     *
     * Extraction is paren-balanced from the `setIocLookups(mapOf(` anchor over
     * comment-stripped source, rather than a whole-file regex: the same string
     * literals appear in this file's own KDoc/comments and in nearby code, and
     * a regex over the whole file would keep passing after the map itself lost
     * an entry.
     */
    private fun registeredLookupNamesFromSource(): Set<String> {
        val source = TestRuleRepo.stripKotlinComments(
            TestRuleRepo.mainSourceFile(ORCHESTRATOR_SOURCE).readText()
        )
        val anchor = source.indexOf(SET_LOOKUPS_ANCHOR)
        assertTrue(
            "Could not find `$SET_LOOKUPS_ANCHOR` in $ORCHESTRATOR_SOURCE — the registration " +
                "was reshaped. Re-point this gate at the new spelling; do NOT delete it.",
            anchor >= 0,
        )
        // The '(' of `mapOf(` is the last char of the anchor.
        val open = anchor + SET_LOOKUPS_ANCHOR.length - 1
        var depth = 1
        var i = open + 1
        while (i < source.length && depth > 0) {
            when (source[i]) {
                '(' -> depth++
                ')' -> depth--
            }
            i++
        }
        assertEquals("Unbalanced parentheses while extracting the setIocLookups block", 0, depth)
        val block = source.substring(open + 1, i - 1)
        val names = LOOKUP_KEY_PATTERN.findAll(block).map { it.groupValues[1] }.toSet()
        assertTrue(
            "Extracted no lookup keys from the setIocLookups block — extraction broke, " +
                "and a vacuous pass here would hide a dropped registration. Block was:\n$block",
            names.isNotEmpty(),
        )
        return names
    }

    @Test
    fun `registered lookup names in ScanOrchestrator source match the expected set`() {
        val registered = registeredLookupNamesFromSource()
        assertEquals(
            "The lookup names registered by ScanOrchestrator.initRuleEngine() have drifted from " +
                "the set this test (and ioc-lookup-definitions.yml) mirror. Since the evaluator is " +
                "fail-closed, a dropped or renamed registration SILENTLY DISABLES every rule that " +
                "names it — it does not error. Update both sides deliberately.\n" +
                "Expected: $kotlinLookupNames\nIn source: $registered\n" +
                "Missing from source: ${kotlinLookupNames - registered}\n" +
                "Extra in source:     ${registered - kotlinLookupNames}",
            kotlinLookupNames,
            registered,
        )
    }

    @Test
    fun `every delivered and bundled rule's ioc_lookup resolves on this build`() {
        val registered = registeredLookupNamesFromSource()
        // Predicate bodies are irrelevant here — unevaluableRules only asks
        // whether the NAME is registered.
        val lookups: Map<String, (Any) -> Boolean> = registered.associateWith { { _: Any -> true } }

        val bundled = TestRuleRepo.bundledRuleFiles()
        val delivered = TestRuleRepo.submoduleRuleFiles()
            ?: error("android-sigma-rules submodule not checked out. Run: git submodule update --init")
        val corpus = (bundled + delivered).mapNotNull { file ->
            SigmaRuleParser.parse(file.readText())?.let { file.name to it }
        }
        assertTrue(
            "Parsed only ${corpus.size} rules from ${bundled.size} bundled + ${delivered.size} " +
                "delivered files — a mass parse failure would make this sweep vacuous",
            corpus.size >= TestRuleRepo.MIN_RULE_FILES,
        )

        val unevaluable = SigmaRuleEvaluator.unevaluableRules(corpus.map { it.second }, lookups)
        val fileByRuleId = corpus.associate { (name, rule) -> rule.id to name }
        assertTrue(
            "These SHIPPED rules name an ioc_lookup this build does not register, so the " +
                "fail-closed evaluator SKIPS THEM WHOLE — silently, with no error and no finding:\n" +
                unevaluable.entries.joinToString("\n") { (ruleId, name) ->
                    "  $ruleId (${fileByRuleId[ruleId]}): '$name'"
                } +
                "\nRegistered on this build: $registered\n" +
                "Fix by registering the lookup in ScanOrchestrator.initRuleEngine() (and " +
                "ioc-lookup-definitions.yml), or by not delivering the rule.",
            unevaluable.isEmpty(),
        )
    }

    private companion object {
        const val ORCHESTRATOR_SOURCE = "com/androdr/scanner/ScanOrchestrator.kt"
        const val SET_LOOKUPS_ANCHOR = "setIocLookups(mapOf("

        /** `"name" to { … }` — one registration entry in the map literal. */
        val LOOKUP_KEY_PATTERN = Regex(""""([A-Za-z0-9_]+)"\s+to\s*\{""")
    }
}

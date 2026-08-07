package com.androdr.sigma

import org.junit.Assert.assertTrue
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Shared locator + loader for rule-sweep tests (#268).
 *
 * The 5 legacy `rulesDirectory()` copies (and `BundledMirrorParityTest.bundledDir()`)
 * are intentionally left un-retrofitted — migrating them is out of scope, as is
 * `LogsourceTaxonomyCrossCheckTest`'s private taxonomy parse, which predates this
 * helper. NEW tests must use this helper instead of adding another copy.
 *
 * Fail-vs-skip semantics: only an absent submodule checkout is skippable
 * ([submoduleRoot]/[submoduleRuleFiles]/[loadTaxonomy] return null for the caller
 * to `assumeTrue` on, the BundledMirrorParityTest convention). Everything else —
 * missing res/raw, an unparseable taxonomy, floor violations — fails loud, so a
 * broken checkout or truncated taxonomy can never turn a sweep test vacuous.
 */
internal object TestRuleRepo {

    /** Floor: a sweep that finds fewer bundled/delivered rule files than this is
     *  running from the wrong directory, not validating a smaller corpus. */
    const val MIN_RULE_FILES = 40

    /** Floor: a taxonomy with fewer services than this is truncated/corrupt. */
    const val MIN_TAXONOMY_SERVICES = 10

    /** Keywords of the device condition grammar (SigmaRuleEvaluator). */
    val CONDITION_KEYWORDS = setOf("and", "or", "not")

    /**
     * Tokenize a condition EXACTLY as the device evaluator does
     * (SigmaRuleEvaluator: `condition.trim().split("\\s+".toRegex())`) —
     * Java `\s` is ASCII-only. Do NOT "fix" this to be Unicode-aware: the pin
     * is the point. An NBSP-joined condition must stay one (unresolvable)
     * token here exactly as it does on-device, or this gate diverges from the
     * runtime and false-passes.
     */
    fun conditionTokens(condition: String): List<String> =
        condition.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }

    private val yamlLoader = Load(LoadSettings.builder().build())

    fun rulesDirectory(): File {
        val candidates = listOf(
            File("app/src/main/res/raw"),
            File("src/main/res/raw"),
            File("/home/yasir/AndroDR/app/src/main/res/raw"),
        )
        return candidates.firstOrNull { it.isDirectory }
            ?: error("Could not locate res/raw; tried: ${candidates.map { it.absolutePath }}")
    }

    /**
     * Bundled non-correlation rule files. Correlation rules are excluded by the
     * `sigma_androdr_corr_` filename-prefix convention (as the other bundled
     * sweeps do); content-level drift between the naming convention and the
     * `correlation:` key is asserted loudly by DetectionFieldCrossCheckTest.
     */
    fun bundledRuleFiles(): List<File> {
        val files = rulesDirectory().listFiles { f ->
            f.name.startsWith("sigma_androdr_") &&
                f.name.endsWith(".yml") &&
                !f.name.startsWith("sigma_androdr_corr_")
        }?.sorted() ?: emptyList()
        assertTrue(
            "Expected at least $MIN_RULE_FILES bundled rule files but found " +
                "${files.size} — wrong working directory?",
            files.size >= MIN_RULE_FILES,
        )
        return files
    }

    /** The pinned submodule root, or null when not checked out (assume-skip). */
    fun submoduleRoot(): File? = listOf(
        File("third-party/android-sigma-rules"),
        File("../third-party/android-sigma-rules"),
        File("/home/yasir/AndroDR/third-party/android-sigma-rules"),
    ).firstOrNull { it.isDirectory && File(it, "rules.txt").isFile }

    /**
     * Every rules.txt-listed file from the pinned submodule, or null when the
     * submodule is absent. Applies NO correlation filename filter: rules.txt
     * lists no correlation rules today (gated by BundledMirrorParityTest and
     * the rules repo's delivery-set check), and repo filenames carry no
     * `sigma_` prefix so the bundled filter could never match them anyway —
     * if a correlation rule ever appears here, DetectionFieldCrossCheckTest's
     * `correlation:`-key assertion must fail loudly rather than a filter
     * silently muting it.
     */
    fun submoduleRuleFiles(): List<File>? {
        val root = submoduleRoot() ?: return null
        val files = File(root, "rules.txt").readLines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .map { File(root, it) }
        files.firstOrNull { !it.isFile }?.let {
            error("rules.txt lists ${it.path} but the file does not exist — manifest drift")
        }
        assertTrue(
            "Expected at least $MIN_RULE_FILES rules.txt entries but found ${files.size}",
            files.size >= MIN_RULE_FILES,
        )
        return files
    }

    /** One taxonomy service: its detection field names and lifecycle status. */
    data class TaxonomyService(val fields: Set<String>, val status: String)

    /**
     * The pinned submodule's logsource taxonomy, or null when the submodule is
     * absent. A present-but-unparseable taxonomy, a service without a
     * non-empty fields map, or fewer than [MIN_TAXONOMY_SERVICES] services
     * fails loud — mirroring validate-rule.py's fail-closed taxonomy load.
     */
    @Suppress("UNCHECKED_CAST")
    fun loadTaxonomy(): Map<String, TaxonomyService>? {
        val root = submoduleRoot() ?: return null
        val file = File(root, "validation/logsource-taxonomy.yml")
        assertTrue("Submodule present but taxonomy missing: ${file.path}", file.isFile)
        val doc = yamlLoader.loadFromString(file.readText()) as? Map<String, Any?>
            ?: error("logsource-taxonomy.yml did not parse to a map")
        val services = doc["services"] as? Map<String, Map<String, Any?>>
            ?: error("logsource-taxonomy.yml has no services map")
        val parsed = services.mapValues { (name, entry) ->
            val fields = (entry["fields"] as? Map<String, Any?>)?.keys
            if (fields.isNullOrEmpty()) {
                error("taxonomy service '$name' lacks a non-empty fields map")
            }
            TaxonomyService(
                fields = fields,
                status = entry["status"]?.toString()
                    ?: error("taxonomy service '$name' has no status"),
            )
        }
        assertTrue(
            "Expected at least $MIN_TAXONOMY_SERVICES taxonomy services but " +
                "found ${parsed.size} — truncated taxonomy?",
            parsed.size >= MIN_TAXONOMY_SERVICES,
        )
        return parsed
    }
}

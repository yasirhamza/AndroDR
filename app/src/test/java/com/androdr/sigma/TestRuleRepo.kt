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

    /**
     * Strict loader for small frozen-set data files (severity-caps.yml,
     * judgment-field-allowlist.yml): `setAllowDuplicateKeys(false)` so a
     * duplicate top-level key (e.g. two `device_posture:` cap entries) fails
     * loud instead of the second silently overwriting the first — the
     * ioc-lookup-definitions.yml / IocLookupDefinitionsCrossCheckTest idiom.
     */
    private val strictYamlLoader = Load(LoadSettings.builder().setAllowDuplicateKeys(false).build())

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

    /**
     * One taxonomy service: its detection field names, lifecycle status, and
     * per-field `kind` (raw_fact/judgment — see logsource-taxonomy.yml's
     * header). [fieldKinds] maps every name in [fields] to its raw YAML
     * `kind` value, or null when the field entry has no `kind` key at all (or
     * isn't a map) — validity of that value is a test concern
     * ([TaxonomyJudgmentCrossCheckTest]), not a loader concern, so an
     * unexpected/missing kind does NOT fail here.
     */
    data class TaxonomyService(
        val fields: Set<String>,
        val status: String,
        val fieldKinds: Map<String, String?> = emptyMap(),
    )

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
            val fieldsRaw = entry["fields"] as? Map<String, Any?>
            if (fieldsRaw.isNullOrEmpty()) {
                error("taxonomy service '$name' lacks a non-empty fields map")
            }
            TaxonomyService(
                fields = fieldsRaw.keys,
                status = entry["status"]?.toString()
                    ?: error("taxonomy service '$name' has no status"),
                fieldKinds = fieldsRaw.mapValues { (_, fieldEntry) ->
                    (fieldEntry as? Map<*, *>)?.get("kind")?.toString()
                },
            )
        }
        assertTrue(
            "Expected at least $MIN_TAXONOMY_SERVICES taxonomy services but " +
                "found ${parsed.size} — truncated taxonomy?",
            parsed.size >= MIN_TAXONOMY_SERVICES,
        )
        return parsed
    }

    /**
     * Per-rule-category severity cap declared in `validation/severity-caps.yml`
     * (#136 R1, spec B3), keyed by the YAML's own (unvalidated) category
     * string — mapping that key to a real [RuleCategory] is
     * [SeverityCapsCrossCheckTest]'s job, not this loader's, so an unknown key
     * surfaces as a normal map entry rather than failing here. Null when the
     * submodule is absent (assume-skip).
     */
    @Suppress("UNCHECKED_CAST")
    fun severityCaps(): Map<String, String>? {
        val root = submoduleRoot() ?: return null
        val file = File(root, "validation/severity-caps.yml")
        assertTrue("Submodule present but severity-caps.yml missing: ${file.path}", file.isFile)
        val doc = strictYamlLoader.loadFromString(file.readText()) as? Map<String, Any?>
            ?: error("severity-caps.yml did not parse to a map")
        val caps = doc["caps"] as? Map<String, Any?>
            ?: error("severity-caps.yml has no 'caps' map")
        return caps.mapValues { (key, value) ->
            value?.toString() ?: error("severity-caps.yml cap for '$key' is null")
        }
    }

    /** One judgment field's allowed rule ids, split by delivery lifecycle. */
    data class JudgmentFieldAllowance(val delivered: Set<String>, val staging: Set<String>)

    /**
     * `validation/judgment-field-allowlist.yml`'s `allowed` map (#136 R1, spec
     * B5): field name → the rule ids permitted to reference it, split into
     * `delivered` (res/raw + rules.txt) and `staging`. The TOP-LEVEL KEYS of
     * this map are the frozen judgment-field set — see the YAML's own header
     * and [TaxonomyJudgmentCrossCheckTest]. Null when the submodule is absent
     * (assume-skip).
     */
    @Suppress("UNCHECKED_CAST")
    fun judgmentAllowlist(): Map<String, JudgmentFieldAllowance>? {
        val root = submoduleRoot() ?: return null
        val file = File(root, "validation/judgment-field-allowlist.yml")
        assertTrue(
            "Submodule present but judgment-field-allowlist.yml missing: ${file.path}",
            file.isFile,
        )
        val doc = strictYamlLoader.loadFromString(file.readText()) as? Map<String, Any?>
            ?: error("judgment-field-allowlist.yml did not parse to a map")
        val allowed = doc["allowed"] as? Map<String, Map<String, Any?>>
            ?: error("judgment-field-allowlist.yml has no 'allowed' map")
        return allowed.mapValues { (field, entry) ->
            val delivered = (entry["delivered"] as? List<*>)?.map { it.toString() }?.toSet()
                ?: error("judgment-field-allowlist.yml field '$field' has no 'delivered' list")
            val staging = (entry["staging"] as? List<*>)?.map { it.toString() }?.toSet()
                ?: error("judgment-field-allowlist.yml field '$field' has no 'staging' list")
            JudgmentFieldAllowance(delivered = delivered, staging = staging)
        }
    }
}

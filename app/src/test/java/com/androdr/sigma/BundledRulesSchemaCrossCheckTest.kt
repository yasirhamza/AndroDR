package com.androdr.sigma

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.networknt.schema.SchemaRegistry
import com.networknt.schema.SpecificationVersion
import org.junit.Assume.assumeTrue
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Build-time cross-check gate: validates every bundled detection/atom SIGMA rule
 * against BOTH:
 * 1. The Kotlin runtime parser (SigmaRuleParser.parse())
 * 2. The JSON schema from the android-sigma-rules submodule (rule-schema.json)
 *
 * If either rejects a rule, the build fails — closing the drift loop between
 * the dev pipeline and the AI-powered rule updater.
 *
 * Correlation rules (sigma_androdr_corr_*.yml) are excluded (deferred to Bundle 3).
 */
class BundledRulesSchemaCrossCheckTest {

    private val objectMapper = ObjectMapper()

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

    private fun schemaFile(): File? {
        val candidates = listOf(
            File("third-party/android-sigma-rules/validation/rule-schema.json"),
            File("../third-party/android-sigma-rules/validation/rule-schema.json"),
            File("/home/yasir/AndroDR/third-party/android-sigma-rules/validation/rule-schema.json"),
        )
        return candidates.firstOrNull { it.isFile }
    }

    private fun detectionAndAtomRuleFiles(): List<File> =
        rulesDirectory().listFiles { f ->
            f.name.startsWith("sigma_androdr_") &&
                f.name.endsWith(".yml") &&
                !f.name.startsWith("sigma_androdr_corr_")
        }?.sorted() ?: emptyList()

    @Test
    fun `schema file is reachable from submodule`() {
        val schema = schemaFile()
        assertTrue(
            "rule-schema.json not found. Run: git submodule update --init",
            schema != null && schema.isFile,
        )
    }

    @Test
    fun `every bundled detection rule is accepted by SigmaRuleParser`() {
        val ruleFiles = detectionAndAtomRuleFiles()

        assertTrue(
            "Expected at least 40 detection/atom rule files but found ${ruleFiles.size}. " +
                "Is the test running from the correct working directory?",
            ruleFiles.size >= 40,
        )

        val failures = mutableListOf<String>()

        ruleFiles.forEach { file ->
            try {
                val result = SigmaRuleParser.parse(file.readText())
                if (result == null) {
                    failures += "${file.name}: SigmaRuleParser.parse() returned null"
                }
            } catch (e: Exception) {
                failures += "${file.name}: SigmaRuleParser.parse() threw ${e::class.simpleName}: ${e.message}"
            }
        }

        if (failures.isNotEmpty()) {
            fail(
                "Kotlin parser gate FAILED for ${failures.size} rule(s):\n" +
                    failures.joinToString("\n") { "  - $it" } + "\n\n" +
                    "Check that the rule contains all required fields (id, category, " +
                    "logsource, detection) and that category is 'incident' or 'device_posture'."
            )
        }
    }

    @Test
    fun `every bundled detection rule passes JSON schema validation`() {
        val schema = schemaFile()
        assumeTrue(
            "Skipping: rule-schema.json not found (submodule not initialized). " +
                "Run: git submodule update --init",
            schema != null && schema.isFile,
        )

        val ruleFiles = detectionAndAtomRuleFiles()

        assertTrue(
            "Expected at least 40 detection/atom rule files but found ${ruleFiles.size}.",
            ruleFiles.size >= 40,
        )

        val registry = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12)
        val jsonSchema = schema!!.inputStream().use { registry.getSchema(it) }

        val yamlLoader = Load(
            LoadSettings.builder()
                .setMaxAliasesForCollections(10)
                .setAllowDuplicateKeys(false)
                .build()
        )
        val failures = mutableListOf<String>()

        ruleFiles.forEach { file ->
            try {
                @Suppress("UNCHECKED_CAST")
                val yamlMap = yamlLoader.loadFromString(file.readText()) as? Map<String, Any?>
                if (yamlMap == null) {
                    failures += "${file.name}: YAML parsed to null or non-map"
                    return@forEach
                }

                val jsonNode: JsonNode = objectMapper.valueToTree(yamlMap)
                val errors = jsonSchema.validate(jsonNode)

                if (errors.isNotEmpty()) {
                    val errorSummary = errors.joinToString("; ") { err -> err.message }
                    failures += "${file.name}: schema violations: $errorSummary"
                }
            } catch (e: Exception) {
                failures += "${file.name}: conversion/validation threw ${e::class.simpleName}: ${e.message}"
            }
        }

        if (failures.isNotEmpty()) {
            fail(
                "JSON schema gate FAILED for ${failures.size} rule(s):\n" +
                    failures.joinToString("\n") { "  - $it" } + "\n\n" +
                    "If you added a new field or service to SigmaRuleParser, update " +
                    "rule-schema.json in the android-sigma-rules repo and bump the submodule."
            )
        }
    }

    /**
     * Defense in depth: a rule's `implies_flags: [sideloaded]` only carries the
     * intended guarantee if the rule's detection actually conditions on the app
     * being sideloaded. Two structural patterns satisfy this:
     *
     *   1. A block referenced positively in `condition` declares
     *      `from_trusted_store: false` or `is_sideloaded: true`
     *
     *   2. A block referenced negatively (`not <name>`) in `condition` declares
     *      `from_trusted_store: true` or `is_sideloaded: false`
     *      (the negation makes the property hold)
     *
     * Without this gate, a rule author could add the annotation to a rule that
     * fires on Play Store apps and the Flag would silently lie.
     *
     * Asymmetry note: there is no parallel gate for `implies_flags: [known_malware]`.
     * That annotation is semantic ("this rule's detection corpus is a curated
     * malware database") and doesn't have a single structural signature — IOC
     * lookups (`|ioc_lookup`) and exact-literal package-name matches (e.g. -078)
     * are both valid. Adding a known_malware gate without false negatives would
     * require a more sophisticated heuristic; deferred.
     *
     * Tokenizer scope: the condition parser below handles flat conditions
     * (`a and not b and not c`, `a or b`). It does NOT correctly handle
     * parenthesized negation like `not (filter_a or filter_b)` — after paren
     * stripping the inner `or` would reset the negation state. The bundled
     * corpus has no such conditions today; the loop at the end asserts this
     * so a future rule introducing parens trips the test rather than silently
     * mis-classifying.
     */
    @Test
    fun `rules declaring implies_flags sideloaded structurally guarantee it`() {
        val yamlLoader = Load(
            LoadSettings.builder().setMaxAliasesForCollections(10).setAllowDuplicateKeys(false).build()
        )
        val violations = detectionAndAtomRuleFiles().mapNotNull { file ->
            @Suppress("UNCHECKED_CAST")
            val doc = yamlLoader.loadFromString(file.readText()) as? Map<String, Any?>
                ?: return@mapNotNull null
            val implies = (doc["implies_flags"] as? List<*>)?.map { it.toString() } ?: return@mapNotNull null
            if ("sideloaded" !in implies) return@mapNotNull null
            sideloadedStructuralViolation(file.name, doc)
        }
        if (violations.isNotEmpty()) {
            fail(
                "implies_flags structural-guarantee gate FAILED for ${violations.size} rule(s):\n" +
                    violations.joinToString("\n") { "  - $it" }
            )
        }
    }

    private fun sideloadedStructuralViolation(fileName: String, doc: Map<String, Any?>): String? {
        @Suppress("UNCHECKED_CAST")
        val detection = doc["detection"] as? Map<String, Any?> ?: return null
        val condition = (detection["condition"] as? String) ?: ""

        // Tripwire: parens not supported by flat-condition tokenizer below.
        if ("(" in condition || ")" in condition) {
            return "$fileName: condition contains parentheses, which this structural " +
                "gate does not parse correctly. Refactor to a flat condition or " +
                "extend the test with a proper boolean-expression parser."
        }

        val (positive, negative) = tokenizeFlatCondition(condition)
        val sideloadEvidence = positive.any { name -> blockEstablishesSideload(detection, name, negated = false) } ||
            negative.any { name -> blockEstablishesSideload(detection, name, negated = true) }
        return if (sideloadEvidence) null
        else "$fileName: declares `implies_flags: [sideloaded]` but no detection clause " +
            "establishes it. Need either a positive block with `from_trusted_store: false` / " +
            "`is_sideloaded: true`, or a negated block (`not <name>` in condition) with " +
            "`from_trusted_store: true` / `is_sideloaded: false`."
    }

    /** Split a flat SIGMA condition string into (positively-referenced, negatively-referenced) block names. */
    private fun tokenizeFlatCondition(condition: String): Pair<Set<String>, Set<String>> {
        val tokens = condition.lowercase().split(Regex("\\s+")).filter { it.isNotEmpty() }
        val pos = mutableSetOf<String>()
        val neg = mutableSetOf<String>()
        var negate = false
        for (tok in tokens) when (tok) {
            "and", "or" -> negate = false
            "not" -> negate = true
            else -> { if (negate) neg.add(tok) else pos.add(tok); negate = false }
        }
        return pos to neg
    }

    /**
     * True iff the named detection block, considered with its polarity in the condition,
     * establishes the sideloaded property:
     *   positive: block has `from_trusted_store: false` or `is_sideloaded: true`
     *   negated:  block has `from_trusted_store: true` or `is_sideloaded: false`
     */
    private fun blockEstablishesSideload(
        detection: Map<String, Any?>, name: String, negated: Boolean
    ): Boolean {
        @Suppress("UNCHECKED_CAST")
        val block = detection[name] as? Map<String, Any?> ?: return false
        val trustedExpected = if (negated) true else false
        val sideloadedExpected = if (negated) false else true
        return (block["from_trusted_store"] == trustedExpected) ||
            (block["is_sideloaded"] == sideloadedExpected)
    }
}

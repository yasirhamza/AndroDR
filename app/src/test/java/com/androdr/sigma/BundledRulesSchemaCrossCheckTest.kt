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
}

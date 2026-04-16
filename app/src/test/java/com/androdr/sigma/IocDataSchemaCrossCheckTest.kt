package com.androdr.sigma

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.networknt.schema.SchemaRegistry
import com.networknt.schema.SpecificationVersion
import org.junit.Assume.assumeTrue
import org.junit.Assert.fail
import org.junit.Test
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Build-time cross-check: every entry in every ioc-data YAML file MUST validate
 * against validation/ioc-entry-schema.json. Mirrors the pattern of
 * BundledRulesSchemaCrossCheckTest.
 */
class IocDataSchemaCrossCheckTest {

    private val objectMapper = ObjectMapper()

    private fun schemaFile(): File? {
        val candidates = listOf(
            File("third-party/android-sigma-rules/validation/ioc-entry-schema.json"),
            File("../third-party/android-sigma-rules/validation/ioc-entry-schema.json"),
            File("/home/yasir/AndroDR/third-party/android-sigma-rules/validation/ioc-entry-schema.json"),
        )
        return candidates.firstOrNull { it.isFile }
    }

    private fun iocDataFiles(): List<File> {
        val candidates = listOf(
            File("third-party/android-sigma-rules/ioc-data"),
            File("../third-party/android-sigma-rules/ioc-data"),
            File("/home/yasir/AndroDR/third-party/android-sigma-rules/ioc-data"),
        )
        val dir = candidates.firstOrNull { it.isDirectory } ?: return emptyList()
        return dir.listFiles { f -> f.name.endsWith(".yml") }?.sorted() ?: emptyList()
    }

    @Test
    fun `every ioc-data entry validates against ioc-entry-schema`() {
        val schema = schemaFile()
        assumeTrue(
            "Skipping: ioc-entry-schema.json not found (submodule not initialized). " +
                "Run: git submodule update --init",
            schema != null && schema.isFile,
        )

        val files = iocDataFiles()
        assumeTrue("No ioc-data/*.yml files found", files.isNotEmpty())

        val registry = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12)
        val jsonSchema = schema!!.inputStream().use { registry.getSchema(it) }

        val yamlLoader = Load(
            LoadSettings.builder()
                .setMaxAliasesForCollections(10)
                .setAllowDuplicateKeys(false)
                .build()
        )
        val failures = mutableListOf<String>()

        files.forEach { file ->
            try {
                @Suppress("UNCHECKED_CAST")
                val doc = yamlLoader.loadFromString(file.readText()) as? Map<String, Any?> ?: run {
                    failures += "${file.name}: not a YAML map"
                    return@forEach
                }
                @Suppress("UNCHECKED_CAST")
                val entries = doc["entries"] as? List<Map<String, Any?>> ?: emptyList()
                entries.forEachIndexed { idx, entry ->
                    val jsonNode: JsonNode = objectMapper.valueToTree(entry)
                    val errors = jsonSchema.validate(jsonNode)
                    if (errors.isNotEmpty()) {
                        val summary = errors.joinToString("; ") { e -> e.message }
                        failures += "${file.name} entries[${idx}]: $summary"
                    }
                }
            } catch (e: Exception) {
                failures += "${file.name}: ${e::class.simpleName}: ${e.message}"
            }
        }

        if (failures.isNotEmpty()) {
            fail(
                "ioc-entry-schema gate FAILED for ${failures.size} entry(ies):\n" +
                    failures.joinToString("\n") { "  - $it" } + "\n\n" +
                    "If you added a new IOC field, update ioc-entry-schema.json in the " +
                    "android-sigma-rules repo and bump the submodule."
            )
        }
    }
}

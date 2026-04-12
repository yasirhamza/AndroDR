package com.androdr.sigma

import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Gate 4 parameterized fixture test.
 *
 * Discovers all *.yml files under gate4-fixtures/, loads the referenced SIGMA rule
 * from res/raw/, parses it with [SigmaRuleParser], verifies the service matches the
 * fixture declaration, and then runs [GateFourTestHarness.runGate4] asserting all
 * true-positive and true-negative cases pass.
 */
@RunWith(Parameterized::class)
class GateFourFixtureTest(
    private val fixtureName: String,
    private val fixtureFile: File
) {

    companion object {

        private val yamlLoader: Load = Load(
            LoadSettings.builder()
                .setMaxAliasesForCollections(10)
                .setAllowDuplicateKeys(false)
                .build()
        )

        private fun fixturesDirectory(): File {
            val candidates = listOf(
                File("app/src/test/resources/gate4-fixtures"),
                File("src/test/resources/gate4-fixtures"),
                File("/home/yasir/AndroDR/app/src/test/resources/gate4-fixtures")
            )
            return candidates.firstOrNull { it.isDirectory }
                ?: error(
                    "Could not locate gate4-fixtures directory; tried: " +
                        candidates.map { it.absolutePath }
                )
        }

        private fun rulesDirectory(): File {
            val candidates = listOf(
                File("app/src/main/res/raw"),
                File("src/main/res/raw"),
                File("/home/yasir/AndroDR/app/src/main/res/raw")
            )
            return candidates.firstOrNull { it.isDirectory }
                ?: error(
                    "Could not locate res/raw directory; tried: " +
                        candidates.map { it.absolutePath }
                )
        }

        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        @Suppress("UNCHECKED_CAST")
        fun fixtures(): List<Array<Any>> {
            val dir = fixturesDirectory()
            return dir.listFiles { f -> f.name.endsWith(".yml") }
                ?.sorted()
                ?.map { file -> arrayOf(file.nameWithoutExtension, file) as Array<Any> }
                ?: emptyList()
        }
    }

    @Suppress("UNCHECKED_CAST")
    @Test
    fun `fixture passes gate 4`() {
        val raw = fixtureFile.readText()
        val fixtureMap = yamlLoader.loadFromString(raw) as? Map<String, Any?>
            ?: error("Fixture $fixtureName: YAML did not parse to a map")

        val ruleFile = fixtureMap["rule_file"] as? String
            ?: error("Fixture $fixtureName: missing 'rule_file' key")

        val fixtureService = fixtureMap["service"] as? String
            ?: error("Fixture $fixtureName: missing 'service' key")

        // Load and parse the rule
        val ruleText = File(rulesDirectory(), ruleFile).readText()
        val rule = SigmaRuleParser.parse(ruleText)
            ?: error("Fixture $fixtureName: SigmaRuleParser.parse() returned null for $ruleFile")

        // Assert service declared in fixture matches parsed rule
        assertTrue(
            "Fixture $fixtureName: service mismatch — fixture declares '$fixtureService' " +
                "but rule $ruleFile has service '${rule.service}'",
            rule.service == fixtureService
        )

        // Parse ioc_stubs: Map<String, List<String>>
        val iocStubsRaw = fixtureMap["ioc_stubs"] as? Map<String, Any?> ?: emptyMap()
        val iocStubs: Map<String, Set<String>> = iocStubsRaw.mapValues { (_, v) ->
            (v as? List<*>)?.mapNotNull { it?.toString() }?.toSet() ?: emptySet()
        }

        // Parse true_positives and true_negatives: each is a List<Map<String, Any?>>
        val truePositives = parseRecordList(fixtureMap, "true_positives", fixtureName)
        val trueNegatives = parseRecordList(fixtureMap, "true_negatives", fixtureName)

        // Run gate 4
        val result = GateFourTestHarness.runGate4(
            rule = rule,
            truePositives = truePositives,
            trueNegatives = trueNegatives,
            iocStubs = iocStubs
        )

        assertTrue(
            "Fixture '$fixtureName' FAILED gate 4:\n" +
                result.errors.joinToString("\n") { "  $it" },
            result.pass
        )
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseRecordList(
        fixtureMap: Map<String, Any?>,
        key: String,
        fixtureName: String
    ): List<Map<String, Any?>> {
        val raw = fixtureMap[key] as? List<*> ?: return emptyList()
        return raw.mapIndexed { idx, entry ->
            (entry as? Map<*, *>)?.entries
                ?.associate { (k, v) -> k.toString() to v }
                ?: error("Fixture $fixtureName: $key[$idx] is not a map")
        }
    }
}

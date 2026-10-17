package com.androdr.reporting

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Every logsource service is either run by a live scan (SCANNER_FOR_SERVICE, keyed to the name the
 * orchestrator records when that scanner crashes) or only by an import (IMPORT_ONLY_SERVICES).
 * A new service or a renamed scanner would otherwise count as "always checked" (#394).
 */
class ServiceScannerMapCrossCheckTest {

    private fun file(vararg candidates: String) = candidates.map(::File).first { it.isFile }

    @Suppress("UNCHECKED_CAST")
    private fun taxonomyServices(): Set<String> {
        val f = file("../third-party/android-sigma-rules/validation/logsource-taxonomy.yml",
            "third-party/android-sigma-rules/validation/logsource-taxonomy.yml")
        val root = Load(LoadSettings.builder().build()).loadFromString(f.readText()) as Map<String, Any?>
        return (root["services"] as Map<String, Any?>).keys
    }

    @Test
    fun `every taxonomy service is classified exactly once`() {
        val services = taxonomyServices()
        assertEquals(services, SCANNER_FOR_SERVICE.keys + IMPORT_ONLY_SERVICES)
        assertTrue((SCANNER_FOR_SERVICE.keys intersect IMPORT_ONLY_SERVICES).isEmpty())
    }

    @Test
    fun `every mapped scanner name is one the orchestrator records`() {
        val source = file("src/main/java/com/androdr/scanner/ScanOrchestrator.kt",
            "app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt").readText()
        val recorded = Regex("""trackedAsync\(\s*"(\w+)"""").findAll(source).map { it.groupValues[1] }.toSet() +
            (if ("scanner = DNS_SNAPSHOT_SCANNER" in source) setOf(DNS_SNAPSHOT_SCANNER) else emptySet())
        assertTrue("not recorded by ScanOrchestrator: ${SCANNER_FOR_SERVICE.values.toSet() - recorded}",
            recorded.containsAll(SCANNER_FOR_SERVICE.values))
    }
}

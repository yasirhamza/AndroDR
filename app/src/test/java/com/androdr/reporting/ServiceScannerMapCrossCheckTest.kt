package com.androdr.reporting

import com.androdr.sigma.TestRuleRepo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Every logsource service is either run by a live scan (SCANNER_FOR_SERVICE, keyed to the name the
 * orchestrator records when that scanner crashes), only by an import (IMPORT_ONLY_SERVICES), or
 * never, being stored but not rule-evaluated ([emitterOnlyServices]).
 * A new service or a renamed scanner would otherwise count as "always checked" (#394).
 */
class ServiceScannerMapCrossCheckTest {

    /**
     * Services that are stored but never rule-evaluated (taxonomy `status: emitter_only`). Test-only:
     * no production code branches on them. No rule may target one, so no campaign can name it in
     * `detected_by`; if one ever did, [campaignCoverage] would report it as an unknown service,
     * which is the honest answer.
     */
    private val emitterOnlyServices: Set<String> = setOf(
        "usage_stats", "system_property", "adb_audit", "activity_audit",
    )

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
        assertEquals(services, SCANNER_FOR_SERVICE.keys + IMPORT_ONLY_SERVICES + emitterOnlyServices)
        assertTrue((SCANNER_FOR_SERVICE.keys intersect IMPORT_ONLY_SERVICES).isEmpty())
        assertTrue((SCANNER_FOR_SERVICE.keys intersect emitterOnlyServices).isEmpty())
        assertTrue((IMPORT_ONLY_SERVICES intersect emitterOnlyServices).isEmpty())
    }

    @Test
    fun `emitter-only services are exactly the taxonomy's emitter_only services`() {
        val taxonomy = TestRuleRepo.loadTaxonomy()
        assumeTrue("Skipping: submodule not initialized.", taxonomy != null)
        assertEquals(taxonomy!!.filterValues { it.status == "emitter_only" }.keys, emitterOnlyServices)
    }

    @Test
    fun `every mapped scanner name is one the orchestrator records`() {
        // The live scan's scanners are run (and their failures recorded) by LiveScanCollector.
        val source = file("src/main/java/com/androdr/scanner/LiveScanCollector.kt",
            "app/src/main/java/com/androdr/scanner/LiveScanCollector.kt").readText()
        // Comment lines are dropped so a mention in a KDoc or comment cannot satisfy the DNS check.
        val code = source.lines().filterNot { line ->
            line.trimStart().let { it.startsWith("//") || it.startsWith("*") }
        }.joinToString("\n")
        val recorded = Regex("""tracked\(\s*"(\w+)"""").findAll(code).map { it.groupValues[1] }.toSet() +
            (if (Regex("""scanner\s*=\s*DNS_SNAPSHOT_SCANNER""").containsMatchIn(code)) setOf(DNS_SNAPSHOT_SCANNER)
            else emptySet())
        assertTrue("not recorded by LiveScanCollector: ${SCANNER_FOR_SERVICE.values.toSet() - recorded}",
            recorded.containsAll(SCANNER_FOR_SERVICE.values))
    }

    @Test
    fun `every coverage producer scanner name is recorded`() {
        // Comment lines are dropped, as in the DNS check above, so a mention cannot satisfy the pin.
        fun code(name: String): String = file("src/main/java/com/androdr/scanner/$name",
            "app/src/main/java/com/androdr/scanner/$name").readText().lines().filterNot { line ->
            line.trimStart().let { it.startsWith("//") || it.startsWith("*") }
        }.joinToString("\n")
        // The live scan's DNS attribution failures are recorded where its DNS chunk is appended.
        val orchestrator = code("WriterSessions.kt")
        val visibility = code("ScanVisibilityGaps.kt")
        assertTrue("attribution must be recorded via ATTRIBUTION_SCANNER",
            Regex("""scanner\s*=\s*ATTRIBUTION_SCANNER""").containsMatchIn(orchestrator))
        assertTrue("visibility gaps must be recorded via VISIBILITY_GAPS_SCANNER",
            Regex("""scanner\s*=\s*VISIBILITY_GAPS_SCANNER""").containsMatchIn(visibility))
        assertFalse(Regex("""scanner\s*=\s*"attribution"""").containsMatchIn(orchestrator))
        assertFalse(Regex("""scanner\s*=\s*"visibility_gaps"""").containsMatchIn(visibility))
    }
}

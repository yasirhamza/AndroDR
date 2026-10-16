package com.androdr.sigma

import com.androdr.scanner.ScanOrchestrator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** A declared evidence_type with no provider falls back silently; this makes it fail the build. */
class EvidenceProviderCoverageTest {
    private fun dir(vararg p: String) = p.map(::File).first { it.isDirectory }

    private fun bundledRules(): List<SigmaRule> = dir("app/src/main/res/raw", "src/main/res/raw")
        .listFiles { f -> f.name.startsWith("sigma_androdr_") && !f.name.startsWith("sigma_androdr_corr_") }!!
        .mapNotNull { SigmaRuleParser.parse(it.readText()) }

    private fun deliveredRules(): List<SigmaRule> {
        val root = dir("third-party/android-sigma-rules", "../third-party/android-sigma-rules")
        return File(root, "rules.txt").readLines().map { it.trim() }
            .filter { it.endsWith(".yml") && !it.startsWith("#") }
            .mapNotNull { SigmaRuleParser.parse(File(root, it).readText()) }
    }

    @Test
    fun `IOC lookup rules declare ioc_match`() {
        val byId = bundledRules().associateBy { it.id }
        for (id in listOf("androdr-001", "androdr-002", "androdr-003")) {
            assertEquals(id, "ioc_match", byId.getValue(id).display.evidenceType)
        }
    }

    @Test
    fun `every declared evidence type has a registered provider`() {
        val rules = bundledRules() + deliveredRules()
        val unprovided = rules.map { it.id to it.display.evidenceType }
            .filter { (_, t) -> t != "none" && t !in ScanOrchestrator.REGISTERED_EVIDENCE_TYPES }
        assertTrue("Rules declare evidence types with no provider: $unprovided", unprovided.isEmpty())
    }
}

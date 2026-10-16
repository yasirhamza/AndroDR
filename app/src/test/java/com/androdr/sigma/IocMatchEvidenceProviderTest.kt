package com.androdr.sigma

import com.androdr.data.model.Indicator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Regression gate: an IOC-lookup finding names the threat it matched. */
class IocMatchEvidenceProviderTest {
    private fun rule(f: String) = SigmaRuleParser.parse(
        File(listOf(File("app/src/main/res/raw"), File("src/main/res/raw")).first { it.isDirectory }, f).readText())!!

    private val rows = mapOf(
        "domain_ioc_db" to mapOf("forti.external-muki.com" to Indicator("domain", "forti.external-muki.com",
            family = "Graphite (Paragon)", category = "NATION_STATE_SPYWARE", campaignKey = "graphite",
            source = "androdr_public_repo", reference = "https://citizenlab.ca/x", fetchedAt = 0L)),
        "package_ioc_db" to mapOf("com.serv.services" to Indicator("package", "com.serv.services",
            family = "NoviSpy", category = "NATION_STATE_SPYWARE", source = "androdr_public_repo", fetchedAt = 0L)),
    )
    private val provider = IocMatchEvidenceProvider { db, v -> rows[db]?.get(v) }

    @Test
    fun `domain hit carries Graphite family, campaign and reference`() {
        val e = provider.provide(rule("sigma_androdr_003_domain_ioc.yml"),
            mapOf("domain" to "forti.external-muki.com")).single().evidence as Evidence.IocMatch
        assertEquals("Graphite (Paragon)", e.family)
        assertEquals("graphite", e.campaign)
        assertEquals("https://citizenlab.ca/x", e.reference)
    }

    @Test
    fun `package hit carries family and category`() {
        val e = provider.provide(rule("sigma_androdr_001_package_ioc.yml"),
            mapOf("package_name" to "com.serv.services", "is_system_app" to false))
            .single().evidence as Evidence.IocMatch
        assertEquals("NoviSpy", e.family); assertEquals("NATION_STATE_SPYWARE", e.category)
    }

    @Test
    fun `evaluator attaches attribution to the finding`() {
        val f = SigmaRuleEvaluator.evaluate(listOf(rule("sigma_androdr_003_domain_ioc.yml")),
            listOf(mapOf("domain" to "forti.external-muki.com")), "dns_monitor",
            mapOf("domain_ioc_db" to { v: Any -> rows["domain_ioc_db"]!!.containsKey(v.toString()) }),
            mapOf("ioc_match" to provider)).single()
        assertEquals("Graphite (Paragon)", (f.evidence as Evidence.IocMatch).family)
    }

    @Test
    fun `domain hit carries the DNS observation time`() {
        val e = provider.provide(rule("sigma_androdr_003_domain_ioc.yml"),
            mapOf("domain" to "forti.external-muki.com", "timestamp" to 1_760_000_000_000L))
            .single().evidence as Evidence.IocMatch
        assertEquals(1_760_000_000_000L, e.observedAt)
    }

    @Test
    fun `no stored row means no evidence`() {
        assertTrue(provider.provide(rule("sigma_androdr_003_domain_ioc.yml"), mapOf("domain" to "x.example")).isEmpty())
    }
}

package com.androdr.scanner

import com.androdr.data.model.Indicator
import com.androdr.ioc.ApkHashIocDatabase
import com.androdr.ioc.BundledDomainDatabase
import com.androdr.ioc.CertHashIocDatabase
import com.androdr.ioc.FakeIndicatorDao
import com.androdr.ioc.IndicatorResolver
import com.androdr.ioc.IocDatabase
import com.androdr.ioc.CampaignRegistry
import com.androdr.data.model.ScanResult
import com.androdr.reporting.ReportFormatter
import com.androdr.sigma.Evidence
import com.androdr.sigma.SigmaRuleEvaluator
import com.androdr.sigma.SigmaRuleParser
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class IocEvidenceRegistrationTest {
    private val dao = FakeIndicatorDao()
    private val bundledDomains = mockk<BundledDomainDatabase> { every { lookup(any()) } returns null }
    private val resolver = IndicatorResolver(
        dao,
        mockk<IocDatabase> { every { isKnownBadPackage(any()) } returns null },
        mockk<CertHashIocDatabase> { every { isKnownBadCert(any()) } returns null },
        mockk<ApkHashIocDatabase> { every { isKnownBadApkHash(any()) } returns null },
        bundledDomains,
    )
    private val host = "forti.external-muki.com"
    private val row = Indicator("domain", host, family = "Graphite (Paragon)", source = "androdr_public_repo",
        fetchedAt = 1L)
    private val rule003 = SigmaRuleParser.parse(File(listOf(File("app/src/main/res/raw"), File("src/main/res/raw"))
        .first { it.isDirectory }, "sigma_androdr_003_domain_ioc.yml").readText())!!

    /** The runtime check in initRuleEngine is also a build-time gate. */
    @Test
    fun `provider map keys equal REGISTERED_EVIDENCE_TYPES`() {
        val keys = ScanOrchestrator.buildEvidenceProviders(emptyList()) { _, _ -> null }.keys
        assertEquals(ScanOrchestrator.REGISTERED_EVIDENCE_TYPES, keys)
    }

    @Test
    fun `live domain match returns the prefetched row`() = runTest {
        dao.upsertAll(listOf(row)); resolver.refreshCache()
        resolver.prefetchDomainIndicators(listOf(host))
        assertEquals("Graphite (Paragon)", ScanOrchestrator.iocRow(resolver, "domain_ioc_db", host)?.family)
    }

    /**
     * B2 carry-over: prefetched rows are never evicted, so one can outlive its
     * indicator. A cached row is never evidence that a domain is an IOC.
     */
    @Test
    fun `stale cached row without a live match gives no evidence and no finding`() = runTest {
        dao.upsertAll(listOf(row)); resolver.refreshCache()
        resolver.prefetchDomainIndicators(listOf(host))
        dao.deleteStaleEntries("androdr_public_repo", Long.MAX_VALUE); resolver.refreshCache()
        assertEquals("precondition: the stale row is still cached", setOf(host), resolver.domainCacheKeys())
        assertNull(resolver.isKnownBadDomainWithBundle(host))

        assertNull(ScanOrchestrator.iocRow(resolver, "domain_ioc_db", host))
        assertTrue(resolver.attributionMisses.get().isEmpty())
        val providers = ScanOrchestrator.buildEvidenceProviders(emptyList()) { db, v ->
            ScanOrchestrator.iocRow(resolver, db, v)
        }
        assertTrue(providers.getValue("ioc_match").provide(rule003, mapOf("domain" to host)).isEmpty())
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule003), listOf(mapOf("domain" to host)), "dns_monitor",
            mapOf("domain_ioc_db" to { v: Any -> resolver.isKnownBadDomainWithBundle(v.toString()) != null }),
            providers)
        assertTrue(findings.isEmpty())
    }

    @Test
    fun `live match without a prefetch is recorded as an attribution miss`() = runTest {
        dao.upsertAll(listOf(row)); resolver.refreshCache()
        assertNull(ScanOrchestrator.iocRow(resolver, "domain_ioc_db", host))
        assertEquals(setOf(host), resolver.attributionMisses.get())
        resolver.prefetchDomainIndicators(emptyList())
        assertTrue("prefetch clears misses", resolver.attributionMisses.get().isEmpty())
    }

    /**
     * Final review item 1, end to end: generic feeds loaded but the rules-repo ioc-data did
     * not. The HaGeZi row for the same domain used to shadow the bundled Graphite entry, so
     * the report printed "[OK] Graphite (Paragon): not detected" beside the DNS IOC hit.
     */
    @Test
    fun `a HaGeZi row does not shadow the bundled Graphite campaign in the report`() = runTest {
        dao.upsertAll(listOf(Indicator("domain", host, family = "HaGeZi TIF", source = "hagezi_tif", fetchedAt = 1L)))
        every { bundledDomains.lookup(host) } returns Indicator("domain", host, family = "Graphite (Paragon)",
            category = "NATION_STATE_SPYWARE", campaignKey = "graphite", source = "bundled", fetchedAt = 0L)
        resolver.refreshCache()
        resolver.prefetchDomainIndicators(listOf(host))
        val providers = ScanOrchestrator.buildEvidenceProviders(emptyList()) { db, v ->
            ScanOrchestrator.iocRow(resolver, db, v)
        }
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule003), listOf(mapOf("domain" to host)), "dns_monitor",
            mapOf("domain_ioc_db" to { v: Any -> resolver.isKnownBadDomainWithBundle(v.toString()) != null }),
            providers)
        val evidence = findings.single().evidence as Evidence.IocMatch
        assertEquals("graphite", evidence.campaign)

        val scan = ScanResult(id = 1L, timestamp = 1_711_900_800_000L, findings = findings,
            bugReportFindings = emptyList(), riskySideloadCount = 0, knownMalwareCount = 0)
        val registry = CampaignRegistry.parseBundled(listOf(File("src/main/res/raw/known_campaigns.json"),
            File("app/src/main/res/raw/known_campaigns.json")).first { it.isFile }.readText())
        val report = ReportFormatter.formatScanReport(scan, emptyList(), emptyList(), versionName = "test",
            campaigns = registry, ruleScopes = emptyMap(), ruleCategoryById = emptyMap())
        assertTrue(report, report.contains("Graphite (Paragon): DETECTED"))
        assertFalse(report, report.contains("Graphite (Paragon): not detected"))
    }

    @Test
    fun `a stored rules-repo row wins over the bundled entry because it is fresher`() = runTest {
        dao.upsertAll(listOf(Indicator("domain", host, family = "Graphite (fresh)", campaignKey = "graphite",
            source = "androdr_public_repo", fetchedAt = 1L)))
        every { bundledDomains.lookup(host) } returns Indicator("domain", host, family = "Graphite (Paragon)",
            campaignKey = "graphite", source = "bundled", fetchedAt = 0L)
        resolver.refreshCache()
        resolver.prefetchDomainIndicators(listOf(host))
        val row = ScanOrchestrator.iocRow(resolver, "domain_ioc_db", host)!!
        assertEquals("Graphite (fresh)", row.family)
        assertEquals("androdr_public_repo", row.source)
    }
}

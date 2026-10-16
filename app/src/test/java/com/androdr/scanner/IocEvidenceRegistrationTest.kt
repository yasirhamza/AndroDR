package com.androdr.scanner

import com.androdr.data.model.Indicator
import com.androdr.ioc.ApkHashIocDatabase
import com.androdr.ioc.BundledDomainDatabase
import com.androdr.ioc.CertHashIocDatabase
import com.androdr.ioc.FakeIndicatorDao
import com.androdr.ioc.IndicatorResolver
import com.androdr.ioc.IocDatabase
import com.androdr.sigma.SigmaRuleEvaluator
import com.androdr.sigma.SigmaRuleParser
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
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
        assertNotNull("precondition: the stale row is still cached", resolver.cachedDomainIndicator(host))
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
}

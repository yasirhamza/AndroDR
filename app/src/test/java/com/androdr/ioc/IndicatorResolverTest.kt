package com.androdr.ioc

import com.androdr.data.db.IndicatorDao
import com.androdr.data.model.Indicator
import io.mockk.clearMocks
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class IndicatorResolverTest {

    private lateinit var dao: IndicatorDao
    private lateinit var bundledPackages: IocDatabase
    private lateinit var bundledCerts: CertHashIocDatabase
    private lateinit var bundledApkHashes: ApkHashIocDatabase
    private lateinit var bundledDomains: BundledDomainDatabase
    private lateinit var resolver: IndicatorResolver

    @Before
    fun setup() {
        dao = mockk()
        bundledPackages = mockk()
        bundledCerts = mockk()
        bundledApkHashes = mockk()
        bundledDomains = mockk()
        every { bundledDomains.lookup(any()) } returns null
        every { bundledPackages.isKnownBadPackage(any()) } returns null
        every { bundledCerts.isKnownBadCert(any()) } returns null
        every { bundledApkHashes.isKnownBadApkHash(any()) } returns null
        // Default: all queries return empty/null
        coEvery { dao.getAllByType(any()) } returns emptyList()
        coEvery { dao.getValuesByType(any()) } returns emptyList()
        coEvery { dao.lookup(any(), any()) } returns null
        resolver = IndicatorResolver(dao, bundledPackages, bundledCerts, bundledApkHashes, bundledDomains)
    }

    @Test
    fun `returns null when cache is empty and bundled has no match`() {
        assertNull(resolver.isKnownBadCert("unknown"))
        assertNull(resolver.isKnownBadPackage("unknown"))
        assertNull(resolver.isKnownBadDomain("unknown.com"))
        assertNull(resolver.isKnownBadApkHash("unknown"))
    }

    @Test
    fun `cert hash lookup works after cache refresh`() = runTest {
        coEvery { dao.getAllByType("cert_hash") } returns listOf(
            Indicator(type = "cert_hash", value = "abc123", family = "TestMalware",
                severity = "CRITICAL", source = "test",
                fetchedAt = 1000L)
        )
        resolver.refreshCache()
        val result = resolver.isKnownBadCert("abc123")
        assertNotNull(result)
        assertEquals("TestMalware", result!!.family)
    }

    @Test
    fun `domain lookup with subdomain matching via bloom index`() = runTest {
        coEvery { dao.getValuesByType("domain") } returns listOf("evil.com")
        resolver.refreshCache()
        // sub.evil.com → label-strip walks to evil.com → bloom hit → exact hit
        assertNotNull(resolver.isKnownBadDomain("sub.evil.com"))
        assertNotNull(resolver.isKnownBadDomain("evil.com"))
        assertNull(resolver.isKnownBadDomain("safe.com"))
    }

    @Test
    fun `domain lookup returns null before first refresh`() {
        // Empty index returned by DomainBloomIndex.empty() — every query misses.
        assertNull(resolver.isKnownBadDomain("evil.com"))
    }

    @Test
    fun `domain lookup handles trailing dot and case`() = runTest {
        coEvery { dao.getValuesByType("domain") } returns listOf("Evil.Com")
        resolver.refreshCache()
        assertNotNull(resolver.isKnownBadDomain("evil.com."))
        assertNotNull(resolver.isKnownBadDomain("EVIL.COM"))
    }

    @Test
    fun `package lookup falls back to bundled`() {
        val bundledInfo = BadPackageInfo("com.evil", "Evil", "MALWARE", "HIGH", "desc")
        every { bundledPackages.isKnownBadPackage("com.evil") } returns bundledInfo
        val result = resolver.isKnownBadPackage("com.evil")
        assertNotNull(result)
        assertEquals("Evil", result!!.name)
    }

    @Test
    fun `cert hash falls back to bundled`() {
        val bundledCert = CertHashInfo("bundled123", "BundledMalware", "STALKERWARE", "HIGH", "desc")
        every { bundledCerts.isKnownBadCert("bundled123") } returns bundledCert
        val result = resolver.isKnownBadCert("bundled123")
        assertNotNull(result)
        assertEquals("BundledMalware", result!!.family)
    }

    @Test
    fun `apk hash lookup works`() = runTest {
        coEvery { dao.getAllByType("apk_hash") } returns listOf(
            Indicator(type = "apk_hash", value = "deadbeef", family = "Trojan", severity = "CRITICAL", source = "test",
                fetchedAt = 1000L)
        )
        resolver.refreshCache()
        assertNotNull(resolver.isKnownBadApkHash("deadbeef"))
        assertNull(resolver.isKnownBadApkHash("cafebabe"))
    }

    @Test
    fun `normalizes cert hash to lowercase`() = runTest {
        coEvery { dao.getAllByType("cert_hash") } returns listOf(
            Indicator(type = "cert_hash", value = "abc123def456", family = "TestMalware",
                severity = "CRITICAL", source = "test",
                fetchedAt = 1000L)
        )
        resolver.refreshCache()
        assertNotNull(resolver.isKnownBadCert("ABC123DEF456"))
    }

    @Test
    fun `prefetched domain hit returns the stored row`() = runTest {
        coEvery { dao.getValuesByType("domain") } returns listOf("forti.external-muki.com")
        coEvery { dao.lookup("domain", "forti.external-muki.com") } returns Indicator("domain",
            "forti.external-muki.com", family = "Graphite (Paragon)", category = "NATION_STATE_SPYWARE",
            campaignKey = "graphite", source = "androdr_public_repo", fetchedAt = 1L)
        resolver.refreshCache()
        resolver.prefetchDomainIndicators(listOf("forti.external-muki.com", "example.org"))
        assertEquals("Graphite (Paragon)", resolver.cachedDomainIndicator("forti.external-muki.com")!!.family)
        assertNull(resolver.cachedDomainIndicator("example.org"))
    }

    @Test
    fun `subdomain hit resolves to the listed parent row`() = runTest {
        coEvery { dao.getValuesByType("domain") } returns listOf("evil.com")
        coEvery { dao.lookup("domain", "evil.com") } returns Indicator("domain", "evil.com",
            family = "Predator Spyware Indicators of Compromise", source = "mvt", fetchedAt = 1L)
        resolver.refreshCache()
        resolver.prefetchDomainIndicators(listOf("c2.evil.com"))
        assertEquals("evil.com", resolver.cachedDomainIndicator("c2.evil.com")!!.value)
    }

    @Test
    fun `cold start falls back to the bundled domain entry`() = runTest {
        every { bundledDomains.lookup("forti.external-muki.com") } returns Indicator("domain",
            "forti.external-muki.com", family = "Graphite (Paragon)", source = "bundled", fetchedAt = 0L)
        resolver.prefetchDomainIndicators(listOf("forti.external-muki.com"))
        assertEquals("Graphite (Paragon)", resolver.cachedDomainIndicator("forti.external-muki.com")!!.family)
    }

    @Test
    fun `cold start matches a bundled domain without Room`() = runTest {
        every { bundledDomains.lookup("forti.external-muki.com") } returns Indicator("domain",
            "forti.external-muki.com", family = "Graphite (Paragon)", source = "bundled", fetchedAt = 0L)
        val hit = resolver.isKnownBadDomainWithBundle("sub.forti.external-muki.com")
        assertEquals("forti.external-muki.com", hit!!.value)
        coVerify(exactly = 0) { dao.lookup(any(), any()) }
    }

    @Test
    fun `concurrent prefetches merge rather than replace`() = runTest {
        coEvery { dao.getValuesByType("domain") } returns listOf("a.com", "b.com")
        coEvery { dao.lookup("domain", "a.com") } returns
            Indicator("domain", "a.com", family = "A", source = "s", fetchedAt = 1L)
        coEvery { dao.lookup("domain", "b.com") } returns
            Indicator("domain", "b.com", family = "B", source = "s", fetchedAt = 1L)
        resolver.refreshCache()
        resolver.prefetchDomainIndicators(listOf("a.com"))
        resolver.prefetchDomainIndicators(listOf("b.com"))
        assertEquals("A", resolver.cachedDomainIndicator("a.com")!!.family)
        assertEquals("B", resolver.cachedDomainIndicator("b.com")!!.family)
    }

    @Test
    fun `isKnownBadDomain never touches the DAO`() = runTest {
        coEvery { dao.getValuesByType("domain") } returns listOf("evil.com")
        resolver.refreshCache()
        clearMocks(dao, answers = false, recordedCalls = true)
        resolver.isKnownBadDomain("c2.evil.com")
        coVerify(exactly = 0) { dao.lookup(any(), any()) }
        coVerify(exactly = 0) { dao.getAllByType(any()) }
    }

    @Test
    fun `package indicator keeps family and source`() = runTest {
        coEvery { dao.getAllByType("package") } returns listOf(Indicator("package", "com.serv.services",
            family = "NoviSpy", category = "NATION_STATE_SPYWARE", source = "androdr_public_repo", fetchedAt = 1L))
        resolver.refreshCache()
        val got = resolver.packageIndicator("com.serv.services")!!
        assertEquals("NoviSpy", got.family)
        assertEquals("androdr_public_repo", got.source)
    }

    @Test
    fun `bundled hits never carry a raw out-of-enum category`() {
        every { bundledPackages.isKnownBadPackage("com.bad.bank") } returns
            BadPackageInfo("com.bad.bank", "Bank", "BANKER", "HIGH", "d")
        every { bundledDomains.lookup("bad.example") } returns Indicator("domain", "bad.example",
            family = "F", category = "RAT", source = "bundled", fetchedAt = 0L)
        assertEquals("", resolver.packageIndicator("com.bad.bank")!!.category)
        assertEquals("", resolver.isKnownBadDomainWithBundle("bad.example")!!.category)
    }


    @Test
    fun `bundled cert and apk hash hits are sanitised`() {
        every { bundledApkHashes.isKnownBadApkHash("aa") } returns
            ApkHashInfo("aa", "Fam", "BANKER", "HIGH", "d")
        every { bundledCerts.isKnownBadCert("bb") } returns
            CertHashInfo("bb", "Fam", "RAT", "HIGH", "d")
        assertEquals("", resolver.isKnownBadApkHash("aa")!!.category)
        assertEquals("", resolver.isKnownBadCert("bb")!!.category)
    }

    @Test
    fun `refreshCache leaves prefetched domain rows intact`() = runTest {
        coEvery { dao.getValuesByType("domain") } returns listOf("a.com")
        coEvery { dao.lookup("domain", "a.com") } returns
            Indicator("domain", "a.com", family = "A", source = "s", fetchedAt = 1L)
        resolver.refreshCache()
        resolver.prefetchDomainIndicators(listOf("a.com"))
        resolver.refreshCache()
        assertEquals("A", resolver.cachedDomainIndicator("a.com")!!.family)
    }

    // ── B5 fix round 1: the cache is keyed by the MATCHED indicator, not the queried
    // hostname, so an imported log of distinct subdomains cannot grow it unbounded.

    @Test
    fun `ten thousand subdomains of one IOC cost one cache entry and one DAO lookup`() = runTest {
        coEvery { dao.getValuesByType("domain") } returns listOf("evil.com")
        coEvery { dao.lookup("domain", "evil.com") } returns
            Indicator("domain", "evil.com", family = "F", source = "s", fetchedAt = 1L)
        resolver.refreshCache()
        resolver.prefetchDomainIndicators((0 until 10_000).map { "s$it.evil.com" })
        assertEquals(setOf("evil.com"), resolver.domainCacheKeys())
        coVerify(atMost = 1) { dao.lookup(any(), any()) }
        assertEquals("F", resolver.cachedDomainIndicator("s9999.evil.com")!!.family)
    }

    @Test
    fun `a matched value that no longer resolves is removed from the cache`() = runTest {
        coEvery { dao.getValuesByType("domain") } returns listOf("a.com")
        coEvery { dao.lookup("domain", "a.com") } returns
            Indicator("domain", "a.com", family = "A", source = "s", fetchedAt = 1L)
        resolver.refreshCache()
        resolver.prefetchDomainIndicators(listOf("x.a.com"))
        assertEquals(setOf("a.com"), resolver.domainCacheKeys())
        // Row deleted (feed eviction) while the bloom index still says a.com.
        coEvery { dao.lookup("domain", "a.com") } returns null
        resolver.prefetchDomainIndicators(listOf("y.a.com"))
        assertTrue(resolver.domainCacheKeys().isEmpty())
        assertNull(resolver.cachedDomainIndicator("y.a.com"))
    }

    @Test
    fun `a cached row whose key no longer matches live is not returned`() = runTest {
        coEvery { dao.getValuesByType("domain") } returns listOf("a.com")
        coEvery { dao.lookup("domain", "a.com") } returns
            Indicator("domain", "a.com", family = "A", source = "s", fetchedAt = 1L)
        resolver.refreshCache()
        resolver.prefetchDomainIndicators(listOf("a.com"))
        coEvery { dao.getValuesByType("domain") } returns emptyList()
        resolver.refreshCache()
        assertEquals("refreshCache keeps the row (B2)", setOf("a.com"), resolver.domainCacheKeys())
        assertNull(resolver.cachedDomainIndicator("a.com"))
    }

    @Test
    fun `the most specific cached live label wins`() = runTest {
        coEvery { dao.getValuesByType("domain") } returns listOf("a.com", "b.a.com")
        coEvery { dao.lookup("domain", "a.com") } returns
            Indicator("domain", "a.com", family = "Parent", source = "s", fetchedAt = 1L)
        coEvery { dao.lookup("domain", "b.a.com") } returns
            Indicator("domain", "b.a.com", family = "Child", source = "s", fetchedAt = 1L)
        resolver.refreshCache()
        resolver.prefetchDomainIndicators(listOf("x.b.a.com", "a.com"))
        assertEquals(setOf("a.com", "b.a.com"), resolver.domainCacheKeys())
        assertEquals("Child", resolver.cachedDomainIndicator("x.b.a.com")!!.family)
    }

    // ── Final review item 1: the bundle IS rules-repo content (top SourceRank), so a
    // lower-ranked stored row must not shadow it when the rules-repo ioc-data did not load.

    @Test
    fun `bundled Graphite domain outranks a HaGeZi row for the same value`() = runTest {
        val host = "forti.external-muki.com"
        coEvery { dao.getValuesByType("domain") } returns listOf(host)
        coEvery { dao.lookup("domain", host) } returns Indicator("domain", host, family = "HaGeZi TIF",
            source = "hagezi_tif", fetchedAt = 1L)
        every { bundledDomains.lookup(host) } returns Indicator("domain", host, family = "Graphite (Paragon)",
            category = "NATION_STATE_SPYWARE", campaignKey = "graphite", source = "bundled", fetchedAt = 0L)
        resolver.refreshCache()
        resolver.prefetchDomainIndicators(listOf(host))
        assertEquals("graphite", resolver.cachedDomainIndicator(host)!!.campaignKey)
        assertEquals("graphite", resolver.resolveDomainRow(host)!!.campaignKey)
    }

    @Test
    fun `a stored rules-repo domain row wins over the bundled entry`() = runTest {
        val host = "forti.external-muki.com"
        coEvery { dao.getValuesByType("domain") } returns listOf(host)
        coEvery { dao.lookup("domain", host) } returns Indicator("domain", host, family = "Graphite (fresh)",
            campaignKey = "graphite", source = "androdr_public_repo", fetchedAt = 1L)
        every { bundledDomains.lookup(host) } returns Indicator("domain", host, family = "Graphite (Paragon)",
            campaignKey = "graphite", source = "bundled", fetchedAt = 0L)
        resolver.refreshCache()
        resolver.prefetchDomainIndicators(listOf(host))
        assertEquals("Graphite (fresh)", resolver.cachedDomainIndicator(host)!!.family)
    }

    @Test
    fun `bundled package cert and apk hash entries outrank lower-ranked stored rows`() = runTest {
        coEvery { dao.getAllByType("package") } returns listOf(Indicator("package", "com.mm.enabler",
            family = "Generic", source = "stalkerware_indicators", fetchedAt = 1L))
        coEvery { dao.getAllByType("cert_hash") } returns listOf(Indicator("cert_hash", "cc",
            family = "Generic", source = "malwarebazaar_certs", fetchedAt = 1L))
        coEvery { dao.getAllByType("apk_hash") } returns listOf(Indicator("apk_hash", "aa",
            family = "Generic", source = "mvt_indicators", fetchedAt = 1L))
        every { bundledPackages.isKnownBadPackage("com.mm.enabler") } returns BadPackageInfo("com.mm.enabler",
            "Midnight Mimosa", "NATION_STATE_SPYWARE", "CRITICAL", "d", campaign = "midnight-mimosa")
        every { bundledCerts.isKnownBadCert("cc") } returns
            CertHashInfo("cc", "Midnight Mimosa", "NATION_STATE_SPYWARE", "HIGH", "d", campaign = "midnight-mimosa")
        every { bundledApkHashes.isKnownBadApkHash("aa") } returns
            ApkHashInfo("aa", "Midnight Mimosa", "NATION_STATE_SPYWARE", "HIGH", "d", campaign = "midnight-mimosa")
        resolver.refreshCache()
        assertEquals("midnight-mimosa", resolver.packageIndicator("com.mm.enabler")!!.campaignKey)
        assertEquals("Midnight Mimosa", resolver.isKnownBadPackage("com.mm.enabler")!!.name)
        assertEquals("midnight-mimosa", resolver.isKnownBadCert("cc")!!.campaignKey)
        assertEquals("midnight-mimosa", resolver.isKnownBadApkHash("aa")!!.campaignKey)
    }

    @Test
    fun `stored rules-repo package cert and apk hash rows win over the bundle`() = runTest {
        coEvery { dao.getAllByType("package") } returns listOf(Indicator("package", "com.mm.enabler",
            family = "Fresh", source = "androdr_public_repo", fetchedAt = 1L))
        coEvery { dao.getAllByType("cert_hash") } returns listOf(Indicator("cert_hash", "cc",
            family = "Fresh", source = "androdr_public_repo", fetchedAt = 1L))
        coEvery { dao.getAllByType("apk_hash") } returns listOf(Indicator("apk_hash", "aa",
            family = "Fresh", source = "androdr_public_repo", fetchedAt = 1L))
        every { bundledPackages.isKnownBadPackage("com.mm.enabler") } returns
            BadPackageInfo("com.mm.enabler", "Old", "MALWARE", "HIGH", "d")
        every { bundledCerts.isKnownBadCert("cc") } returns CertHashInfo("cc", "Old", "MALWARE", "HIGH", "d")
        every { bundledApkHashes.isKnownBadApkHash("aa") } returns ApkHashInfo("aa", "Old", "MALWARE", "HIGH", "d")
        resolver.refreshCache()
        assertEquals("Fresh", resolver.packageIndicator("com.mm.enabler")!!.family)
        assertEquals("Fresh", resolver.isKnownBadPackage("com.mm.enabler")!!.name)
        assertEquals("Fresh", resolver.isKnownBadCert("cc")!!.family)
        assertEquals("Fresh", resolver.isKnownBadApkHash("aa")!!.family)
    }

    @Test
    fun `feedCoverage asks for rules-repo rows by source and MVT rows by prefix`() = runTest {
        coEvery { dao.count() } returns 7
        coEvery { dao.hasSource("androdr_public_repo") } returns false
        coEvery { dao.hasSourcePrefix("mvt_") } returns true
        assertEquals(FeedCoverage(7, rulesRepoLoaded = false, mvtLoaded = true), resolver.feedCoverage())
    }

    @Test
    fun `feedCoverage over the fake DAO sees rules-repo and per-collection MVT sources`() = runTest {
        val fake = FakeIndicatorDao()
        val r = IndicatorResolver(fake, bundledPackages, bundledCerts, bundledApkHashes, bundledDomains)
        fake.upsertAll(listOf(Indicator("domain", "a.com", source = "hagezi_tif", fetchedAt = 1L)))
        assertEquals(FeedCoverage(1, rulesRepoLoaded = false, mvtLoaded = false), r.feedCoverage())
        fake.upsertAll(listOf(Indicator("domain", "b.com", source = "mvt_predator", fetchedAt = 1L),
            Indicator("domain", "c.com", source = "androdr_public_repo", fetchedAt = 1L)))
        assertEquals(FeedCoverage(3, rulesRepoLoaded = true, mvtLoaded = true), r.feedCoverage())
    }
}

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
}

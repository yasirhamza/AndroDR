package com.androdr.ioc

import com.androdr.data.db.IndicatorDao
import com.androdr.data.model.Indicator
import io.mockk.coEvery
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
    private lateinit var resolver: IndicatorResolver

    @Before
    fun setup() {
        dao = mockk()
        bundledPackages = mockk()
        bundledCerts = mockk()
        every { bundledPackages.isKnownBadPackage(any()) } returns null
        every { bundledCerts.isKnownBadCert(any()) } returns null
        resolver = IndicatorResolver(dao, bundledPackages, bundledCerts)
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
        coEvery { dao.getAll() } returns listOf(
            Indicator("cert_hash", "abc123", "TestMalware", "", "CRITICAL", "", "test", 1000L)
        )
        resolver.refreshCache()
        val result = resolver.isKnownBadCert("abc123")
        assertNotNull(result)
        assertEquals("TestMalware", result!!.name)
    }

    @Test
    fun `domain lookup with subdomain matching`() = runTest {
        coEvery { dao.getAll() } returns listOf(
            Indicator("domain", "evil.com", "", "Pegasus", "CRITICAL", "", "test", 1000L)
        )
        resolver.refreshCache()
        assertNotNull(resolver.isKnownBadDomain("sub.evil.com"))
        assertNotNull(resolver.isKnownBadDomain("evil.com"))
        assertNull(resolver.isKnownBadDomain("safe.com"))
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
        assertEquals("BundledMalware", result!!.name)
    }

    @Test
    fun `apk hash lookup works`() = runTest {
        coEvery { dao.getAll() } returns listOf(
            Indicator("apk_hash", "deadbeef", "Trojan", "", "CRITICAL", "", "test", 1000L)
        )
        resolver.refreshCache()
        assertNotNull(resolver.isKnownBadApkHash("deadbeef"))
        assertNull(resolver.isKnownBadApkHash("cafebabe"))
    }

    @Test
    fun `normalizes cert hash to lowercase`() = runTest {
        coEvery { dao.getAll() } returns listOf(
            Indicator("cert_hash", "abc123def456", "TestMalware", "", "CRITICAL", "", "test", 1000L)
        )
        resolver.refreshCache()
        assertNotNull(resolver.isKnownBadCert("ABC123DEF456"))
    }
}

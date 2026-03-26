package com.androdr.ioc

import com.androdr.data.db.CertHashIocEntryDao
import com.androdr.data.model.CertHashIocEntry
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

class CertHashIocResolverTest {

    private lateinit var dao: CertHashIocEntryDao
    private lateinit var bundled: CertHashIocDatabase
    private lateinit var resolver: CertHashIocResolver

    private val testEntry = CertHashIocEntry(
        certHash = "abc123def456",
        familyName = "TestMalware",
        category = "RAT",
        severity = "CRITICAL",
        description = "Test malware cert",
        source = "test",
        fetchedAt = 1000L
    )

    @Before
    fun setup() {
        dao = mockk()
        bundled = mockk()
        resolver = CertHashIocResolver(dao, bundled)
    }

    @Test
    fun `returns null when cache is empty and bundled has no match`() {
        every { bundled.isKnownBadCert("unknown") } returns null
        assertNull(resolver.isKnownBadCert("unknown"))
    }

    @Test
    fun `returns entry from remote cache after refresh`() = runTest {
        coEvery { dao.getAll() } returns listOf(testEntry)
        resolver.refreshCache()
        val result = resolver.isKnownBadCert("abc123def456")
        assertNotNull(result)
        assertEquals("TestMalware", result!!.familyName)
    }

    @Test
    fun `falls back to bundled when remote cache has no match`() = runTest {
        coEvery { dao.getAll() } returns emptyList()
        resolver.refreshCache()
        val bundledInfo = CertHashInfo(
            certHash = "bundled123",
            familyName = "BundledMalware",
            category = "STALKERWARE",
            severity = "HIGH",
            description = "Bundled cert"
        )
        every { bundled.isKnownBadCert("bundled123") } returns bundledInfo
        val result = resolver.isKnownBadCert("bundled123")
        assertNotNull(result)
        assertEquals("BundledMalware", result!!.familyName)
    }

    @Test
    fun `normalizes cert hash to lowercase`() = runTest {
        coEvery { dao.getAll() } returns listOf(testEntry)
        resolver.refreshCache()
        val result = resolver.isKnownBadCert("ABC123DEF456")
        assertNotNull(result)
        assertEquals("TestMalware", result!!.familyName)
    }

    @Test
    fun `remoteEntryCount delegates to dao`() = runTest {
        coEvery { dao.count() } returns 42
        assertEquals(42, resolver.remoteEntryCount())
    }
}

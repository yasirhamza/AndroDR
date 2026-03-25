package com.androdr.ioc

import com.androdr.data.db.DomainIocEntryDao
import com.androdr.data.model.DomainIocEntry
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

class DomainIocResolverTest {

    private val dao: DomainIocEntryDao = mockk()
    private lateinit var resolver: DomainIocResolver

    private val pegasusEntry = DomainIocEntry(
        domain = "evil.com",
        campaignName = "NSO Group Pegasus",
        severity = "CRITICAL",
        source = "mvt_pegasus",
        fetchedAt = 1000L
    )

    @Before
    fun setUp() {
        resolver = DomainIocResolver(dao)
    }

    @Test
    fun `isKnownBadDomain returns null before cache is loaded`() {
        assertNull(resolver.isKnownBadDomain("evil.com"))
    }

    @Test
    fun `isKnownBadDomain returns entry for exact apex match after refresh`() = runTest {
        coEvery { dao.getAll() } returns listOf(pegasusEntry)
        resolver.refreshCache()
        val result = resolver.isKnownBadDomain("evil.com")
        assertEquals("evil.com", result?.domain)
        assertEquals("NSO Group Pegasus", result?.campaignName)
    }

    @Test
    fun `isKnownBadDomain returns entry for subdomain via label-stripping`() = runTest {
        coEvery { dao.getAll() } returns listOf(pegasusEntry)
        resolver.refreshCache()
        assertEquals("evil.com", resolver.isKnownBadDomain("c2.evil.com")?.domain)
        assertEquals("evil.com", resolver.isKnownBadDomain("deep.sub.evil.com")?.domain)
    }

    @Test
    fun `isKnownBadDomain returns null for unrelated domain`() = runTest {
        coEvery { dao.getAll() } returns listOf(pegasusEntry)
        resolver.refreshCache()
        assertNull(resolver.isKnownBadDomain("safe.com"))
        assertNull(resolver.isKnownBadDomain("notevil.com"))
    }

    @Test
    fun `isKnownBadDomain handles trailing dot in query`() = runTest {
        coEvery { dao.getAll() } returns listOf(pegasusEntry)
        resolver.refreshCache()
        assertEquals("evil.com", resolver.isKnownBadDomain("evil.com.")?.domain)
    }

    @Test
    fun `isKnownBadDomain returns null for empty cache after refresh with no entries`() = runTest {
        coEvery { dao.getAll() } returns emptyList()
        resolver.refreshCache()
        assertNull(resolver.isKnownBadDomain("evil.com"))
    }
}

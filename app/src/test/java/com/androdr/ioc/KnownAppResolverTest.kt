package com.androdr.ioc

import com.androdr.data.db.KnownAppDbEntry
import com.androdr.data.db.KnownAppEntryDao
import com.androdr.data.model.KnownAppCategory
import com.androdr.data.model.KnownAppEntry
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

class KnownAppResolverTest {

    private val mockDao = mockk<KnownAppEntryDao>()
    private val mockBundled = mockk<KnownAppDatabase>()
    private lateinit var resolver: KnownAppResolver

    private fun oemEntry(pkg: String) = KnownAppEntry(
        packageName = pkg, displayName = pkg, category = KnownAppCategory.OEM,
        sourceId = "bundled", fetchedAt = 0
    )

    @Before
    fun setUp() {
        resolver = KnownAppResolver(mockDao, mockBundled)
    }

    @Test
    fun `null cache falls back to bundled entry`() {
        every { mockBundled.lookup("com.samsung.settings") } returns oemEntry("com.samsung.settings")

        val result = resolver.lookup("com.samsung.settings")

        assertEquals(KnownAppCategory.OEM, result?.category)
    }

    @Test
    fun `null cache returns null when bundled also misses`() {
        every { mockBundled.lookup("com.unknown.app") } returns null

        val result = resolver.lookup("com.unknown.app")

        assertNull(result)
    }

    @Test
    fun `populated cache returns cached entry`() = runTest {
        val dbEntry = KnownAppDbEntry(
            packageName = "com.whatsapp", displayName = "WhatsApp",
            category = "USER_APP", sourceId = "plexus", fetchedAt = 1000L
        )
        coEvery { mockDao.getAll() } returns listOf(dbEntry)

        resolver.refreshCache()
        val result = resolver.lookup("com.whatsapp")

        assertEquals(KnownAppCategory.USER_APP, result?.category)
        assertEquals("WhatsApp", result?.displayName)
    }

    @Test
    fun `populated cache miss falls back to bundled`() = runTest {
        coEvery { mockDao.getAll() } returns emptyList()
        every { mockBundled.lookup("com.samsung.settings") } returns oemEntry("com.samsung.settings")

        resolver.refreshCache()
        val result = resolver.lookup("com.samsung.settings")

        assertEquals(KnownAppCategory.OEM, result?.category)
    }

    @Test
    fun `neither source has entry returns null`() = runTest {
        coEvery { mockDao.getAll() } returns emptyList()
        every { mockBundled.lookup("com.mystery.app") } returns null

        resolver.refreshCache()
        val result = resolver.lookup("com.mystery.app")

        assertNull(result)
    }
}

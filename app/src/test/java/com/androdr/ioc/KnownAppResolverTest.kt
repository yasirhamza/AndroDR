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
        every { mockBundled.lookup("com.whatsapp") } returns null

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

    @Test
    fun `RRO suffix is stripped and base package resolves`() {
        val base = "com.shannon.imsservice"
        val rro = "$base.auto_generated_rro_product___"
        every { mockBundled.lookup(rro) } returns null
        every { mockBundled.lookup(base) } returns oemEntry(base)

        val result = resolver.lookup(rro)

        assertEquals(base, result?.packageName)
    }

    @Test
    fun `non-RRO package passes through unmodified`() {
        every { mockBundled.lookup("com.example.app") } returns null

        val result = resolver.lookup("com.example.app")

        assertNull(result)
    }

    @Test
    fun `RRO suffix stripped but base package not in DB returns null`() {
        val rro = "com.unknown.app.auto_generated_rro_vendor___"
        every { mockBundled.lookup(rro) } returns null
        every { mockBundled.lookup("com.unknown.app") } returns null

        val result = resolver.lookup(rro)

        assertNull(result)
    }

    @Test
    fun `package that is only an RRO suffix pattern returns null`() {
        val suffix = ".auto_generated_rro_product___"
        every { mockBundled.lookup(suffix) } returns null

        val result = resolver.lookup(suffix)

        assertNull(result)
    }

    @Test
    fun `RRO suffix with hyphen is stripped and resolves`() {
        val base = "com.qualcomm.qtil"
        val rro = "$base.auto_generated_rro_vendor-overlay___"
        every { mockBundled.lookup(rro) } returns null
        every { mockBundled.lookup(base) } returns oemEntry(base)

        val result = resolver.lookup(rro)

        assertEquals(base, result?.packageName)
    }

    @Test
    fun `cache USER_APP does not override bundled OEM for same package`() = runTest {
        // Regression: Plexus feed writes every entry as USER_APP and can race UAD writes
        // in the Room DB. When bundled JSON has an authoritative OEM/AOSP/GOOGLE
        // classification for the same package, that must win — otherwise Netflix/Facebook
        // preloads on Samsung devices get mis-classified as USER_APP and trip
        // rule-014 App Impersonation (HIGH).
        val cachedUserApp = KnownAppDbEntry(
            packageName = "com.facebook.katana", displayName = "Facebook",
            category = "USER_APP", sourceId = "plexus", fetchedAt = 1000L
        )
        coEvery { mockDao.getAll() } returns listOf(cachedUserApp)
        every { mockBundled.lookup("com.facebook.katana") } returns KnownAppEntry(
            packageName = "com.facebook.katana", displayName = "Facebook",
            category = KnownAppCategory.OEM, sourceId = "bundled", fetchedAt = 0L
        )

        resolver.refreshCache()
        val result = resolver.lookup("com.facebook.katana")

        assertEquals(KnownAppCategory.OEM, result?.category)
    }

    @Test
    fun `cache OEM is preferred over bundled USER_APP`() = runTest {
        // Symmetric case: fresh UAD fetch (cache) has OEM, older bundled has USER_APP.
        // Cache's authoritative classification wins.
        val cachedOem = KnownAppDbEntry(
            packageName = "com.example.preload", displayName = "Preload",
            category = "OEM", sourceId = "uad_ng", fetchedAt = 2000L
        )
        coEvery { mockDao.getAll() } returns listOf(cachedOem)
        every { mockBundled.lookup("com.example.preload") } returns KnownAppEntry(
            packageName = "com.example.preload", displayName = "Preload",
            category = KnownAppCategory.USER_APP, sourceId = "bundled", fetchedAt = 0L
        )

        resolver.refreshCache()
        val result = resolver.lookup("com.example.preload")

        assertEquals(KnownAppCategory.OEM, result?.category)
    }

    @Test
    fun `cache USER_APP is returned when bundled has no entry`() = runTest {
        val cachedUserApp = KnownAppDbEntry(
            packageName = "com.whatsapp", displayName = "WhatsApp",
            category = "USER_APP", sourceId = "plexus", fetchedAt = 1000L
        )
        coEvery { mockDao.getAll() } returns listOf(cachedUserApp)
        every { mockBundled.lookup("com.whatsapp") } returns null

        resolver.refreshCache()
        val result = resolver.lookup("com.whatsapp")

        assertEquals(KnownAppCategory.USER_APP, result?.category)
    }

    @Test
    fun `RRO suffix stripped and base resolves from cache`() = runTest {
        val dbEntry = KnownAppDbEntry(
            packageName = "com.samsung.settings", displayName = "Settings",
            category = "OEM", sourceId = "bundled", fetchedAt = 0L
        )
        coEvery { mockDao.getAll() } returns listOf(dbEntry)
        every { mockBundled.lookup(any()) } returns null

        resolver.refreshCache()
        val rro = "com.samsung.settings.auto_generated_rro_product___"
        val result = resolver.lookup(rro)

        assertEquals("com.samsung.settings", result?.packageName)
    }
}

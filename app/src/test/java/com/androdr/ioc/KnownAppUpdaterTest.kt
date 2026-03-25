package com.androdr.ioc

import com.androdr.data.db.KnownAppDbEntry
import com.androdr.data.db.KnownAppEntryDao
import com.androdr.data.model.KnownAppCategory
import com.androdr.data.model.KnownAppEntry
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

class KnownAppUpdaterTest {

    private val mockDao      = mockk<KnownAppEntryDao>(relaxed = true)
    private val mockResolver = mockk<KnownAppResolver>(relaxed = true)

    private fun makeEntry(pkg: String) = KnownAppEntry(
        packageName = pkg, displayName = pkg, category = KnownAppCategory.OEM,
        sourceId = "uad_ng", fetchedAt = 1000L
    )

    @Test
    fun `update returns total count from all feeds`() = runTest {
        val feed1 = mockk<KnownAppFeed>()
        val feed2 = mockk<KnownAppFeed>()
        coEvery { feed1.fetch() } returns listOf(makeEntry("com.a"), makeEntry("com.b"))
        coEvery { feed2.fetch() } returns listOf(makeEntry("com.c"))
        coEvery { feed1.sourceId } returns "uad_ng"
        coEvery { feed2.sourceId } returns "plexus"
        coEvery { mockDao.count() } returns 3

        val updater = KnownAppUpdater(mockDao, mockResolver, listOf(feed1, feed2))
        val total = updater.update()

        assertEquals(3, total)
    }

    @Test
    fun `upsertAll is called with mapped DB entries`() = runTest {
        val feed = mockk<KnownAppFeed>()
        coEvery { feed.fetch() } returns listOf(makeEntry("com.android.settings"))
        coEvery { feed.sourceId } returns "uad_ng"
        coEvery { mockDao.count() } returns 1

        val updater = KnownAppUpdater(mockDao, mockResolver, listOf(feed))
        updater.update()

        coVerify { mockDao.upsertAll(match { it.size == 1 && it[0].packageName == "com.android.settings" }) }
    }

    @Test
    fun `deleteStaleEntries is called with correct sourceId and timestamp`() = runTest {
        val feed = mockk<KnownAppFeed>()
        val entry = makeEntry("com.android.settings").copy(fetchedAt = 5000L)
        coEvery { feed.fetch() } returns listOf(entry)
        coEvery { feed.sourceId } returns "uad_ng"
        coEvery { mockDao.count() } returns 1

        val updater = KnownAppUpdater(mockDao, mockResolver, listOf(feed))
        updater.update()

        coVerify { mockDao.deleteStaleEntries("uad_ng", 4999L) }  // minOf(fetchedAt) - 1
    }

    @Test
    fun `refreshCache is called after upsert`() = runTest {
        val feed = mockk<KnownAppFeed>()
        coEvery { feed.fetch() } returns listOf(makeEntry("com.a"))
        coEvery { feed.sourceId } returns "uad_ng"
        coEvery { mockDao.count() } returns 1

        val updater = KnownAppUpdater(mockDao, mockResolver, listOf(feed))
        updater.update()

        coVerify { mockResolver.refreshCache() }
    }

    @Test
    fun `zero entries from all feeds returns 0`() = runTest {
        val feed = mockk<KnownAppFeed>()
        coEvery { feed.fetch() } returns emptyList()
        coEvery { feed.sourceId } returns "uad_ng"
        coEvery { mockDao.count() } returns 0

        val updater = KnownAppUpdater(mockDao, mockResolver, listOf(feed))
        val total = updater.update()

        assertEquals(0, total)
        coVerify(exactly = 0) { mockDao.upsertAll(any()) }
    }
}

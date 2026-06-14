package com.androdr.ioc

import com.androdr.data.db.IndicatorDao
import com.androdr.data.model.Indicator
import com.androdr.data.model.IocEntry
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class IndicatorUpdaterTest {

    private val dao: IndicatorDao = mockk(relaxed = true)
    private val resolver: IndicatorResolver = mockk(relaxed = true)

    private fun packageFeed(id: String, count: Int): IocFeed = object : IocFeed {
        override val sourceId: String = id
        override suspend fun fetch(): List<IocEntry> = (0 until count).map {
            IocEntry(
                packageName = "com.pkg$it",
                name = "n", category = "c", severity = "LOW",
                description = "d", source = id, fetchedAt = 1_000L + it,
            )
        }
    }

    @Test
    fun `large feed is upserted in bounded chunks rather than one transaction`() = runBlocking {
        val total = IndicatorUpdater.UPSERT_CHUNK_SIZE * 2 + 37
        val sizes = mutableListOf<Int>()
        coEvery { dao.upsertAll(any()) } answers {
            sizes += firstArg<List<Indicator>>().size
        }

        val updater = IndicatorUpdater(
            dao = dao,
            resolver = resolver,
            domainFeeds = emptyList(),
            certHashFeeds = emptyList(),
            packageFeeds = listOf(packageFeed("test_feed", total)),
        )

        val returned = updater.update()

        assertEquals("update() should report the full fetched count", total, returned)
        // No single transaction may exceed the chunk cap.
        assertTrue(
            "no chunk may exceed UPSERT_CHUNK_SIZE; saw $sizes",
            sizes.all { it <= IndicatorUpdater.UPSERT_CHUNK_SIZE },
        )
        // All rows must still be written exactly once in aggregate.
        assertEquals(total, sizes.sum())
        // It must actually be split into multiple transactions (regression guard
        // against reverting to one giant upsert). Derive the expected count from
        // the chunk size rather than hard-coding it, so the assertion tracks
        // UPSERT_CHUNK_SIZE instead of breaking when it is retuned.
        val expectedChunks =
            (total + IndicatorUpdater.UPSERT_CHUNK_SIZE - 1) / IndicatorUpdater.UPSERT_CHUNK_SIZE
        assertTrue("bulk feed must be split across transactions", sizes.size > 1)
        assertEquals(expectedChunks, sizes.size)
    }

    @Test
    fun `empty feed performs no upsert`() = runBlocking {
        val updater = IndicatorUpdater(
            dao = dao,
            resolver = resolver,
            domainFeeds = emptyList(),
            certHashFeeds = emptyList(),
            packageFeeds = listOf(packageFeed("empty_feed", 0)),
        )

        updater.update()

        coVerify(exactly = 0) { dao.upsertAll(any()) }
    }
}

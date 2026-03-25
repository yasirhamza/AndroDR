package com.androdr.ioc

import com.androdr.data.db.DomainIocEntryDao
import com.androdr.data.model.DomainIocEntry
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

class DomainIocUpdaterTest {

    private val dao: DomainIocEntryDao = mockk(relaxed = true)
    private val resolver: DomainIocResolver = mockk(relaxed = true)

    private val entry = DomainIocEntry(
        domain = "evil.com", campaignName = "Test", severity = "CRITICAL",
        source = "mvt_test", fetchedAt = 1000L
    )

    @Test
    fun `update returns count of entries stored`() = runTest {
        val testFeed = object : DomainIocFeed {
            override val sourceId = "mvt_test"
            override suspend fun fetch() = listOf(entry)
        }
        val updater = DomainIocUpdater(dao, resolver, listOf(testFeed))
        coEvery { dao.count() } returns 1
        val result = updater.update()
        assertEquals(1, result)
    }

    @Test
    fun `update calls refreshCache after upsert`() = runTest {
        val testFeed = object : DomainIocFeed {
            override val sourceId = "mvt_test"
            override suspend fun fetch() = listOf(entry)
        }
        val updater = DomainIocUpdater(dao, resolver, listOf(testFeed))
        coEvery { dao.count() } returns 1
        updater.update()
        coVerify { dao.upsertAll(listOf(entry)) }
        coVerify { resolver.refreshCache() }
    }

    @Test
    fun `update prunes stale entries for each feed source`() = runTest {
        val testFeed = object : DomainIocFeed {
            override val sourceId = "mvt_test"
            override suspend fun fetch() = listOf(entry)
        }
        val updater = DomainIocUpdater(dao, resolver, listOf(testFeed))
        coEvery { dao.count() } returns 1
        updater.update()
        coVerify { dao.deleteStaleEntries("mvt_test", entry.fetchedAt - 1) }
    }

    @Test
    fun `update returns 0 when all feeds return empty`() = runTest {
        val testFeed = object : DomainIocFeed {
            override val sourceId = "mvt_test"
            override suspend fun fetch() = emptyList<DomainIocEntry>()
        }
        val updater = DomainIocUpdater(dao, resolver, listOf(testFeed))
        coEvery { dao.count() } returns 0
        assertEquals(0, updater.update())
    }
}

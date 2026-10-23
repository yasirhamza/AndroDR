package com.androdr.data.store

import androidx.paging.PagingConfig
import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.androdr.data.model.ScanState
import com.androdr.data.store.StoreFixture.Companion.app
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** Keyset paging over one scan's records: no OFFSET, scroll position survives invalidation. */
@RunWith(RobolectricTestRunner::class)
class KeysetPagingSourceTest {
    private val f = StoreFixture()
    private val service = "app_scanner"

    @Before fun setUp() = runBlocking {
        f.scan(1L)
        f.persist(1L, service, (0 until 100).map { app("p%03d".format(it)) })
        f.setState(1L, ScanState.COMPLETE)
    }

    @After fun tearDown() = f.close()

    /** Room notifies observers asynchronously after a commit; wait (bounded) for the invalidation. */
    private fun awaitInvalid(s: PagingSource<*, *>, attempts: Int = 200): Boolean {
        repeat(attempts) {
            f.db.invalidationTracker.refreshVersionsSync()
            if (s.invalid) return true
            Thread.sleep(10)
        }
        return false
    }

    private fun source() = f.reader.pagingSource(1L, service)

    private suspend fun PagingSource<Int, DecodedRecord>.page(params: PagingSource.LoadParams<Int>) =
        load(params) as PagingSource.LoadResult.Page<Int, DecodedRecord>

    private val PagingSource.LoadResult.Page<Int, DecodedRecord>.ordinals get() = data.map { it.ordinal }

    @Test
    fun `refresh, append and prepend walk the keyset`() = runBlocking {
        val s = source()
        val first = s.page(PagingSource.LoadParams.Refresh(null, 30, false))
        assertEquals((0..29).toList(), first.ordinals)
        assertNull(first.prevKey)
        val next = s.page(PagingSource.LoadParams.Append(first.nextKey!!, 30, false))
        assertEquals((30..59).toList(), next.ordinals)
        val mid = source().page(PagingSource.LoadParams.Refresh(50, 30, false))
        assertEquals((50..79).toList(), mid.ordinals)
        val before = source().page(PagingSource.LoadParams.Prepend(mid.prevKey!!, 20, false))
        assertEquals((30..49).toList(), before.ordinals)
        val last = source().page(PagingSource.LoadParams.Append(89, 30, false))
        assertEquals((90..99).toList(), last.ordinals)
        assertNull(last.nextKey)
    }

    @Test
    fun `scroll position survives an invalidation`() = runBlocking {
        val old = source()
        val p1 = old.page(PagingSource.LoadParams.Refresh(null, 30, false))
        val p2 = old.page(PagingSource.LoadParams.Append(p1.nextKey!!, 30, false))
        // A scan completing is what invalidates (ScanResult is observed).
        f.scan(2L, ScanState.COMPLETE)
        assertTrue(awaitInvalid(old))
        val state = PagingState(listOf(p1, p2), anchorPosition = 45,
            config = PagingConfig(pageSize = 30, initialLoadSize = 30), leadingPlaceholderCount = 0)
        val key = old.getRefreshKey(state)
        assertEquals(30, key)
        val reloaded = source().page(PagingSource.LoadParams.Refresh(key, 30, false))
        assertTrue(45 in reloaded.ordinals)
        assertEquals(30, reloaded.ordinals.first())
    }

    @Test
    fun `store chunk commits do not invalidate a page`() = runBlocking {
        f.scan(3L)
        f.db.invalidationTracker.refreshVersionsSync()
        val s = source()
        s.page(PagingSource.LoadParams.Refresh(null, 30, false))
        f.persist(3L, service, listOf(app("later")))
        assertFalse(awaitInvalid(s, attempts = 30))
    }

    @Test
    fun `observes only tables that exist in the current schema`() {
        val existing = f.db.openHelper.readableDatabase.query("SELECT name FROM sqlite_master WHERE type = 'table'")
            .use { c -> buildList { while (c.moveToNext()) add(c.getString(0)) } }
        assertEquals(listOf("ScanResult", "forensic_timeline"), KeysetPagingSource.OBSERVED_TABLES.toList())
        assertTrue(existing.containsAll(KeysetPagingSource.OBSERVED_TABLES.toList()))
    }

    @Test
    fun `no captured SQL contains OFFSET`() = runBlocking {
        val s = source()
        val p = s.page(PagingSource.LoadParams.Refresh(40, 20, false))
        s.page(PagingSource.LoadParams.Prepend(p.prevKey!!, 20, false))
        s.page(PagingSource.LoadParams.Append(p.nextKey!!, 20, false))
        f.reader.forEach(1L, service) { }
        assertTrue(f.sql.isNotEmpty())
        assertTrue(f.sql.filter { it.uppercase().contains("OFFSET") }.joinToString("\n"),
            f.sql.none { it.uppercase().contains("OFFSET") })
    }
}

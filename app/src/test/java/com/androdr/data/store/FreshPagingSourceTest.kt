package com.androdr.data.store

import androidx.paging.PagingSource
import androidx.paging.PagingState
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * The test helpers that load a page the way Paging does: an invalidated source is replaced and the
 * load repeated. Regression gate for the intermittent main failure where a test cast
 * [PagingSource.LoadResult.Invalid] to a page.
 */
class FreshPagingSourceTest {
    /** Answers each load with the next of [results]. */
    private class Scripted(private val results: Iterator<LoadResult<Int, String>>) : PagingSource<Int, String>() {
        override suspend fun load(params: LoadParams<Int>): LoadResult<Int, String> = results.next()
        override fun getRefreshKey(state: PagingState<Int, String>): Int? = null
    }

    private val refresh = PagingSource.LoadParams.Refresh<Int>(null, 10, false)
    private val invalid: PagingSource.LoadResult<Int, String> = PagingSource.LoadResult.Invalid()
    private fun page(vararg items: String) = PagingSource.LoadResult.Page<Int, String>(items.toList(), null, null)
    private fun scripted(vararg results: PagingSource.LoadResult<Int, String>) = Scripted(results.iterator())

    @Test
    fun `an invalidated source is replaced and the load repeated`() = runBlocking {
        val wanted = page("a", "b")
        val answers = listOf(invalid, invalid, wanted)
        var made = 0
        val got = loadFresh(refresh) { scripted(answers[made++]) }
        assertSame(wanted, got)
        assertEquals("one source per attempt", 3, made)
    }

    @Test
    fun `a walk invalidated part way starts again from the first page`() = runBlocking {
        val first = page("a")
        val second = page("b")
        val scripts = listOf(listOf(first, invalid), listOf(first, second))
        var made = 0
        val walked = withFreshSource({ Scripted(scripts[made++].iterator()) }) { s ->
            s.pageOrRestart(refresh).data + s.pageOrRestart(refresh).data
        }
        assertEquals(listOf("a", "b"), walked)
        assertEquals(2, made)
    }

    @Test
    fun `a source invalidated on every attempt fails, it does not loop`() {
        var made = 0
        val failure = assertThrows(RuntimeException::class.java) {
            runBlocking {
                loadFresh(refresh) {
                    made++
                    scripted(invalid)
                }
            }
        }
        assertEquals("the paging source was invalidated on every attempt", failure.message)
        assertEquals(20, made)
    }

    @Test
    fun `a failed load is reported with its cause, not as a cast failure`() {
        val cause = IllegalStateException("disk")
        val failure = assertThrows(AssertionError::class.java) {
            runBlocking {
                loadFresh(refresh) { scripted(PagingSource.LoadResult.Error(cause)) }
            }
        }
        assertSame(cause, failure.cause)
    }
}

package com.androdr.data.store

import androidx.paging.PagingSource

/*
 * Room can invalidate a paging source that has only just been created. [KeysetPagingSource]
 * registers its observer on the first load, and a change notification Room is still delivering on
 * its executor, for a write made before that load, can arrive after the observer is registered.
 * Paging answers [PagingSource.LoadResult.Invalid] by loading again through a new source. These
 * helpers do the same, so a test never fails on the timing of that notification (a cast of the
 * load result to a page did, once, on main).
 */

private class SourceInvalidated : RuntimeException("the paging source was invalidated on every attempt")

private const val MAX_ATTEMPTS = 20

/** One load of this source: its page, or a restart of the enclosing [withFreshSource]. */
internal suspend fun <K : Any, V : Any> PagingSource<K, V>.pageOrRestart(
    params: PagingSource.LoadParams<K>,
): PagingSource.LoadResult.Page<K, V> = when (val result = load(params)) {
    is PagingSource.LoadResult.Page -> result
    is PagingSource.LoadResult.Invalid -> throw SourceInvalidated()
    is PagingSource.LoadResult.Error -> throw AssertionError("the load failed", result.throwable)
}

/**
 * Runs [block] over a new source from [source], starting again with another new source when a
 * [pageOrRestart] inside it finds the source invalidated. [block] may load several pages; it must
 * be safe to run more than once.
 */
internal suspend fun <S : PagingSource<*, *>, R> withFreshSource(
    source: () -> S,
    attempts: Int = MAX_ATTEMPTS,
    block: suspend (S) -> R,
): R {
    repeat(attempts - 1) {
        try {
            return block(source())
        } catch (expected: SourceInvalidated) {
            // Load again through a new source, as Paging does.
        }
    }
    return block(source())
}

/** One page through a new source, loaded again if Room invalidates that source. */
internal suspend fun <K : Any, V : Any> loadFresh(
    params: PagingSource.LoadParams<K>,
    source: () -> PagingSource<K, V>,
): PagingSource.LoadResult.Page<K, V> = withFreshSource(source) { it.pageOrRestart(params) }

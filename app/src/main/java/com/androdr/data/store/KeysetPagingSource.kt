package com.androdr.data.store

import android.annotation.SuppressLint
import androidx.paging.PagingSource
import androidx.paging.PagingState
import androidx.room.InvalidationTracker
import androidx.room.RoomDatabase
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.conflate
import java.util.concurrent.atomic.AtomicBoolean

/**
 * A Room-backed [PagingSource] paging by key, never by OFFSET (spec §5.1, room-paging is not
 * used). Keys are exclusive for append (`> key`) and prepend (`< key`, through a reverse-ordered
 * query) and inclusive for refresh (`>= key`).
 *
 * Invalidation: on the first load it calls `refreshVersionsSync()` (so writes before the load
 * do not invalidate it) and registers an [InvalidationTracker.Observer] on [observed]; the
 * observer is removed when the source is invalidated. Store tables are not observed: store data
 * becomes visible only when a scan completes or is deleted, so chunk commits cause no
 * invalidation storms. Pass only tables that exist in the current schema (see [OBSERVED_TABLES]).
 */
abstract class KeysetPagingSource<K : Any, V : Any>(
    private val db: RoomDatabase,
    observed: Array<String>,
) : PagingSource<K, V>() {

    private val registered = AtomicBoolean(false)
    private val observer = object : InvalidationTracker.Observer(observed) {
        override fun onInvalidated(tables: Set<String>) = invalidate()
    }

    init {
        registerInvalidatedCallback { db.invalidationTracker.removeObserver(observer) }
    }

    protected abstract fun keyOf(item: V): K

    /** Items with key >= [from] (from the start when null), ascending, at most [size]. */
    protected abstract suspend fun loadFrom(from: K?, size: Int): List<V>

    /** Items with key > [after], ascending, at most [size]. */
    protected abstract suspend fun loadAfter(after: K, size: Int): List<V>

    /** Items with key < [before], DESCENDING (nearest first), at most [size]. */
    protected abstract suspend fun loadBefore(before: K, size: Int): List<V>

    override val jumpingSupported: Boolean get() = false

    @SuppressLint("RestrictedApi") // refreshVersionsSync: what Room's own paging sources call
    override suspend fun load(params: LoadParams<K>): LoadResult<K, V> {
        if (registered.compareAndSet(false, true)) {
            db.invalidationTracker.refreshVersionsSync()
            db.invalidationTracker.addObserver(observer)
        }
        val size = params.loadSize
        val page = when (params) {
            is LoadParams.Refresh -> loadFrom(params.key, size).let { items ->
                val prev = if (params.key == null) null else items.firstOrNull()?.let(::keyOf) ?: params.key
                LoadResult.Page(items, prev, nextKeyOf(items, size))
            }
            is LoadParams.Append -> loadAfter(params.key, size).let { items ->
                LoadResult.Page(items, null, nextKeyOf(items, size))
            }
            is LoadParams.Prepend -> loadBefore(params.key, size).asReversed().let { items ->
                LoadResult.Page(items, if (items.size < size) null else keyOf(items.first()), null)
            }
        }
        return if (invalid) LoadResult.Invalid() else page
    }

    private fun nextKeyOf(items: List<V>, size: Int): K? = if (items.size < size) null else keyOf(items.last())

    /** Backs off half a load from the anchor, so the reloaded page still covers it. */
    override fun getRefreshKey(state: PagingState<K, V>): K? {
        val anchor = state.anchorPosition ?: return null
        val position = (anchor - state.config.initialLoadSize / 2).coerceAtLeast(0)
        return state.closestItemToPosition(position)?.let(::keyOf)
    }

    companion object {
        /**
         * Tables paging sources observe, as of the current schema (20): `ScanResult` and
         * `forensic_timeline`. Schema 21 adds `alert`.
         */
        val OBSERVED_TABLES: Array<String> = arrayOf("ScanResult", "forensic_timeline")
    }
}

/** Emits once on collection and again after each change to [tables] (conflated). */
internal fun RoomDatabase.tableChanges(tables: Array<String>): Flow<Unit> = callbackFlow {
    val observer = object : InvalidationTracker.Observer(tables) {
        override fun onInvalidated(tables: Set<String>) {
            trySend(Unit)
        }
    }
    invalidationTracker.addObserver(observer)
    trySend(Unit)
    awaitClose { invalidationTracker.removeObserver(observer) }
}.conflate()

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
import java.lang.ref.WeakReference
import java.util.concurrent.atomic.AtomicBoolean

/**
 * A Room-backed [PagingSource] paging by key, never by OFFSET (spec §5.1, room-paging is not
 * used). Keys are exclusive for append (`> key`) and prepend (`< key`, through a reverse-ordered
 * query) and inclusive for refresh (`>= key`).
 *
 * Invalidation: on the first load it calls `refreshVersionsSync()` (so writes before the load
 * do not invalidate it) and registers an [InvalidationTracker.Observer] on [observed]; the
 * observer is removed (off the calling thread) when the source is invalidated. The tracker holds
 * only a small forwarding observer that references this source weakly, so a source Paging abandons
 * without invalidating (its collector cancelled) is collected, and its forwarder removes itself on
 * the next change of [observed]. Store tables are not observed: store data
 * becomes visible only when a scan completes or is deleted, so chunk commits cause no
 * invalidation storms. Pass only tables that exist in the current schema (see [OBSERVED_TABLES]).
 */
abstract class KeysetPagingSource<K : Any, V : Any>(
    private val db: RoomDatabase,
    observed: Array<String>,
) : PagingSource<K, V>() {

    private val registered = AtomicBoolean(false)
    private val observer = WeakForwarder(db, observed, WeakReference(this))

    init {
        registerInvalidatedCallback { db.queryExecutor.execute { db.invalidationTracker.removeObserver(observer) } }
    }

    protected abstract fun keyOf(item: V): K

    /**
     * One read: the [items] to show and the [keys] of every entry the keyset read selected, in read
     * order. Page keys and the end of the list come from [keys], so an entry that fails to load
     * after it was selected (deleted in between) is skipped without ending the list early.
     */
    class Slice<K : Any, V : Any>(val items: List<V>, val keys: List<K>)

    /** A slice whose items are exactly the entries read. */
    protected fun slice(items: List<V>): Slice<K, V> = Slice(items, items.map(::keyOf))

    /** Entries with key >= [from] (from the start when null), ascending, at most [size]. */
    protected abstract suspend fun loadFrom(from: K?, size: Int): Slice<K, V>

    /** Entries with key > [after], ascending, at most [size]. */
    protected abstract suspend fun loadAfter(after: K, size: Int): Slice<K, V>

    /** Entries with key < [before], DESCENDING (nearest first), at most [size]. */
    protected abstract suspend fun loadBefore(before: K, size: Int): Slice<K, V>

    override val jumpingSupported: Boolean get() = false

    @SuppressLint("RestrictedApi") // refreshVersionsSync: what Room's own paging sources call
    override suspend fun load(params: LoadParams<K>): LoadResult<K, V> {
        if (registered.compareAndSet(false, true)) {
            db.invalidationTracker.refreshVersionsSync()
            db.invalidationTracker.addObserver(observer)
        }
        val size = params.loadSize
        val page = when (params) {
            is LoadParams.Refresh -> loadFrom(params.key, size).let { s ->
                val prev = if (params.key == null) null else s.keys.firstOrNull() ?: params.key
                LoadResult.Page(s.items, prev, nextKeyOf(s, size))
            }
            is LoadParams.Append -> loadAfter(params.key, size).let { s ->
                LoadResult.Page(s.items, null, nextKeyOf(s, size))
            }
            is LoadParams.Prepend -> loadBefore(params.key, size).let { s ->
                // Read nearest first; shown ascending. The next prepend continues past the farthest read.
                LoadResult.Page(s.items.asReversed(), if (s.keys.size < size) null else s.keys.last(), null)
            }
        }
        return if (invalid) LoadResult.Invalid() else page
    }

    private fun nextKeyOf(s: Slice<K, V>, size: Int): K? = if (s.keys.size < size) null else s.keys.last()

    /** Backs off half a load from the anchor, so the reloaded page still covers it. */
    override fun getRefreshKey(state: PagingState<K, V>): K? {
        val anchor = state.anchorPosition ?: return null
        val position = (anchor - state.config.initialLoadSize / 2).coerceAtLeast(0)
        return state.closestItemToPosition(position)?.let(::keyOf)
    }

    /**
     * The observer the tracker holds: it forwards to the source while the source is reachable, and
     * removes itself once the source has been collected (A5 deferred minor: a strong observer kept
     * every abandoned source alive).
     */
    private class WeakForwarder(
        private val db: RoomDatabase,
        tables: Array<String>,
        private val source: WeakReference<KeysetPagingSource<*, *>>,
    ) : InvalidationTracker.Observer(tables) {
        override fun onInvalidated(tables: Set<String>) {
            val target = source.get()
            if (target != null) target.invalidate() else db.invalidationTracker.removeObserver(this)
        }
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

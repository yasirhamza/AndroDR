package com.androdr.data.db

import androidx.room.Dao
import androidx.room.RawQuery
import androidx.sqlite.db.SupportSQLiteQuery
import com.androdr.data.model.TimelineRowEntity

/**
 * The Timeline's one keyset-paged read (spec §6): the union of visible event facts and visible
 * `forensic_timeline` rows, in display order ([TimelineKey.DISPLAY_ORDER]), never by OFFSET and
 * never capped. A page and a count are each ONE statement ([TimelineQueries]): a consistent read
 * that takes no transaction, so it never holds the writer lock that an import's chunk commits and
 * the DNS monitor's inserts need.
 */
@Dao
abstract class TimelineDao {

    /** One page statement ([TimelineQueries.page]); call [page] instead. */
    @RawQuery
    abstract suspend fun pageRows(query: SupportSQLiteQuery): List<TimelineRowEntity>

    /** One count statement ([TimelineQueries.count]); call [count] instead. */
    @RawQuery
    abstract suspend fun countRows(query: SupportSQLiteQuery): Long

    /**
     * Up to [size] entries on [direction]'s side of [key]: display order for [TimelineDirection.FROM]
     * and [TimelineDirection.AFTER], nearest first (ascending) for [TimelineDirection.BEFORE].
     */
    open suspend fun page(
        filter: TimelineFilter, key: TimelineKey?, direction: TimelineDirection, size: Int,
    ): List<TimelineRowEntity> {
        val keyOrder = if (direction == TimelineDirection.BEFORE) {
            TimelineKey.DISPLAY_ORDER.reversed()
        } else {
            TimelineKey.DISPLAY_ORDER
        }
        val order = compareBy(keyOrder) { e: TimelineRowEntity -> e.key }
        // UNION ALL without an outer ORDER BY promises no order: each arm is re-sorted (≤ size each).
        val arms = pageRows(TimelineQueries.page(filter, key, direction, size).toQuery())
            .partition { it.rowKind == TimelineRowEntity.ROW }.toList().map { it.sortedWith(order) }
        return mergeSorted(arms, order, size)
    }

    /** What the list shows for [filter]: its rows, its standalone facts, and the rows' visible evidence. */
    open suspend fun count(filter: TimelineFilter): Long = countRows(TimelineQueries.count(filter).toQuery())

    companion object {
        /** The first [size] of [lists] (each already sorted by [order]), merged. */
        internal fun <T> mergeSorted(lists: List<List<T>>, order: Comparator<T>, size: Int): List<T> {
            val heads = IntArray(lists.size)
            val out = ArrayList<T>(minOf(size, lists.sumOf { it.size }))
            while (out.size < size) {
                var best = -1
                for (i in lists.indices) {
                    if (heads[i] < lists[i].size &&
                        (best < 0 || order.compare(lists[i][heads[i]], lists[best][heads[best]]) < 0)
                    ) best = i
                }
                if (best < 0) break
                out += lists[best][heads[best]++]
            }
            return out
        }
    }
}

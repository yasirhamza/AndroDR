package com.androdr.data.db

import androidx.room.Dao
import androidx.room.RawQuery
import androidx.room.Transaction
import androidx.sqlite.db.SupportSQLiteQuery
import com.androdr.data.model.TimelineRowEntity

/**
 * The Timeline's one keyset-paged read (spec §6): the union of visible event facts and visible
 * `forensic_timeline` rows, in display order ([TimelineKey.DISPLAY_ORDER]), never by OFFSET and
 * never capped. Both arms ([TimelineQueries]) run in one read transaction and are merged here.
 */
@Dao
abstract class TimelineDao {

    /** One arm of a page ([TimelineQueries.page]); call [page] instead. */
    @RawQuery
    abstract suspend fun arm(query: SupportSQLiteQuery): List<TimelineRowEntity>

    /** One count arm ([TimelineQueries.counts]); call [count] instead. */
    @RawQuery
    abstract suspend fun countArm(query: SupportSQLiteQuery): Long

    /**
     * Up to [size] entries on [direction]'s side of [key]: display order for [TimelineDirection.FROM]
     * and [TimelineDirection.AFTER], nearest first (ascending) for [TimelineDirection.BEFORE].
     */
    @Transaction
    open suspend fun page(
        filter: TimelineFilter, key: TimelineKey?, direction: TimelineDirection, size: Int,
    ): List<TimelineRowEntity> {
        val order = if (direction == TimelineDirection.BEFORE) {
            TimelineKey.DISPLAY_ORDER.reversed()
        } else {
            TimelineKey.DISPLAY_ORDER
        }
        val arms = TimelineQueries.page(filter, key, direction, size).map { arm(it.toQuery()) }
        return mergeSorted(arms, compareBy(order) { it.key }, size)
    }

    /** Entries [filter] matches: its rows plus its facts, nested facts included (they are shown). */
    @Transaction
    open suspend fun count(filter: TimelineFilter): Long =
        TimelineQueries.counts(filter).sumOf { countArm(it.toQuery()) }

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

package com.androdr.data.store

import com.androdr.data.db.AppDatabase
import com.androdr.data.db.AtomRow
import com.androdr.data.db.chunkedIn
import com.androdr.sigma.AtomRef
import com.androdr.sigma.Fact
import com.androdr.sigma.Row
import com.androdr.sigma.TimelineAtom
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Correlation inputs (spec §5.2): timeline rows and exact-precision facts in the atom-bound
 * [categories], read inside the finishing transaction. A fact a timeline row stands in for (its
 * `recordId`, or `sourceKey` = the row's `sourceEventKey`) is never also an atom, so every event
 * binds once; a row and a fact with the same numeric id are distinct ([AtomRef]).
 *
 * The fact queries bind the category list up to three times (the filter and both stand-in tests),
 * and those tests are only right when every category is in the same query, so the list is bound in
 * one chunk of at most [MAX_ATOM_CATEGORIES] (atom rules bind five categories today).
 */
@Singleton
class AtomReader @Inject constructor(private val db: AppDatabase) {
    private val dao get() = db.atomDao()

    /** This scan's own rows (with their real ids) and the facts it observed; the scan may be `IN_PROGRESS`. */
    suspend fun atomsForScan(scanId: Long, categories: Set<String>): List<TimelineAtom> {
        if (categories.isEmpty()) return emptyList()
        val cats = oneChunk(categories)
        return chunkedIn(cats, MAX_ATOM_CATEGORIES) { dao.rowsForScan(scanId, it) }.map { it.atom(::Row) } +
            chunkedIn(cats, MAX_ATOM_CATEGORIES) { dao.factsForScan(scanId, it) }.map { it.atom(::Fact) }
    }

    /**
     * The live lookback in `[since, until]`: visible live rows and facts a `COMPLETE` live scan
     * observed. Imports are never included (their events carry their own historical times), nor are
     * rows or facts of `IN_PROGRESS` or `DELETING` scans.
     */
    suspend fun atomsBetween(since: Long, until: Long, categories: Set<String>): List<TimelineAtom> {
        if (categories.isEmpty() || until < since) return emptyList()
        val cats = oneChunk(categories)
        return chunkedIn(cats, MAX_ATOM_CATEGORIES) { dao.liveRowsBetween(since, until, it) }.map { it.atom(::Row) } +
            chunkedIn(cats, MAX_ATOM_CATEGORIES) { dao.liveFactsBetween(since, until, it) }.map { it.atom(::Fact) }
    }

    private fun oneChunk(categories: Set<String>): List<String> {
        require(categories.size <= MAX_ATOM_CATEGORIES) { "${categories.size} atom categories exceed one query" }
        return categories.toList()
    }

    private fun AtomRow.atom(ref: (Long) -> AtomRef) =
        TimelineAtom(ref(id), category, timestamp, packageName, ruleId, telemetrySource)

    companion object {
        /** Three bindings of this many stay under SQLite's 999-variable limit. */
        const val MAX_ATOM_CATEGORIES = 200
    }
}

package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.SignalMember

/** A member ref of one signal (see [SignalMemberDao.existingRefs]). */
data class MemberRef(val signalRowId: Long, val kind: Int, val refId: Long)

/** Correlation-signal members (spec §5.4). List-parameter queries go through [chunkedEach] / [chunkedIn]. */
@Dao
interface SignalMemberDao {

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertAll(members: List<SignalMember>)

    /**
     * One page of [signalRowId]'s members ordered by `(kind, refId)`, after the cursor
     * `(afterKind, afterRefId)`; both null for the first page.
     */
    @Query(
        "SELECT * FROM signal_member WHERE signalRowId = :signalRowId AND (:afterKind IS NULL " +
            "OR kind > :afterKind OR (kind = :afterKind AND refId > :afterRefId)) ORDER BY kind, refId LIMIT :size"
    )
    suspend fun forSignal(signalRowId: Long, afterKind: Int?, afterRefId: Long?, size: Int): List<SignalMember>

    /** Every member of [ids] (a signal row delete takes them with it). Call through [chunkedEach]. */
    @Query("DELETE FROM signal_member WHERE signalRowId IN (:ids)")
    suspend fun deleteForSignals(ids: List<Long>)

    /**
     * Fact refs of [ids]' members: the pins a signal-row delete releases (read by
     * `TimelineRowDeleter` just before [deleteForSignals], in the same transaction). Uses the
     * primary-key prefix `signalRowId`. Call through [chunkedIn].
     */
    @Query(
        "SELECT DISTINCT refId FROM signal_member WHERE signalRowId IN (:ids) AND kind = ${SignalMember.KIND_FACT}"
    )
    suspend fun factRefsOf(ids: List<Long>): List<Long>

    /**
     * Of [signalRowIds]' members, those whose row or fact is still visible, ordered by signal then
     * `(kind, refId)` (the CSV `member_refs` column). Call through [chunkedIn].
     */
    @Query(
        "SELECT sm.signalRowId AS signalRowId, sm.kind AS kind, sm.refId AS refId FROM signal_member sm " +
            "WHERE sm.signalRowId IN (:signalRowIds) AND ((sm.kind = ${SignalMember.KIND_ROW} AND EXISTS " +
            "(SELECT 1 FROM forensic_timeline r WHERE r.id = sm.refId AND ${VisibleRow.SQL})) " +
            "OR (sm.kind = ${SignalMember.KIND_FACT} AND EXISTS " +
            "(SELECT 1 FROM telemetry_record f WHERE f.id = sm.refId AND ${VisibleFact.SQL}))) " +
            "ORDER BY sm.signalRowId, sm.kind, sm.refId"
    )
    suspend fun existingRefs(signalRowIds: List<Long>): List<MemberRef>
}

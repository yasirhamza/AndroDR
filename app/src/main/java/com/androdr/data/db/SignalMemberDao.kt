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

    @Query("DELETE FROM signal_member WHERE signalRowId IN (:ids)")
    suspend fun deleteForSignals(ids: List<Long>)

    /**
     * Fact refs of members whose signal row no longer exists: the pins a row delete releases
     * (read by `TimelineRowDeleter` just before [deleteOrphans], in the same transaction).
     */
    @Query(
        "SELECT DISTINCT o.refId FROM signal_member o WHERE o.kind = ${SignalMember.KIND_FACT} " +
            "AND NOT EXISTS (SELECT 1 FROM forensic_timeline s WHERE s.id = o.signalRowId)"
    )
    suspend fun orphanFactRefs(): List<Long>

    /** Members whose signal row is gone: every row delete removes its signals' members with it. */
    @Query(
        "DELETE FROM signal_member WHERE NOT EXISTS " +
            "(SELECT 1 FROM forensic_timeline s WHERE s.id = signal_member.signalRowId)"
    )
    suspend fun deleteOrphans()

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

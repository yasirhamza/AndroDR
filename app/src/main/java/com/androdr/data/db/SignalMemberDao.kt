package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.SignalMember

/** Correlation-signal members (spec §5.4). List-parameter queries go through [chunkedEach]. */
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
}

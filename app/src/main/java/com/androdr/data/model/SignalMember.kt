package com.androdr.data.model

import androidx.room.Entity
import androidx.room.Index

/**
 * A member of a correlation signal (spec §5.4): the only store of member lists. [kind] is
 * [KIND_ROW] (a `forensic_timeline` row id) or [KIND_FACT] (a `telemetry_record` id), matching
 * `AtomRef.kind`. The composite primary key is the unique `(signalRowId, kind, refId)`; the
 * `(kind, refId)` index serves the pin test and prune exemptions.
 */
@Entity(
    tableName = "signal_member",
    primaryKeys = ["signalRowId", "kind", "refId"],
    indices = [Index(value = ["kind", "refId"])]
)
data class SignalMember(
    val signalRowId: Long,
    val kind: Int,
    val refId: Long,
) {
    companion object {
        const val KIND_ROW = 0
        const val KIND_FACT = 1
    }
}

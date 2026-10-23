package com.androdr.ui.bugreport

import android.net.Uri
import com.androdr.data.model.TelemetryState
import com.androdr.scanner.WriteResult

/** What the import preflight asks the user before a tight import starts. */
data class PreflightPrompt(val uri: Uri, val estimateBytes: Long?, val freeBytes: Long)

/** Why an import was not fully stored, when it was not. */
sealed interface ImportNotice {
    /** Fully stored. */
    data object None : ImportNotice

    /** The space reserve was breached: findings were kept, records were not stored; free [bytes] to re-import. */
    data class FreeSpace(val bytes: Long) : ImportNotice

    /** Findings were kept but the records were not stored (the database refused them). */
    data object NotStored : ImportNotice
}

/**
 * The counts an import shows: how many facts were new, how many the store already held, how many
 * exact duplicates it dropped, which size bounds tripped, and whether the import was stored at all.
 * Built only from what the import session reported.
 */
data class ImportCard(
    val newFacts: Int,
    val alreadyStored: Int,
    val duplicatesDropped: Int,
    val trippedBounds: List<String>,
    val notice: ImportNotice,
) {
    companion object {
        /** Shown for an intrusion log whose parser hit a line-length or per-type record limit. */
        const val INTRUSION_LIMIT = "A line-length or per-type record limit dropped some records."

        /**
         * [truncated] is the intrusion-log stats flag, [boundTrips] a bug report's per-module bound
         * trips. Null [write] (a result not produced by a session) yields no card.
         */
        fun from(write: WriteResult?, truncated: Boolean, boundTrips: List<String>): ImportCard? {
            if (write == null) return null
            val bounds = buildList {
                if (truncated) add(INTRUSION_LIMIT)
                addAll(boundTrips)
            }
            val notice = when {
                write.spaceToFree > 0L -> ImportNotice.FreeSpace(write.spaceToFree)
                write.telemetryState == TelemetryState.FAILED -> ImportNotice.NotStored
                else -> ImportNotice.None
            }
            return ImportCard(write.newFacts, write.alreadyStored, write.duplicatesDropped, bounds, notice)
        }
    }
}

package com.androdr.ui.bugreport

import android.net.Uri
import com.androdr.data.model.TelemetryState
import com.androdr.scanner.WriteResult

/** What the import preflight asks the user before a tight import starts. */
data class PreflightPrompt(val uri: Uri, val estimateBytes: Long?, val freeBytes: Long?) {
    /** Low space is claimed only when a size estimate exists; otherwise the dialog says the size is unknown. */
    val sizeUnknown: Boolean get() = estimateBytes == null
}

/** Why an import was not fully stored, when it was not. */
sealed interface ImportNotice {
    /** Fully stored. */
    data object None : ImportNotice

    /**
     * Storage ran low partway: [storedFacts] new records were stored before that, the rest were only
     * checked. Free at least [freeAtLeastBytes] more; [wholeImportBytes] is the preflight estimate for
     * the whole import, null when unknown.
     */
    data class LowSpace(val storedFacts: Int, val freeAtLeastBytes: Long, val wholeImportBytes: Long?) : ImportNotice

    /** The database refused part of the import (not a reserve breach): [storedFacts] were stored. */
    data class NotFullyStored(val storedFacts: Int) : ImportNotice
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
    /** How the file was read, e.g. "times assume UTC" when a bug report names no zone (R27). */
    val notes: List<String> = emptyList(),
) {
    companion object {
        /** Shown for an intrusion log whose parser hit a line-length or per-type record limit. */
        const val INTRUSION_LIMIT = "A line-length or per-type record limit dropped some records."

        /**
         * [truncated] is the intrusion-log stats flag, [boundTrips] a bug report's per-module bound
         * trips. Null [write] (a result not produced by a session) yields no card.
         */
        fun from(
            write: WriteResult?,
            truncated: Boolean,
            boundTrips: List<String>,
            estimateBytes: Long? = null,
            notes: List<String> = emptyList(),
        ): ImportCard? {
            if (write == null) return null
            val bounds = buildList {
                if (truncated) add(INTRUSION_LIMIT)
                addAll(boundTrips)
            }
            val notice = when {
                write.spaceToFree > 0L -> ImportNotice.LowSpace(write.newFacts, write.spaceToFree, estimateBytes)
                write.telemetryState == TelemetryState.FAILED -> ImportNotice.NotFullyStored(write.newFacts)
                else -> ImportNotice.None
            }
            return ImportCard(write.newFacts, write.alreadyStored, write.duplicatesDropped, bounds, notice, notes)
        }
    }
}

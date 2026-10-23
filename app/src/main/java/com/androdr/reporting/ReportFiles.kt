package com.androdr.reporting

import java.io.File

/**
 * The shared-report directory (`cacheDir/reports`): every report, timeline, STIX and hash export
 * is written there and handed out through the FileProvider. The startup sweep removes files older
 * than [STALE_AFTER_MS] (spec §5.2), so exported evidence does not linger in the cache.
 */
class ReportFiles(val dir: File, private val now: () -> Long = System::currentTimeMillis) {

    /** Deletes regular files under [dir] last modified more than [STALE_AFTER_MS] ago; returns how many. */
    fun deleteStale(): Int {
        val cutoff = now() - STALE_AFTER_MS
        val stale = dir.listFiles()?.filter { it.isFile && it.lastModified() < cutoff }.orEmpty()
        return stale.count { it.delete() }
    }

    companion object {
        /** Long enough for a share sheet started before a restart to finish reading its file. */
        const val STALE_AFTER_MS = 60L * 60 * 1000
    }
}

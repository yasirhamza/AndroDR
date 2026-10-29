package com.androdr.reporting

import java.io.File
import java.io.Writer

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

/**
 * Streams into a `.part` sibling of [file] through [open] (a buffered UTF-8 writer by default), then
 * renames it to [file], so a reader polling for [file] (the debug harness) never sees a half-written
 * export, and a write that fails (a full disk) leaves nothing behind. Every export into
 * [ReportFiles.dir] writes through here: the report, the telemetry JSONL and the Timeline.
 */
@Suppress("TooGenericExceptionCaught") // any failure removes the partial file, then rethrows
internal suspend fun writeReportFile(
    file: File,
    open: (File) -> Writer = { it.bufferedWriter(Charsets.UTF_8) },
    write: suspend (Writer) -> Unit,
) {
    val part = File(file.parentFile, "${file.name}.part")
    try {
        open(part).use { write(it) }
        // rename(2) replaces an existing file atomically: never delete it first.
        check(part.renameTo(file)) { "could not move the export into place" }
    } catch (t: Throwable) {
        part.delete()
        throw t
    }
}

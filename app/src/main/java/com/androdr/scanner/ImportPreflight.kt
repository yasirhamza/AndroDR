package com.androdr.scanner

import android.content.Context
import android.net.Uri
import android.util.Log
import com.androdr.data.store.Preflight
import com.androdr.data.store.StoragePreflight
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.FileInputStream
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Runs the storage preflight for a picked import (spec §5.2): sums the archive's decompressed entry
 * sizes from the ZIP central directory (no inflation), takes its type from [ImportArchive] (the same
 * classification the analyzer is routed by), and asks [StoragePreflight.check] with that type's
 * stored-size factor. An archive whose sizes cannot be read — not seekable, unreadable directory, an
 * entry with unknown size — yields an unknown estimate, which the preflight always treats as tight.
 */
@Singleton
class ImportPreflight @Inject constructor(
    @ApplicationContext private val context: Context,
    private val storage: StoragePreflight,
) {
    suspend fun check(uri: Uri): Preflight {
        val contents = ImportArchive.centralDirectory(context, uri)
        return storage.check(contents?.totalSize, storedSizeFactor(contents?.type ?: ArtifactType.UNRECOGNIZED))
    }

    companion object {
        /**
         * Stored bytes per decompressed byte of an intrusion-log export (ruling R45): measured ≈3.5 on
         * the F916B battery (telemetry tables + indexes ≈78 MB for ≈22 MB decompressed), plus headroom.
         * Findings add more on top, which no size predicts.
         */
        const val INTRUSION_LOG_STORED_SIZE_FACTOR = 4.0

        /**
         * Stored bytes per decompressed byte of a bug report (ruling R45): measured ≈0.0023 on the
         * F916B battery (≈236 KB for 302 records from 103,317,358 decompressed bytes); about 20× that,
         * for reports with a long battery history. Most of a bug report is text no module stores.
         */
        const val BUG_REPORT_STORED_SIZE_FACTOR = 0.05

        /**
         * The measured stored-size factor of an artifact [type] (spec §5.2). An unrecognized archive
         * (refused after the preflight) takes the larger, conservative factor.
         */
        fun storedSizeFactor(type: ArtifactType): Double = when (type) {
            ArtifactType.BUG_REPORT -> BUG_REPORT_STORED_SIZE_FACTOR
            ArtifactType.INTRUSION_LOG, ArtifactType.UNRECOGNIZED -> INTRUSION_LOG_STORED_SIZE_FACTOR
        }

        /** Sum of the entry sizes; null when any entry's size is unknown (negative) or the sum overflows. */
        fun sumSizes(sizes: Sequence<Long>): Long? {
            var total = 0L
            for (s in sizes) {
                if (s < 0) return null
                total += s
                if (total < 0) return null
            }
            return total
        }
    }
}

/**
 * The one classification of a picked import (#418), shared by [ImportPreflight] (its stored-size
 * factor) and [ScanOrchestrator.analyzeArtifact] (which analyzer runs). Both used to classify on their
 * own, the preflight by the central directory's names and the analyzer by the local headers' names, so
 * a forged ZIP whose two name lists disagree got the bug report's 0.05 factor while the intrusion-log
 * analyzer (4.0) ran. Now the central directory decides both when it is readable; only when it is not
 * (the preflight's estimate is then unknown, so no size relied on a type) does [type] fall back to
 * sniffing the stream.
 */
object ImportArchive {
    private const val TAG = "ImportArchive"

    /** The archive's central-directory size and type, or null when that directory cannot be read. */
    @Suppress("TooGenericExceptionCaught")
    suspend fun centralDirectory(context: Context, uri: Uri): ZipCentralDirectory.Contents? =
        withContext(Dispatchers.IO) {
            try {
                // The descriptor the provider handed us is read in place; no path is reopened.
                context.contentResolver.openFileDescriptor(uri, "r")?.use { pfd ->
                    // The stream does not own the descriptor; closing it only releases the channel.
                    FileInputStream(pfd.fileDescriptor).use { ZipCentralDirectory.contents(it.channel) }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "archive size unknown: ${e.javaClass.simpleName}")
                null
            }
        }

    /**
     * What the import is: the central directory's type, or (directory unreadable) the bounded stream
     * sniff ([ArtifactSniffer.classifyZip], which caps inflation against a deflate bomb).
     */
    suspend fun type(context: Context, uri: Uri): ArtifactType =
        centralDirectory(context, uri)?.type ?: withContext(Dispatchers.IO) {
            val stream = context.contentResolver.openInputStream(uri) ?: return@withContext ArtifactType.UNRECOGNIZED
            stream.use { s -> ArtifactSniffer.classifyZip(s).type }
        }
}

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
 * sizes from the ZIP central directory (no inflation) and asks [StoragePreflight.check]. An archive
 * whose sizes cannot be read — not seekable, unreadable directory, an entry with unknown size —
 * yields an unknown estimate, which the preflight always treats as tight.
 */
@Singleton
class ImportPreflight @Inject constructor(
    @ApplicationContext private val context: Context,
    private val storage: StoragePreflight,
) {
    suspend fun check(uri: Uri): Preflight = storage.check(decompressedBytes(uri))

    @Suppress("TooGenericExceptionCaught")
    private suspend fun decompressedBytes(uri: Uri): Long? = withContext(Dispatchers.IO) {
        try {
            // The descriptor the provider handed us is read in place; no path is reopened.
            context.contentResolver.openFileDescriptor(uri, "r")?.use { pfd ->
                // The stream does not own the descriptor; closing it only releases the channel.
                FileInputStream(pfd.fileDescriptor).use { ZipCentralDirectory.totalSize(it.channel) }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.w(TAG, "archive size unknown: ${e.javaClass.simpleName}")
            null
        }
    }

    companion object {
        private const val TAG = "ImportPreflight"

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

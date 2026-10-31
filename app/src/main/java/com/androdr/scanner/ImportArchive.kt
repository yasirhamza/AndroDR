package com.androdr.scanner

import android.content.Context
import android.net.Uri
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.FileInputStream

/**
 * A picked import's classification (#418), shared by [ImportPreflight] (its stored-size factor, from
 * the central directory) and [ScanOrchestrator.analyzeArtifact] (which analyzer runs, [type]). A ZIP
 * holds its entry names twice: in the central directory, and in the local headers the analyzers
 * stream. A forged ZIP can make the two disagree, so the preflight sized one type while another
 * analyzer ran, or (routing by the directory alone) the routed analyzer found nothing in the stream
 * and the import read clean. [type] therefore rejects an archive whose two classifications differ.
 * Both reads happen on each call: the preflight's directory read is not reused, which costs one
 * bounded re-read per import.
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
     * What the import is: the bounded stream sniff ([ArtifactSniffer.classifyZip], which caps inflation
     * against a deflate bomb; it reads the local headers, as the analyzers do), cross-checked against
     * the central directory when that is readable. A disagreement is [ArtifactType.UNRECOGNIZED], so the
     * import is rejected instead of running an analyzer that would read nothing.
     */
    suspend fun type(context: Context, uri: Uri): ArtifactType {
        val streamed = withContext(Dispatchers.IO) {
            context.contentResolver.openInputStream(uri)?.use { s -> ArtifactSniffer.classifyZip(s).type }
        } ?: return ArtifactType.UNRECOGNIZED
        val central = centralDirectory(context, uri)?.type ?: return streamed
        if (central != streamed) Log.w(TAG, "central directory ($central) and local headers ($streamed) disagree")
        return if (central == streamed) streamed else ArtifactType.UNRECOGNIZED
    }
}

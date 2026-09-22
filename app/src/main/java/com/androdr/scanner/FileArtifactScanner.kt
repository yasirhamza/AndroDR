package com.androdr.scanner

import android.util.Log
import com.androdr.data.model.FileArtifactTelemetry
import com.androdr.data.model.TelemetrySource
import com.androdr.ioc.KnownSpywareArtifactsResolver
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Checks the filesystem for known spyware artifact paths derived from MVT indicators
 * and Citizen Lab research. Returns one [FileArtifactTelemetry] record **per path in
 * the list**, whether or not the path could be read.
 *
 * Most of these paths are unreadable by an unprivileged app. The scanner used to drop
 * those silently, so a device where nothing could be checked produced exactly the same
 * evidence as a device that was checked and found clean: no telemetry, no evaluation of
 * the only CRITICAL artifact rule, and a report that mentioned none of it (#366).
 * Now an unreadable path is reported with `accessible = false`, which is what lets the
 * report say what it could not check. `fileExists = false` on such a row means "not
 * looked at", never "looked at and absent" -- only [FileArtifactTelemetry.accessible]
 * separates the two, so callers that feed rules must filter on it.
 *
 * The path list is sourced from [KnownSpywareArtifactsResolver], which loads
 * `res/raw/known_spyware_artifacts.yml`. The scanner itself stays simple: for each
 * resolved path, probe the filesystem and emit telemetry.
 */
@Singleton
class FileArtifactScanner @Inject constructor(
    private val knownSpywareArtifactsResolver: KnownSpywareArtifactsResolver,
) {

    /**
     * Probes every known artifact path and returns one record per path: the file's
     * metadata when it could be read, and an `accessible = false` record when it
     * could not.
     */
    suspend fun collectTelemetry(): List<FileArtifactTelemetry> = withContext(Dispatchers.IO) {
        val results = knownSpywareArtifactsResolver.paths.map { path -> probe(path) }
        val unreadable = results.count { !it.accessible }
        Log.d(TAG, "Probed ${results.size} paths, " +
            "${results.count { t -> t.fileExists }} found, $unreadable unreadable")
        results
    }

    @Suppress("TooGenericExceptionCaught") // a refused path is evidence, not a reason to stop
    private fun probe(path: String): FileArtifactTelemetry = try {
        val file = File(path)
        if (file.parentFile?.canRead() == true) {
            val exists = file.exists()
            FileArtifactTelemetry(
                filePath = path,
                fileExists = exists,
                fileSize = if (exists) file.length() else null,
                fileModified = if (exists) file.lastModified() else null,
                source = TelemetrySource.LIVE_SCAN,
                accessible = true,
            )
        } else {
            unreadable(path)
        }
    } catch (e: Exception) {
        // SecurityException or any other refusal: record that we could not look.
        Log.d(TAG, "Cannot access $path: ${e.message}")
        unreadable(path)
    }

    /** A path the app was not allowed to look at: no claim either way about its contents. */
    private fun unreadable(path: String) = FileArtifactTelemetry(
        filePath = path,
        fileExists = false,
        fileSize = null,
        fileModified = null,
        source = TelemetrySource.LIVE_SCAN,
        accessible = false,
    )

    companion object {
        private const val TAG = "FileArtifactScanner"
    }
}

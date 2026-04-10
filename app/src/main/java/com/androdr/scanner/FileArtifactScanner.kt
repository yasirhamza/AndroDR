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
 * and Citizen Lab research. Returns one [FileArtifactTelemetry] record per path checked.
 *
 * Most paths require root to read; without root, [File.exists] returns false for
 * inaccessible paths, which is the expected baseline on a clean device.
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
     * Checks each known artifact path and returns telemetry about whether the file exists
     * and its metadata (size, modification time) when accessible.
     */
    @Suppress("TooGenericExceptionCaught")
    suspend fun collectTelemetry(): List<FileArtifactTelemetry> = withContext(Dispatchers.IO) {
        var skipped = 0
        val results = knownSpywareArtifactsResolver.paths.mapNotNull { path ->
            try {
                val file = File(path)
                val parentReadable = file.parentFile?.canRead() ?: false
                if (!parentReadable) {
                    Log.d(TAG, "Skipping inaccessible path: $path")
                    skipped++
                    return@mapNotNull null
                }
                val exists = file.exists()
                FileArtifactTelemetry(
                    filePath = path,
                    fileExists = exists,
                    fileSize = if (exists) file.length() else null,
                    fileModified = if (exists) file.lastModified() else null,
                    source = TelemetrySource.LIVE_SCAN,
                    accessible = true,
                )
            } catch (e: Exception) {
                // SecurityException or other access errors — skip entirely
                Log.d(TAG, "Cannot access $path: ${e.message}")
                skipped++
                null
            }
        }
        Log.d(TAG, "Checked ${results.size} accessible paths, " +
            "${results.count { t -> t.fileExists }} found, $skipped skipped (inaccessible)")
        results
    }

    companion object {
        private const val TAG = "FileArtifactScanner"
    }
}

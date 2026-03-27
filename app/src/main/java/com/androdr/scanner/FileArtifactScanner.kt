package com.androdr.scanner

import android.os.Environment
import android.util.Log
import com.androdr.data.model.FileArtifactTelemetry
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
 */
@Singleton
class FileArtifactScanner @Inject constructor() {

    /**
     * Known artifact paths associated with commercial spyware (Pegasus, Predator, etc.).
     * Sources: MVT indicators, Citizen Lab forensic reports.
     *
     * Paths under external storage use [Environment.getExternalStorageDirectory] to resolve
     * the correct mount point rather than hardcoding "/sdcard".
     */
    @Suppress("DEPRECATION") // getExternalStorageDirectory is deprecated but needed for IOC paths
    private val knownArtifactPaths: List<String> by lazy {
        val extStorage = Environment.getExternalStorageDirectory().absolutePath
        listOf(
            "/data/local/tmp/.raptor",
            "/data/local/tmp/.stat",
            "/data/local/tmp/.mobilesoftwareupdate",
            "$extStorage/.hidden_config",
            "$extStorage/Android/data/.system_update"
        )
    }

    /**
     * Checks each known artifact path and returns telemetry about whether the file exists
     * and its metadata (size, modification time) when accessible.
     */
    @Suppress("TooGenericExceptionCaught")
    suspend fun collectTelemetry(): List<FileArtifactTelemetry> = withContext(Dispatchers.IO) {
        knownArtifactPaths.map { path ->
            try {
                val file = File(path)
                val exists = file.exists()
                FileArtifactTelemetry(
                    filePath = path,
                    fileExists = exists,
                    fileSize = if (exists) file.length() else null,
                    fileModified = if (exists) file.lastModified() else null
                )
            } catch (e: Exception) {
                // SecurityException or other access errors — treat as non-existent
                Log.d(TAG, "Cannot access $path: ${e.message}")
                FileArtifactTelemetry(
                    filePath = path,
                    fileExists = false,
                    fileSize = null,
                    fileModified = null
                )
            }
        }.also {
            Log.d(TAG, "Checked ${it.size} artifact paths, " +
                "${it.count { t -> t.fileExists }} found")
        }
    }

    companion object {
        private const val TAG = "FileArtifactScanner"
    }
}

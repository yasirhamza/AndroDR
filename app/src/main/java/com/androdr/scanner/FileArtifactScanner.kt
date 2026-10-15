package com.androdr.scanner

import android.annotation.SuppressLint
import android.util.Log
import com.androdr.data.model.FileArtifactTelemetry
import com.androdr.data.model.TelemetrySource
import com.androdr.ioc.KnownSpywareArtifactsResolver
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Paths
import java.nio.file.attribute.BasicFileAttributes
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
 * The scanner looks up each exact path rather than first asking whether the folder can
 * be listed. `/data/local/tmp` is `rwxrwx--x`: an app may not list it but may look up a
 * name inside it, so gating on the folder being listable skipped checks the system
 * allows (#387). The system's answer decides the row: "no such file" is a completed
 * check that found nothing; "permission denied", or any other refusal, is a check that
 * could not be made. Shared storage is the exception: it answers "no such file" for
 * whatever it hides from this app (another app's `Android/data`, for one), so there that
 * answer only counts when the folder can be listed.
 *
 * The path list is sourced from [KnownSpywareArtifactsResolver], which loads
 * `res/raw/known_spyware_artifacts.yml`. The scanner itself stays simple: for each
 * resolved path, probe the filesystem and emit telemetry.
 */
@Singleton
class FileArtifactScanner internal constructor(
    private val knownSpywareArtifactsResolver: KnownSpywareArtifactsResolver,
    private val sharedStorageRoots: List<String>,
) {

    @Inject
    constructor(knownSpywareArtifactsResolver: KnownSpywareArtifactsResolver) :
        this(knownSpywareArtifactsResolver, SHARED_STORAGE_ROOTS)

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
        val attrs = Files.readAttributes(Paths.get(path), BasicFileAttributes::class.java)
        FileArtifactTelemetry(
            filePath = path,
            fileExists = true,
            fileSize = attrs.size(),
            fileModified = attrs.lastModifiedTime().toMillis(),
            source = TelemetrySource.LIVE_SCAN,
            accessible = true,
        )
    } catch (expected: NoSuchFileException) {
        if (isOnSharedStorage(path) && File(path).parentFile?.canRead() != true) {
            // Shared storage answers "no such file" for what it hides from this app, so
            // the answer is only a real check when the folder can be listed.
            unreadable(path)
        } else {
            // The lookup ran and the system answered: nothing by that name.
            checkedAbsent(path)
        }
    } catch (e: Exception) {
        // Permission denied, SecurityException or any other refusal: record that we could not look.
        Log.d(TAG, "Cannot access $path: ${e.message}")
        unreadable(path)
    }

    private fun isOnSharedStorage(path: String) =
        sharedStorageRoots.any { root -> path == root || path.startsWith(root.trimEnd('/') + "/") }

    /** A path the system said does not exist: a completed check that found nothing. */
    private fun checkedAbsent(path: String) = FileArtifactTelemetry(
        filePath = path,
        fileExists = false,
        fileSize = null,
        fileModified = null,
        source = TelemetrySource.LIVE_SCAN,
        accessible = true,
    )

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

        /**
         * Shared (external) storage, where per-app visibility filtering answers "no such
         * file" for files it hides. `/sdcard` and `/mnt/user` are aliases of `/storage`.
         * These prefixes only classify paths; nothing is opened through them.
         */
        @SuppressLint("SdCardPath")
        private val SHARED_STORAGE_ROOTS = listOf("/storage", "/sdcard", "/mnt")
    }
}

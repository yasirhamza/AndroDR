package com.androdr.scanner

import android.os.Environment
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import java.io.File

class FileArtifactScannerTest {

    private lateinit var scanner: FileArtifactScanner

    // The number of IOC paths declared in FileArtifactScanner.knownArtifactPaths
    // ("/data/local/tmp/.raptor", "/data/local/tmp/.stat",
    //  "/data/local/tmp/.mobilesoftwareupdate",
    //  "$extStorage/.hidden_config", "$extStorage/Android/data/.system_update")
    private val knownPathCount = 5

    @Before
    fun setUp() {
        // Environment.getExternalStorageDirectory() is a static Android API that
        // returns null on the test JVM; mock it to return a predictable path so
        // the lazy knownArtifactPaths list initialises cleanly.
        mockkStatic(Environment::class)
        every { Environment.getExternalStorageDirectory() } returns File("/sdcard")

        scanner = FileArtifactScanner()
    }

    @After
    fun tearDown() {
        unmockkStatic(Environment::class)
    }

    // ── 1. Returns entries for all known paths ───────────────────────────────

    @Test
    fun `returns entries for all known paths`() = runTest {
        val result = scanner.collectTelemetry()

        assertEquals(
            "Expected one entry per known artifact path",
            knownPathCount,
            result.size
        )
    }

    // ── 2. Non-existent path returns fileExists false ────────────────────────

    @Test
    fun `non-existent path returns fileExists false`() = runTest {
        val result = scanner.collectTelemetry()

        // On the test JVM (not a rooted Android device) none of the IOC paths
        // exist, so every entry should have fileExists = false.
        result.forEach { telemetry ->
            assertFalse(
                "Expected fileExists = false for non-existent path: ${telemetry.filePath}",
                telemetry.fileExists
            )
        }
    }

    // ── 3. All entries have correct source metadata ──────────────────────────

    @Test
    fun `all entries have correct source metadata`() = runTest {
        val result = scanner.collectTelemetry()

        result.forEach { telemetry ->
            // filePath must be a non-blank absolute path
            assertNotNull("filePath must not be null", telemetry.filePath)
            assertFalse("filePath must not be blank", telemetry.filePath.isBlank())
            assert(telemetry.filePath.startsWith("/")) {
                "filePath must be absolute, was: ${telemetry.filePath}"
            }

            // For non-existent files, size and modified time must be null
            if (!telemetry.fileExists) {
                assertEquals(
                    "fileSize must be null when file does not exist",
                    null,
                    telemetry.fileSize
                )
                assertEquals(
                    "fileModified must be null when file does not exist",
                    null,
                    telemetry.fileModified
                )
            }
        }
    }
}

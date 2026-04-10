package com.androdr.scanner

import com.androdr.ioc.KnownSpywareArtifactsResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

class FileArtifactScannerTest {

    private lateinit var scanner: FileArtifactScanner

    // Mirrors the 5 paths historically hardcoded in FileArtifactScanner.kt before the
    // migration to known_spyware_artifacts.yml. The scanner no longer owns this list —
    // it delegates to KnownSpywareArtifactsResolver, which we mock here.
    private val fakePaths = listOf(
        "/data/local/tmp/.raptor",
        "/data/local/tmp/.stat",
        "/data/local/tmp/.mobilesoftwareupdate",
        "/sdcard/.hidden_config",
        "/sdcard/Android/data/.system_update",
    )

    @Before
    fun setUp() {
        val resolver = mockk<KnownSpywareArtifactsResolver>()
        every { resolver.paths } returns fakePaths
        scanner = FileArtifactScanner(resolver)
    }

    // ── 1. Only accessible paths produce telemetry ──────────────────────────

    @Test
    fun `only accessible paths produce telemetry`() = runTest {
        val result = scanner.collectTelemetry()

        // Count how many fake paths have a readable parent directory on this JVM
        val accessibleCount = fakePaths.count { path ->
            File(path).parentFile?.canRead() ?: false
        }

        assertEquals(
            "Expected one entry per accessible resolver path",
            accessibleCount,
            result.size
        )

        // Every returned entry must have accessible = true
        result.forEach { telemetry ->
            assertTrue(
                "Returned telemetry must have accessible = true",
                telemetry.accessible
            )
        }
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

    // ── 4. Inaccessible paths are skipped entirely ──────────────────────────

    @Test
    fun `inaccessible paths are skipped entirely`() = runTest {
        val result = scanner.collectTelemetry()

        // Verify that no returned path has an unreadable parent
        result.forEach { telemetry ->
            val parentReadable = File(telemetry.filePath).parentFile?.canRead() ?: false
            assertTrue(
                "Returned path ${telemetry.filePath} should have a readable parent",
                parentReadable
            )
        }
    }
}

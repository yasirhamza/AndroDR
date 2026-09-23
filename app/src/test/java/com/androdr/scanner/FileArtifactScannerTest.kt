package com.androdr.scanner

import com.androdr.ioc.KnownSpywareArtifactsResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * The artifact scanner probes known implant paths. Almost none of them are
 * readable by an unprivileged app, and it used to drop those paths silently:
 * the scan produced no telemetry, the CRITICAL artifact rule was never
 * evaluated, and the report was indistinguishable from a device that had been
 * checked and found clean (#366).
 *
 * The contract pinned here is that the scanner reports **one row per path,
 * always**, and says which of them it could not read. Curation belongs to the
 * rules and to the report, never to an emitter that quietly shortens its own
 * evidence.
 */
class FileArtifactScannerTest {

    /** Paths whose parent no unprivileged process can read (nor this JVM). */
    private val unreadablePaths = listOf(
        "/data/local/tmp/.raptor",
        "/data/local/tmp/.stat",
        "/sdcard/.hidden_config",
    )

    private fun scannerFor(paths: List<String>): FileArtifactScanner {
        val resolver = mockk<KnownSpywareArtifactsResolver>()
        every { resolver.paths } returns paths
        return FileArtifactScanner(resolver)
    }

    @Test
    fun `every known path produces exactly one row, readable or not`() = runTest {
        val readableDir = Files.createTempDirectory("artifacts").toFile()
        val absent = File(readableDir, "absent-artifact").absolutePath
        val paths = unreadablePaths + absent

        val result = scannerFor(paths).collectTelemetry()

        assertEquals("one row per probed path", paths.size, result.size)
        assertEquals(paths.toSet(), result.map { it.filePath }.toSet())
    }

    @Test
    fun `a path the app cannot read is reported as inaccessible, not dropped`() = runTest {
        val result = scannerFor(unreadablePaths).collectTelemetry()

        assertEquals(unreadablePaths.size, result.size)
        result.forEach { telemetry ->
            assertFalse("${telemetry.filePath} must be marked inaccessible", telemetry.accessible)
        }
    }

    @Test
    fun `an inaccessible path is never claimed to be absent`() = runTest {
        // fileExists = false on an unreadable path means "we could not look",
        // which only `accessible` can distinguish from "we looked and it is gone".
        val result = scannerFor(unreadablePaths).collectTelemetry()

        assertEquals(unreadablePaths.size, result.size)
        result.forEach { telemetry ->
            assertFalse(telemetry.fileExists)
            assertFalse(telemetry.accessible)
            assertNull(telemetry.fileSize)
            assertNull(telemetry.fileModified)
        }
    }

    @Test
    fun `a readable path that holds nothing is a real negative`() = runTest {
        val readableDir = Files.createTempDirectory("artifacts").toFile()
        val absent = File(readableDir, "absent-artifact").absolutePath

        val telemetry = scannerFor(listOf(absent)).collectTelemetry().single()

        assertTrue("a readable parent means the check actually ran", telemetry.accessible)
        assertFalse(telemetry.fileExists)
        assertNull(telemetry.fileSize)
        assertNull(telemetry.fileModified)
    }

    @Test
    fun `a readable path that holds an artifact keeps its metadata`() = runTest {
        val readableDir = Files.createTempDirectory("artifacts").toFile()
        val planted = File(readableDir, ".raptor").apply { writeText("implant") }

        val telemetry = scannerFor(listOf(planted.absolutePath)).collectTelemetry().single()

        assertTrue(telemetry.accessible)
        assertTrue(telemetry.fileExists)
        assertEquals(planted.length(), telemetry.fileSize)
        assertNotNull(telemetry.fileModified)
    }

    @Test
    fun `paths keep their absolute form`() = runTest {
        val result = scannerFor(unreadablePaths).collectTelemetry()

        assertEquals(unreadablePaths.size, result.size)
        result.forEach { telemetry ->
            assertTrue("expected an absolute path: ${telemetry.filePath}", telemetry.filePath.startsWith("/"))
        }
    }
}

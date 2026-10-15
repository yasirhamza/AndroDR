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
import org.junit.After
import org.junit.Assume.assumeFalse
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

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
 *
 * A parent the app may search but not list (`/data/local/tmp` is `rwxrwx--x`)
 * still answers a lookup of an exact name, so the scanner must look rather than
 * give up because the folder cannot be listed (#387). The fixtures build that
 * permission shape in a temp folder so the tests do not depend on the host.
 */
class FileArtifactScannerTest {

    /** A folder with no permissions at all: even an exact-name lookup is refused. */
    private lateinit var lockedDir: File

    /** Paths inside [lockedDir], which this JVM cannot look up. */
    private lateinit var unreadablePaths: List<String>

    /** Folders whose permissions a test removed, restored afterwards so they can be deleted. */
    private val restricted = mutableListOf<File>()

    @Before
    fun lockAFolder() {
        lockedDir = Files.createTempDirectory("locked").toFile()
        File(lockedDir, ".raptor").writeText("implant")
        unreadablePaths = listOf(".raptor", ".stat", ".hidden_config").map { File(lockedDir, it).absolutePath }
        restrict(lockedDir, "---------")
        // root ignores permission bits, so the "refused" shape cannot be built.
        assumeFalse("running as root: permissions are not enforced", File(lockedDir, ".raptor").exists())
    }

    private fun restrict(dir: File, mode: String) {
        Files.setPosixFilePermissions(dir.toPath(), PosixFilePermissions.fromString(mode))
        restricted += dir
    }

    /** A search-only folder inside its own temp "shared storage" root, like `Android/data`. */
    private fun hiddenSharedDir(): File {
        val sharedRoot = Files.createTempDirectory("shared-root").toFile()
        val hiddenDir = File(sharedRoot, "Android-data").apply { mkdir() }
        restrict(hiddenDir, "--x------")
        assumeFalse("running as root: permissions are not enforced", hiddenDir.canRead())
        return hiddenDir
    }

    @After
    fun restorePermissions() {
        restricted.forEach { dir ->
            Files.setPosixFilePermissions(dir.toPath(), PosixFilePermissions.fromString("rwx------"))
            dir.deleteRecursively()
        }
    }

    /** A folder its owner may search but not list: the shape of `/data/local/tmp` for an app. */
    private fun searchOnlyDir(vararg planted: String): File {
        val dir = Files.createTempDirectory("search-only").toFile()
        planted.forEach { File(dir, it).writeText("implant") }
        restrict(dir, "--x------")
        assumeFalse("running as root: permissions are not enforced", dir.canRead())
        return dir
    }

    private fun scannerFor(
        paths: List<String>,
        sharedStorageRoots: List<String> = emptyList(),
    ): FileArtifactScanner {
        val resolver = mockk<KnownSpywareArtifactsResolver>()
        every { resolver.paths } returns paths
        return FileArtifactScanner(resolver, sharedStorageRoots)
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

    @Test
    fun `a planted artifact under a folder the app cannot list is still found`() = runTest {
        val dir = searchOnlyDir(".raptor")
        val planted = File(dir, ".raptor").absolutePath

        val telemetry = scannerFor(listOf(planted)).collectTelemetry().single()

        assertTrue("an exact-name lookup through a search-only folder is a real check", telemetry.accessible)
        assertTrue("the planted artifact must be found", telemetry.fileExists)
        assertEquals("implant".length.toLong(), telemetry.fileSize)
        assertNotNull(telemetry.fileModified)
    }

    @Test
    fun `an absent artifact under a folder the app cannot list is a real negative`() = runTest {
        val dir = searchOnlyDir()
        val absent = File(dir, ".stat").absolutePath

        val telemetry = scannerFor(listOf(absent)).collectTelemetry().single()

        assertTrue("the lookup ran and the system said the name does not exist", telemetry.accessible)
        assertFalse(telemetry.fileExists)
        assertNull(telemetry.fileSize)
        assertNull(telemetry.fileModified)
    }

    @Test
    fun `a missing folder on the way to the artifact is a real negative`() = runTest {
        val dir = searchOnlyDir()
        val absent = File(dir, "wd/fs.db").absolutePath

        val telemetry = scannerFor(listOf(absent)).collectTelemetry().single()

        assertTrue(telemetry.accessible)
        assertFalse(telemetry.fileExists)
    }

    @Test
    fun `on shared storage, no such file under a folder the app cannot list is not a negative`() = runTest {
        // Shared storage answers "no such file" for whatever it hides from this app:
        // a file planted in /sdcard/Android/data/ reads as absent on Android 17 (#387).
        // Only a folder the app can list makes that answer trustworthy there.
        val dir = searchOnlyDir()
        val hidden = File(dir, ".system_update").absolutePath

        val telemetry = scannerFor(listOf(hidden), sharedStorageRoots = listOf(dir.parent))
            .collectTelemetry().single()

        assertFalse("a hidden answer must not be reported as a completed check", telemetry.accessible)
        assertFalse(telemetry.fileExists)
    }

    @Test
    fun `on shared storage, a listable folder still gives a real negative`() = runTest {
        val readableDir = Files.createTempDirectory("shared").toFile()
        val absent = File(readableDir, ".hidden_config").absolutePath

        val telemetry = scannerFor(listOf(absent), sharedStorageRoots = listOf(readableDir.parent))
            .collectTelemetry().single()

        assertTrue(telemetry.accessible)
        assertFalse(telemetry.fileExists)
    }

    @Test
    fun `on shared storage, a file found under a folder the app cannot list is still found`() = runTest {
        val dir = searchOnlyDir(".system_update")
        val planted = File(dir, ".system_update").absolutePath

        val telemetry = scannerFor(listOf(planted), sharedStorageRoots = listOf(dir.parent))
            .collectTelemetry().single()

        assertTrue(telemetry.accessible)
        assertTrue(telemetry.fileExists)
    }

    @Test
    fun `a path that climbs into shared storage with dot-dot is still guarded`() = runTest {
        val hiddenDir = hiddenSharedDir()
        val sharedRoot = hiddenDir.parentFile
        val elsewhere = Files.createTempDirectory("elsewhere").toFile()
        // Written as <elsewhere>/../<shared-root>/<hidden>/x: the text does not start with
        // the shared root, but the path the kernel resolves does.
        val climbing = "${elsewhere.absolutePath}/../${sharedRoot.name}/${hiddenDir.name}/.system_update"

        val telemetry = scannerFor(listOf(climbing), sharedStorageRoots = listOf(sharedRoot.absolutePath))
            .collectTelemetry().single()

        assertFalse("the guard must classify the path the kernel resolves", telemetry.accessible)
    }

    @Test
    fun `a path that reaches shared storage through a symlink is still guarded`() = runTest {
        val hiddenDir = hiddenSharedDir()
        val sharedRoot = hiddenDir.parentFile
        val link = Files.createTempDirectory("elsewhere").resolve("link")
        Files.createSymbolicLink(link, hiddenDir.toPath())

        val telemetry = scannerFor(listOf("$link/.system_update"), sharedStorageRoots = listOf(sharedRoot.absolutePath))
            .collectTelemetry().single()

        assertFalse("a symlink into shared storage must not escape the guard", telemetry.accessible)
    }

    @Test
    fun `a sibling that merely shares a name prefix is not shared storage`() = runTest {
        val dir = searchOnlyDir()
        val absent = File(dir, ".stat").absolutePath

        val telemetry = scannerFor(listOf(absent), sharedStorageRoots = listOf(dir.absolutePath.dropLast(1)))
            .collectTelemetry().single()

        assertTrue("prefixes match whole path components only", telemetry.accessible)
    }
}

package com.androdr.scanner

import android.net.Uri
import android.os.StatFs
import com.androdr.data.store.Preflight
import com.androdr.data.store.StoragePreflight
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * A7c I6: the import size comes from the ZIP central directory, read through the descriptor the provider
 * handed out (no path reopen). Pins the parser (plain, ZIP64, malformed) and the ContentResolver channel.
 */
@RunWith(RobolectricTestRunner::class)
class ZipCentralDirectoryTest {

    @get:Rule val tmp = TemporaryFolder()

    private fun zip(vararg sizes: Int): File = tmp.newFile().also { f ->
        ZipOutputStream(f.outputStream()).use { z ->
            sizes.forEachIndexed { i, n ->
                z.putNextEntry(ZipEntry("e$i.txt"))
                z.write(ByteArray(n) { 'a'.code.toByte() })
                z.closeEntry()
            }
        }
    }

    /** A zip of named entries, each [bytes] of zeros (deflates to almost nothing). */
    private fun namedZip(bytes: Long, vararg names: String): File = tmp.newFile().also { f ->
        val chunk = ByteArray(1 shl 20)
        ZipOutputStream(f.outputStream()).use { z ->
            for (name in names) {
                z.putNextEntry(ZipEntry(name))
                var left = bytes
                while (left > 0) {
                    val n = minOf(left, chunk.size.toLong()).toInt()
                    z.write(chunk, 0, n)
                    left -= n
                }
                z.closeEntry()
            }
        }
    }

    private fun sizeOf(f: File): Long? = RandomAccessFile(f, "r").use { ZipCentralDirectory.totalSize(it.channel) }

    @Test
    fun `sums the uncompressed sizes of a real archive`() {
        assertEquals(1_000L + 25_000L + 0L, sizeOf(zip(1_000, 25_000, 0)))
    }

    @Test
    fun `an empty archive is zero bytes`() {
        assertEquals(0L, sizeOf(zip()))
    }

    @Test
    fun `garbage, a truncated archive and a tiny file give no estimate and do not throw`() {
        assertNull(sizeOf(tmp.newFile().also { it.writeBytes(ByteArray(5_000) { 7 }) }))
        assertNull(sizeOf(tmp.newFile().also { it.writeBytes(ByteArray(3)) }))
        val whole = zip(100, 200).readBytes()
        assertNull(sizeOf(tmp.newFile().also { it.writeBytes(whole.copyOf(whole.size - 30)) }))
    }

    @Test
    fun `a directory that claims to be larger than the file is rejected`() {
        val b = zip(10).readBytes()
        val eocd = b.size - 22
        ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).putInt(eocd + 12, 0x7FFFFFFF)
        assertNull(sizeOf(tmp.newFile().also { it.writeBytes(b) }))
    }

    @Test
    fun `reads a ZIP64 archive whose entry is larger than 4 GiB`() {
        val big = 5L * 1024 * 1024 * 1024
        val name = "big.bin".toByteArray()
        val extra = ByteBuffer.allocate(4 + 16).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(1).putShort(16).putLong(big).putLong(big).array()
        val cd = ByteBuffer.allocate(46 + name.size + extra.size).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(0x02014b50).putShort(45).putShort(45).putShort(0).putShort(0).putInt(0).putInt(0)
            .putInt(-1).putInt(-1) // compressed, uncompressed: 0xFFFFFFFF (see extra)
            .putShort(name.size.toShort()).putShort(extra.size.toShort()).putShort(0).putShort(0)
            .putShort(0).putInt(0).putInt(0).put(name).put(extra).array()
        val head = ByteArray(10) // pretend local data before the directory
        val zip64Offset = (head.size + cd.size).toLong()
        val rec = ByteBuffer.allocate(56).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(0x06064b50).putLong(44).putShort(45).putShort(45).putInt(0).putInt(0)
            .putLong(1).putLong(1).putLong(cd.size.toLong()).putLong(head.size.toLong()).array()
        val loc = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(0x07064b50).putInt(0).putLong(zip64Offset).putInt(1).array()
        val eocd = ByteBuffer.allocate(22).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(0x06054b50).putShort(0).putShort(0).putShort(-1).putShort(-1).putInt(-1).putInt(-1)
            .putShort(0).array()
        val f = tmp.newFile().also { it.writeBytes(head + cd + rec + loc + eocd) }
        assertEquals(big, sizeOf(f))
    }

    // ---- through the ContentResolver / ParcelFileDescriptor channel ----

    private fun preflight(free: Long) = ImportPreflight(
        RuntimeEnvironment.getApplication(),
        StoragePreflight { mockk<StatFs> { every { availableBytes } returns free } },
    )

    @Test
    fun `check reads the size through the content resolver descriptor`() = runBlocking {
        val f = zip(1_000_000)
        val uri = Uri.fromFile(f)
        assertEquals(Preflight.Ok, preflight(free = 100L shl 30).check(uri))
        val tight = preflight(free = 150L shl 20).check(uri) as Preflight.Tight
        assertEquals("an unrecognized archive is estimated at the largest factor", 4_000_000L, tight.estimate)
    }

    // ---- battery B5, ruling R45: the stored-size factor is per artifact type ----

    @Test
    fun `the stored-size factor is per artifact type`() {
        assertEquals(0.05, ImportPreflight.storedSizeFactor(ArtifactType.BUG_REPORT), 0.0)
        assertEquals(4.0, ImportPreflight.storedSizeFactor(ArtifactType.INTRUSION_LOG), 0.0)
        assertEquals("unknown type: the conservative factor", 4.0,
            ImportPreflight.storedSizeFactor(ArtifactType.UNRECOGNIZED), 0.0)
    }

    @Test
    fun `the central directory names give the artifact type`() {
        fun contentsOf(f: File) = RandomAccessFile(f, "r").use { ZipCentralDirectory.contents(it.channel) }
        val br = contentsOf(namedZip(10, "dumpstate_board.txt", "dumpstate-2026-10-29-08-18-37.txt"))
        assertEquals(ZipCentralDirectory.Contents(20L, ArtifactType.BUG_REPORT), br)
        val il = contentsOf(namedZip(10, "intrusion-logs/2026-10-01.txt", "intrusion-logs/2026-10-01(1).txt"))
        assertEquals(ZipCentralDirectory.Contents(20L, ArtifactType.INTRUSION_LOG), il)
        assertEquals(ArtifactType.UNRECOGNIZED, contentsOf(namedZip(10, "photo.jpg"))?.type)
    }

    @Test
    fun `a 100 MB bug report on 1 GB free is Ok, a 100 MB intrusion log is Tight`() = runBlocking {
        val hundredMb = 100L shl 20
        val gb = 1L shl 30
        val bugReport = Uri.fromFile(namedZip(hundredMb, "dumpstate-2026-10-29-08-18-37.txt"))
        assertEquals(Preflight.Ok, preflight(free = gb).check(bugReport))
        val intrusionLog = Uri.fromFile(namedZip(hundredMb, "2026-10-01.txt"))
        assertEquals(Preflight.Tight(hundredMb * 4, gb), preflight(free = gb).check(intrusionLog))
    }

    /**
     * #418: a ZIP whose central directory names a dumpstate while its local headers hold a per-day log.
     * The preflight sized it as a bug report (factor 0.05) while the analyzer, sniffing the stream,
     * ran the intrusion-log import (4.0). Routing by the directory alone was worse (review): the
     * analyzers read the local headers, so the bug-report analyzer found nothing and the import
     * "succeeded" clean. An archive whose two name lists disagree is rejected as unrecognized.
     */
    @Test
    fun `a zip whose central directory and local headers disagree is rejected`() = runBlocking {
        val local = "a/2026-10-01.txt"
        val central = "dumpstate-ab.txt"
        check(local.length == central.length)
        val f = namedZip(1_000, local)
        val bytes = f.readBytes()
        val name = local.toByteArray()
        val at = (bytes.size - name.size downTo 0).first { i -> name.indices.all { bytes[i + it] == name[it] } }
        central.toByteArray().copyInto(bytes, at) // the last copy of the name is the central directory's
        f.writeBytes(bytes)
        val uri = Uri.fromFile(f)
        val app = RuntimeEnvironment.getApplication()

        val streamSniff = f.inputStream().use { ArtifactSniffer.classifyZip(it).type }
        assertEquals("precondition: the two name lists disagree", ArtifactType.INTRUSION_LOG, streamSniff)
        assertEquals(ArtifactType.BUG_REPORT,
            RandomAccessFile(f, "r").use { ZipCentralDirectory.contents(it.channel) }?.type)
        assertEquals(ArtifactType.UNRECOGNIZED, ImportArchive.type(app, uri))
    }

    @Test
    fun `a consistent zip is routed by its type`() = runBlocking {
        val app = RuntimeEnvironment.getApplication()
        assertEquals(ArtifactType.INTRUSION_LOG,
            ImportArchive.type(app, Uri.fromFile(namedZip(1_000, "a/2026-10-01.txt"))))
        assertEquals(ArtifactType.BUG_REPORT,
            ImportArchive.type(app, Uri.fromFile(namedZip(1_000, "dumpstate-2026-10-29-08-18-37.txt"))))
    }

    @Test
    fun `source gate - the analyzer is routed by the preflight's classification`() {
        val src = listOf(File("src/main/java"), File("app/src/main/java")).first { it.isDirectory }
            .resolve("com/androdr/scanner/ScanOrchestrator.kt").readText()
        val sniff = src.substringAfter("private suspend fun sniffArtifact").substringBefore("\n    /**")
        assertTrue(sniff, sniff.contains("ImportArchive.type(context, uri)"))
        assertTrue("the orchestrator must not classify on its own", !src.contains("ArtifactSniffer.classifyZip"))
    }

    @Test
    fun `check gives an unknown size for an unreadable file`() = runBlocking {
        val garbage = tmp.newFile().also { it.writeBytes(ByteArray(1_000) { 1 }) }
        assertNull((preflight(100L shl 30).check(Uri.fromFile(garbage)) as Preflight.Tight).estimate)
        val missing = Uri.fromFile(File(tmp.root, "missing.zip"))
        assertNull((preflight(100L shl 30).check(missing) as Preflight.Tight).estimate)
    }

    @Test
    fun `an out-of-memory while reading a forged directory gives no estimate`() {
        val ch = mockk<java.nio.channels.FileChannel> { every { size() } throws OutOfMemoryError() }
        assertNull(ZipCentralDirectory.totalSize(ch))
    }

    @Test
    fun `source gate - the preflight never reopens a path and closes its stream`() {
        val src = File("src/main/java/com/androdr/scanner/ImportArchive.kt").readText()
        assertTrue(!src.contains("/proc/self/fd"))
        assertTrue(!src.contains("ZipFile("))
        assertTrue(src.contains("openFileDescriptor"))
        assertTrue(src.contains("FileInputStream(pfd.fileDescriptor).use"))
    }
}

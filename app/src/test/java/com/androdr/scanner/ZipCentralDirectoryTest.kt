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
        assertEquals("estimate is 0.6 x the summed size", 600_000L, tight.estimate)
    }

    @Test
    fun `check gives an unknown size for an unreadable file`() = runBlocking {
        val garbage = tmp.newFile().also { it.writeBytes(ByteArray(1_000) { 1 }) }
        assertNull((preflight(100L shl 30).check(Uri.fromFile(garbage)) as Preflight.Tight).estimate)
        val missing = Uri.fromFile(File(tmp.root, "missing.zip"))
        assertNull((preflight(100L shl 30).check(missing) as Preflight.Tight).estimate)
    }

    @Test
    fun `source gate - the preflight never reopens a path`() {
        val src = File("src/main/java/com/androdr/scanner/ImportPreflight.kt").readText()
        assertTrue(!src.contains("/proc/self/fd"))
        assertTrue(!src.contains("ZipFile("))
        assertTrue(src.contains("openFileDescriptor"))
    }
}

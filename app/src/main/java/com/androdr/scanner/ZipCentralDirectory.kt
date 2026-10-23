package com.androdr.scanner

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel

/**
 * Reads the summed uncompressed entry sizes of a ZIP from its central directory through a channel the
 * caller already holds (no path is reopened, nothing is inflated). Bounded: the directory is read only
 * if it fits inside the file and within [MAX_DIRECTORY_BYTES], and at most [MAX_ENTRIES] entries are
 * walked. Any malformed structure yields null.
 */
@Suppress("ReturnCount") // each early return is a distinct "not a readable ZIP" check
object ZipCentralDirectory {
    const val MAX_DIRECTORY_BYTES = 64L * 1024 * 1024
    const val MAX_ENTRIES = 1_000_000L

    private const val EOCD_SIG = 0x06054b50
    private const val EOCD_MIN = 22
    private const val MAX_COMMENT = 65_535
    private const val ZIP64_LOCATOR_SIG = 0x07064b50
    private const val ZIP64_LOCATOR_SIZE = 20
    private const val ZIP64_EOCD_SIG = 0x06064b50
    private const val ZIP64_EOCD_MIN = 56
    private const val CD_SIG = 0x02014b50
    private const val CD_FIXED = 46
    private const val ZIP64_EXTRA_ID = 0x0001
    private const val U32_MAX = 0xFFFFFFFFL
    private const val U16_MAX = 0xFFFF

    /** Sum of uncompressed sizes, or null when the structure is not a readable ZIP. */
    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    fun totalSize(channel: FileChannel): Long? = try {
        parse(channel)
    } catch (e: java.io.IOException) {
        null
    } catch (e: RuntimeException) {
        null // buffer under/overflow on a malformed directory
    }

    private fun parse(ch: FileChannel): Long? {
        val fileSize = ch.size()
        if (fileSize < EOCD_MIN) return null
        val tailLen = minOf(fileSize, (EOCD_MIN + MAX_COMMENT).toLong()).toInt()
        val tail = readAt(ch, fileSize - tailLen, tailLen) ?: return null
        val eocd = findEocd(tail) ?: return null
        var entries = (tail.getShort(eocd + 10).toInt() and U16_MAX).toLong()
        var cdSize = tail.getInt(eocd + 12).toLong() and U32_MAX
        var cdOffset = tail.getInt(eocd + 16).toLong() and U32_MAX
        if (entries == U16_MAX.toLong() || cdSize == U32_MAX || cdOffset == U32_MAX) {
            val z = zip64Fields(ch, tail, eocd, fileSize) ?: return null
            entries = z[0]; cdSize = z[1]; cdOffset = z[2]
        }
        if (entries !in 0..MAX_ENTRIES || cdSize !in 0..MAX_DIRECTORY_BYTES) return null
        if (cdOffset < 0 || cdOffset + cdSize > fileSize) return null
        val cd = readAt(ch, cdOffset, cdSize.toInt()) ?: return null
        return sumEntries(cd, entries)
    }

    private fun findEocd(tail: ByteBuffer): Int? {
        for (i in tail.limit() - EOCD_MIN downTo 0) {
            if (tail.getInt(i) == EOCD_SIG) return i
        }
        return null
    }

    /** [entries, cdSize, cdOffset] from the ZIP64 end record, or null. */
    private fun zip64Fields(ch: FileChannel, tail: ByteBuffer, eocd: Int, fileSize: Long): LongArray? {
        val loc = eocd - ZIP64_LOCATOR_SIZE
        if (loc < 0 || tail.getInt(loc) != ZIP64_LOCATOR_SIG) return null
        val recordOffset = tail.getLong(loc + 8)
        if (recordOffset < 0 || recordOffset + ZIP64_EOCD_MIN > fileSize) return null
        val rec = readAt(ch, recordOffset, ZIP64_EOCD_MIN) ?: return null
        if (rec.getInt(0) != ZIP64_EOCD_SIG) return null
        return longArrayOf(rec.getLong(32), rec.getLong(40), rec.getLong(48))
    }

    private fun sumEntries(cd: ByteBuffer, entries: Long): Long? {
        var pos = 0
        var total = 0L
        repeat(entries.toInt()) {
            if (pos + CD_FIXED > cd.limit() || cd.getInt(pos) != CD_SIG) return null
            var size = cd.getInt(pos + 24).toLong() and U32_MAX
            val nameLen = cd.getShort(pos + 28).toInt() and U16_MAX
            val extraLen = cd.getShort(pos + 30).toInt() and U16_MAX
            val commentLen = cd.getShort(pos + 32).toInt() and U16_MAX
            val extraStart = pos + CD_FIXED + nameLen
            if (size == U32_MAX) size = zip64Size(cd, extraStart, extraLen) ?: return null
            total += size
            if (total < 0) return null
            pos = extraStart + extraLen + commentLen
        }
        return total
    }

    /** The uncompressed size from the ZIP64 extra field (it is the field's first value). */
    private fun zip64Size(cd: ByteBuffer, start: Int, len: Int): Long? {
        var p = start
        val end = start + len
        while (p + 4 <= end && end <= cd.limit()) {
            val id = cd.getShort(p).toInt() and U16_MAX
            val dataLen = cd.getShort(p + 2).toInt() and U16_MAX
            if (id == ZIP64_EXTRA_ID) {
                return if (dataLen >= 8 && p + 12 <= end) cd.getLong(p + 4).takeIf { it >= 0 } else null
            }
            p += 4 + dataLen
        }
        return null
    }

    private fun readAt(ch: FileChannel, position: Long, length: Int): ByteBuffer? {
        val buf = ByteBuffer.allocate(length).order(ByteOrder.LITTLE_ENDIAN)
        var at = position
        while (buf.hasRemaining()) {
            val n = ch.read(buf, at)
            if (n < 0) return null
            at += n
        }
        buf.flip()
        return buf
    }
}

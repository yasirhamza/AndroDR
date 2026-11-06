package com.androdr.privacy

import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.CRC32
import java.util.zip.Deflater
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Test helper that emits valid (or deliberately broken) dex files and APK zips. */
object SyntheticDex {

    private const val HEADER_SIZE = 0x70

    fun uleb(value: Int): ByteArray {
        val out = ByteArrayOutputStream()
        var v = value
        do {
            var b = v and 0x7F
            v = v ushr 7
            if (v != 0) b = b or 0x80
            out.write(b)
        } while (v != 0)
        return out.toByteArray()
    }

    fun mutf8(s: String): ByteArray {
        val out = ByteArrayOutputStream()
        for (c in s) {
            val code = c.code
            when {
                code == 0 -> {
                    out.write(0xC0)
                    out.write(0x80)
                }
                code < 0x80 -> out.write(code)
                code < 0x800 -> {
                    out.write(0xC0 or (code shr 6))
                    out.write(0x80 or (code and 0x3F))
                }
                else -> {
                    out.write(0xE0 or (code shr 12))
                    out.write(0x80 or ((code shr 6) and 0x3F))
                    out.write(0x80 or (code and 0x3F))
                }
            }
        }
        return out.toByteArray()
    }

    /** string_data_item for [s]: uleb128 utf16 length, MUTF-8 bytes, NUL. */
    fun stringData(s: String): ByteArray = uleb(s.length) + mutf8(s) + byteArrayOf(0)

    /** A valid dex whose type_ids name [descriptors] (one string + one type each). */
    fun dex(descriptors: List<String>, version: String = "035"): ByteArray {
        val data = ByteArrayOutputStream()
        val offs = ArrayList<Int>()
        for (d in descriptors) {
            offs.add(data.size())
            data.write(stringData(d))
        }
        return assemble(data.toByteArray(), offs, descriptors.indices.toList(), version)
    }

    /**
     * Low-level builder: [stringOffsets] are relative to the start of [data]; [typeIdxs] are
     * descriptor_idx values. Header counts/offsets can be overridden to craft broken dex files.
     */
    @Suppress("LongParameterList")
    fun assemble(
        data: ByteArray,
        stringOffsets: List<Int>,
        typeIdxs: List<Int>,
        version: String = "035",
        stringIdsSize: Long = stringOffsets.size.toLong(),
        stringIdsOff: Long = HEADER_SIZE.toLong(),
        typeIdsSize: Long = typeIdxs.size.toLong(),
    ): ByteArray {
        val sTable = HEADER_SIZE
        val tTable = sTable + 4 * stringOffsets.size
        val dataStart = tTable + 4 * typeIdxs.size
        val buf = ByteBuffer.allocate(dataStart + data.size).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(("dex\n$version").toByteArray(Charsets.US_ASCII))
        buf.put(0)
        buf.putInt(0x20, buf.capacity())
        buf.putInt(0x24, HEADER_SIZE)
        buf.putInt(0x28, 0x12345678)
        buf.putInt(0x38, stringIdsSize.toInt())
        buf.putInt(0x3C, stringIdsOff.toInt())
        buf.putInt(0x40, typeIdsSize.toInt())
        buf.putInt(0x44, tTable)
        stringOffsets.forEachIndexed { i, o -> buf.putInt(sTable + 4 * i, dataStart + o) }
        typeIdxs.forEachIndexed { i, idx -> buf.putInt(tTable + 4 * i, idx) }
        System.arraycopy(data, 0, buf.array(), dataStart, data.size)
        return buf.array()
    }

    fun apk(entries: Map<String, ByteArray>, stored: Boolean = true): File {
        val f = File.createTempFile("synthetic", ".apk")
        f.deleteOnExit()
        ZipOutputStream(f.outputStream()).use { zos ->
            for ((name, bytes) in entries) {
                val e = ZipEntry(name)
                if (stored) {
                    e.method = ZipEntry.STORED
                    e.size = bytes.size.toLong()
                    e.compressedSize = bytes.size.toLong()
                    e.crc = CRC32().also { it.update(bytes) }.value
                } else {
                    e.method = ZipEntry.DEFLATED
                }
                zos.putNextEntry(e)
                zos.write(bytes)
                zos.closeEntry()
            }
        }
        return f
    }

    private class Le(val out: ByteArrayOutputStream) {
        fun put(v: Long, n: Int) {
            for (i in 0 until n) out.write(((v shr (8 * i)) and 0xFF).toInt())
        }
    }

    private fun deflateRaw(raw: ByteArray): ByteArray {
        val deflater = Deflater(Deflater.BEST_COMPRESSION, true)
        deflater.setInput(raw)
        deflater.finish()
        val comp = ByteArrayOutputStream()
        val tmp = ByteArray(8192)
        while (!deflater.finished()) comp.write(tmp, 0, deflater.deflate(tmp))
        deflater.end()
        return comp.toByteArray()
    }

    /**
     * Hand-written zip: a deflated `classes.dex` of [realSize] zero bytes whose central directory
     * claims [declaredSize] uncompressed bytes. [declaredSize] == -1 writes an entry with a data
     * descriptor and no size in the central directory (unknown size).
     */
    fun bomb(declaredSize: Long, realSize: Int): File {
        val raw = ByteArray(realSize)
        val cdata = deflateRaw(raw)
        val crc = CRC32().also { it.update(raw) }.value
        val name = "classes.dex".toByteArray()
        val unknown = declaredSize < 0
        val flag = if (unknown) 8L else 0L
        val declared = if (unknown) 0L else declaredSize
        val localCrc = if (unknown) 0L else crc
        val localComp = if (unknown) 0L else cdata.size.toLong()

        val out = ByteArrayOutputStream()
        val le = Le(out)
        le.put(0x04034b50, 4); le.put(20, 2); le.put(flag, 2); le.put(8, 2); le.put(0, 2); le.put(0x21, 2)
        le.put(localCrc, 4); le.put(localComp, 4); le.put(declared, 4)
        le.put(name.size.toLong(), 2); le.put(0, 2)
        out.write(name)
        out.write(cdata)
        if (unknown) {
            le.put(0x08074b50, 4); le.put(crc, 4); le.put(cdata.size.toLong(), 4); le.put(realSize.toLong(), 4)
        }
        val cenStart = out.size()
        le.put(0x02014b50, 4); le.put(20, 2); le.put(20, 2); le.put(flag, 2); le.put(8, 2)
        le.put(0, 2); le.put(0x21, 2)
        le.put(crc, 4); le.put(cdata.size.toLong(), 4); le.put(declared, 4); le.put(name.size.toLong(), 2)
        le.put(0, 2); le.put(0, 2); le.put(0, 2); le.put(0, 2); le.put(0, 4); le.put(0, 4)
        out.write(name)
        val cenSize = out.size() - cenStart
        le.put(0x06054b50, 4); le.put(0, 2); le.put(0, 2); le.put(1, 2); le.put(1, 2)
        le.put(cenSize.toLong(), 4); le.put(cenStart.toLong(), 4); le.put(0, 2)
        val f = File.createTempFile("bomb", ".apk")
        f.deleteOnExit()
        f.writeBytes(out.toByteArray())
        return f
    }
}

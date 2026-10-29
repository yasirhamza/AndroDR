package com.androdr

import com.androdr.scanner.ZipCentralDirectory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.DataInputStream
import java.io.File
import java.util.zip.ZipFile

/**
 * `ByteBuffer.position(int)` (and `limit`, `flip`, `clear`, `mark`, `reset`, `rewind`) gained
 * covariant `ByteBuffer`-returning overrides in API 34 (Java 9). Code compiled to call one throws
 * `NoSuchMethodError` on API 26–33, an error no `catch (e: Exception)` sees (review E4 m1). App code
 * calls them through `java.nio.Buffer`; this gate reads every compiled app class's constant pool and
 * fails on a method reference to one of them whose return type is a concrete buffer type.
 */
class BufferCovariantCallGateTest {

    /** Every compiled app class (a directory or the runtime classes jar, by build), as name to bytes. */
    private fun appClasses(): List<Pair<String, ByteArray>> {
        val root = File(ZipCentralDirectory::class.java.protectionDomain.codeSource.location.toURI())
        return if (root.isDirectory) {
            root.walkTopDown().filter { it.isFile && it.name.endsWith(".class") }
                .map { it.relativeTo(root).path to it.readBytes() }.toList()
        } else {
            ZipFile(root).use { zip ->
                zip.entries().asSequence().filter { it.name.endsWith(".class") }
                    .map { e -> e.name to zip.getInputStream(e).use { it.readBytes() } }.toList()
            }
        }
    }

    @Test
    fun `no app class calls a covariant Buffer method`() {
        val classes = appClasses().filter { it.first.startsWith("com/androdr/") }
        assertTrue("app classes found: ${classes.size}", classes.size > 100)
        assertTrue(classes.any { it.first == "com/androdr/scanner/ZipCentralDirectory.class" })
        val hits = classes.flatMap { (name, bytes) -> covariantBufferCalls(bytes).map { "$name: $it" } }
        assertEquals(emptyList<String>(), hits)
    }

    @Test
    fun `the gate recognises the covariant form and spares the Buffer form`() {
        assertTrue(isCovariant("java/nio/ByteBuffer", "position", "(I)Ljava/nio/ByteBuffer;"))
        assertTrue(isCovariant("java/nio/CharBuffer", "flip", "()Ljava/nio/CharBuffer;"))
        assertTrue(!isCovariant("java/nio/ByteBuffer", "position", "(I)Ljava/nio/Buffer;"))
        assertTrue(!isCovariant("java/nio/Buffer", "position", "(I)Ljava/nio/Buffer;"))
        assertTrue("allocate legitimately returns ByteBuffer",
            !isCovariant("java/nio/ByteBuffer", "allocate", "(I)Ljava/nio/ByteBuffer;"))
    }

    @Test
    fun `the parser finds covariant calls in a class that makes them`() {
        // The JDK's own ByteBuffer calls its covariant overrides (it is compiled for Java 9+).
        val jdk = java.nio.ByteBuffer::class.java.getResourceAsStream("ByteBuffer.class")!!.use { it.readBytes() }
        assertTrue(covariantBufferCalls(jdk).isNotEmpty())
    }

    companion object {
        private val METHODS = setOf("position", "limit", "flip", "clear", "mark", "reset", "rewind")
        private val CONCRETE = Regex("""\)Ljava/nio/(Byte|Char|Short|Int|Long|Float|Double)Buffer;$""")

        fun isCovariant(owner: String, name: String, descriptor: String): Boolean =
            owner.startsWith("java/nio/") && name in METHODS && CONCRETE.containsMatchIn(descriptor)

        /** The covariant Buffer method references in one class file's constant pool. */
        @Suppress("MagicNumber", "CyclomaticComplexMethod")
        fun covariantBufferCalls(bytes: ByteArray): List<String> {
            val input = DataInputStream(bytes.inputStream())
            input.readInt(); input.readUnsignedShort(); input.readUnsignedShort() // magic, minor, major
            val count = input.readUnsignedShort()
            val utf = arrayOfNulls<String>(count)
            val classIdx = IntArray(count)
            val natName = IntArray(count)
            val natDesc = IntArray(count)
            val methodRefs = mutableListOf<Pair<Int, Int>>() // class index, name-and-type index
            var i = 1
            while (i < count) {
                when (val tag = input.readUnsignedByte()) {
                    1 -> utf[i] = input.readUTF()
                    7 -> classIdx[i] = input.readUnsignedShort()
                    12 -> { natName[i] = input.readUnsignedShort(); natDesc[i] = input.readUnsignedShort() }
                    10, 11 -> methodRefs += input.readUnsignedShort() to input.readUnsignedShort()
                    9, 3, 4, 17, 18 -> input.skipBytes(4)
                    5, 6 -> { input.skipBytes(8); i++ }
                    8, 16, 19, 20 -> input.skipBytes(2)
                    15 -> input.skipBytes(3)
                    else -> error("unknown constant pool tag $tag")
                }
                i++
            }
            return methodRefs.mapNotNull { (c, nat) ->
                val owner = utf[classIdx[c]] ?: return@mapNotNull null
                val name = utf[natName[nat]] ?: return@mapNotNull null
                val desc = utf[natDesc[nat]] ?: return@mapNotNull null
                "$owner.$name$desc".takeIf { isCovariant(owner, name, desc) }
            }
        }
    }
}

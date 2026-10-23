package com.androdr.data.store

import com.androdr.data.model.TelemetrySource
import com.androdr.sigma.TaxonomyContract
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.Base64
import java.util.zip.Adler32
import java.util.zip.Deflater

/** Gate S5: dictionary immutability and the zlib header check. */
class TelemetryDictionariesTest {

    private fun rawDir(): File = listOf(File("src/main/res/raw"), File("app/src/main/res/raw")).first { it.isDirectory }

    private fun loadDict(name: String): ByteArray = File(rawDir(), "$name.txt").readBytes()

    private val dicts = TelemetryDictionaries(::loadDict)
    private val codec = TelemetryRecordCodec(dicts)

    private fun sha256(b: ByteArray) =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    @Test fun `S5 every version's bytes match the pinned hash and fit 4 KiB`() {
        assertEquals(TelemetryDictionaries.VERSIONS.keys, TelemetryDictionaries.PINNED_SHA256.keys)
        for ((version, hash) in TelemetryDictionaries.PINNED_SHA256) {
            assertEquals(
                "dictionary v$version changed; add a new version instead", hash, sha256(dicts.byVersion(version))
            )
            assertTrue(dicts.byVersion(version).size <= 4096)
        }
    }

    @Test fun `S5 loading a dictionary with altered bytes is refused`() {
        val tampered = TelemetryDictionaries { name -> loadDict(name).also { it[0] = (it[0].toInt() xor 1).toByte() } }
        assertTrue("a tampered dictionary must not load", runCatching { tampered.byVersion(1) }.isFailure)
    }

    @Test fun `S5 every event service maps to a family and gets that family's newest version`() {
        assertEquals(TaxonomyContract.eventServices, TelemetryDictionaries.FAMILY_OF_SERVICE.keys)
        for (service in TaxonomyContract.eventServices) {
            val family = TelemetryDictionaries.FAMILY_OF_SERVICE.getValue(service)
            val newest = TelemetryDictionaries.VERSIONS.filterValues { it.first == family }.keys.max()
            val (version, bytes) = dicts.current(service)
            assertEquals(newest, version)
            assertArrayEquals(dicts.byVersion(version), bytes)
        }
        assertEquals(
            "families are separate dictionaries",
            TelemetryDictionaries.FAMILY_OF_SERVICE.values.toSet().size,
            TelemetryDictionaries.VERSIONS.values.map { it.first }.toSet().size
        )
    }

    @Test fun `S5 zlib header carries the dictionary flag and the dictionary adler32 for every event service`() {
        for (service in TaxonomyContract.eventServices) {
            val enc = codec.encode(service, codec.canonicalJson(mapOf("a" to "b")), true, Deflater())
            val header = enc.body
            assertEquals("deflate method", 8, header[0].toInt() and 0x0f)
            assertTrue("FDICT flag", (header[1].toInt() and 0x20) != 0)
            assertEquals(0, (((header[0].toInt() and 0xff) shl 8) or (header[1].toInt() and 0xff)) % 31)
            val adler = Adler32().also { it.update(dicts.byVersion(enc.dictVersion)) }.value
            val stored = header.copyOfRange(2, 6).fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xff) }
            assertEquals(service, adler, stored)
        }
    }

    @Test fun `S5 a v1 body stored by an earlier build still decodes`() {
        val body = Base64.getDecoder().decode(V1_FIXTURE_BASE64)
        val decoded = codec.decode(
            body, 1, 1, V1_FIXTURE_RAW_BYTES, 0b11, TelemetrySource.LIVE_SCAN, 1_729_612_345_678L
        )
        assertNotNull(decoded)
        assertEquals(V1_FIXTURE_FIELDS, decoded)
    }

    @Test fun `decode returns null when the dictionary loader fails or the body has trailing bytes`() {
        val enc = codec.encode("network_monitor", codec.canonicalJson(mapOf("a" to "b")), true, Deflater())
        val failing = TelemetryRecordCodec(
            TelemetryDictionaries { throw java.io.UncheckedIOException(java.io.IOException("x")) }
        )
        assertNull(failing.decode(enc.body, 1, enc.dictVersion, enc.rawBytes, 0, TelemetrySource.LIVE_SCAN, 1L))
        assertNotNull(codec.decode(enc.body, 1, enc.dictVersion, enc.rawBytes, 0, TelemetrySource.LIVE_SCAN, 1L))
        val padded = enc.body + byteArrayOf(1, 2, 3)
        assertNull(codec.decode(padded, 1, enc.dictVersion, enc.rawBytes, 0, TelemetrySource.LIVE_SCAN, 1L))
    }

    @Test fun `S5 the builder script cannot change a pinned dictionary without a new version`() {
        val script = listOf(
            File("../scripts/build_telemetry_dictionaries.py"), File("scripts/build_telemetry_dictionaries.py")
        ).firstOrNull { it.isFile }
        assertNotNull("builder script scripts/build_telemetry_dictionaries.py not found", script)
        val out = File(System.getProperty("java.io.tmpdir"), "dict-candidates-${System.nanoTime()}")
        val proc = try {
            ProcessBuilder("python3", "-I", script!!.absolutePath, "--out", out.absolutePath)
                .redirectErrorStream(true).start()
        } catch (e: java.io.IOException) {
            // Skip only on a developer machine; CI must have python3.
            assertTrue("python3 missing on CI: ${e.message}", System.getenv("CI").isNullOrEmpty())
            assumeTrue("python3 not available", false)
            null
        }
        val log = proc!!.inputStream.bufferedReader().readText()
        assertEquals(log, 0, proc.waitFor())
        val candidates = out.listFiles { f -> f.name.matches(Regex("telemetry_dict_.*_v\\d+\\.txt")) }.orEmpty()
        assertEquals(
            "builder must emit one file per pinned version",
            TelemetryDictionaries.PINNED_SHA256.size, candidates.size
        )
        for (c in candidates) {
            val version = Regex("_v(\\d+)\\.txt").find(c.name)!!.groupValues[1].toInt()
            val pinned = TelemetryDictionaries.PINNED_SHA256[version]
            assertNotNull("builder emitted v$version which is not pinned: pin it and add the res/raw file", pinned)
            assertEquals(
                "builder output for v$version differs from the pinned dictionary: ship it under a NEW " +
                    "version number, never edit v$version",
                pinned, sha256(c.readBytes())
            )
            assertArrayEquals(File(rawDir(), c.name).readBytes(), c.readBytes())
            val family = TelemetryDictionaries.VERSIONS.getValue(version).first
            assertEquals("telemetry_dict_${family}_v$version", c.nameWithoutExtension)
        }
        out.deleteRecursively()
    }

    private companion object {
        // Produced independently of the codec (python zlib.compressobj(zdict=<network v1 dictionary>)) from
        // the canonical JSON of the map below minus source/captured_at (stripped, mask 0b11).
        const val V1_FIXTURE_BASE64 = "eLs7reHAQ3FVflG6Xm5+VWZOTqJeWmZRalp+BaqzjAwNsTnLwBiYzg2BrrLEntBJdBQAKnIupg=="
        const val V1_FIXTURE_RAW_BYTES = 148
        val V1_FIXTURE_FIELDS: Map<String, Any?> = mapOf(
            "app_name" to "org.mozilla.firefox", "app_uid" to 10211, "destination_ip" to "203.0.113.9",
            "destination_port" to 8443, "protocol" to "TCP", "timestamp" to 1_729_612_345_678L,
            "source" to "LIVE_SCAN", "captured_at" to 1_729_612_345_678L,
        )
    }
}

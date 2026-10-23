package com.androdr.data.store

import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.zip.Deflater
import kotlin.random.Random

class TelemetryRecordCodecTest {

    private val codec = TelemetryRecordCodec(TelemetryDictionaries(::loadDict))

    private fun loadDict(name: String): ByteArray = listOf(
        File("src/main/res/raw/$name.txt"), File("app/src/main/res/raw/$name.txt")
    ).first { it.isFile }.readBytes()

    private val captured = 1_729_612_345_678L

    // ---- stripping -------------------------------------------------------------------------

    @Test fun `content-valued source strings are kept`() {
        for (content in listOf("bugreport_import", "adb_trusted_key")) {
            val fields = mapOf("source" to content, "x" to 1)
            val stripped = codec.strip(fields, TelemetrySource.BUGREPORT_IMPORT, captured)
            assertEquals(fields, stripped.fields)
            assertEquals(0, stripped.strippedKeys)
        }
    }

    @Test fun `source equal to the observation source name is stripped`() {
        val fields = mapOf("source" to "BUGREPORT_IMPORT", "x" to 1)
        val same = codec.strip(fields, TelemetrySource.BUGREPORT_IMPORT, captured)
        assertFalse(same.fields.containsKey("source"))
        assertTrue(same.strippedKeys != 0)
        val other = codec.strip(fields, TelemetrySource.LIVE_SCAN, captured)
        assertEquals(fields, other.fields)
        assertEquals(0, other.strippedKeys)
    }

    @Test fun `captured_at is stripped only when equal`() {
        val equal = codec.strip(mapOf("captured_at" to captured), TelemetrySource.LIVE_SCAN, captured)
        assertTrue(equal.fields.isEmpty())
        val differs = codec.strip(mapOf("captured_at" to captured + 1), TelemetrySource.LIVE_SCAN, captured)
        assertEquals(mapOf<String, Any?>("captured_at" to captured + 1), differs.fields)
        assertEquals(0, differs.strippedKeys)
        val wrongType = codec.strip(mapOf("captured_at" to "x"), TelemetrySource.LIVE_SCAN, captured)
        assertEquals(0, wrongType.strippedKeys)
    }

    @Test fun `decode restores exactly the stripped keys`() {
        val cases = listOf(
            mapOf("source" to "LIVE_SCAN", "captured_at" to captured, "a" to 1),
            mapOf("source" to "LIVE_SCAN", "captured_at" to 5L, "a" to 1),
            mapOf("source" to "adb_trusted_key", "captured_at" to captured, "a" to 1),
            mapOf("source" to "adb_trusted_key", "a" to 1),
            mapOf("a" to 1),
        )
        for (fields in cases) {
            val s = codec.strip(fields, TelemetrySource.LIVE_SCAN, captured)
            for (event in listOf(false, true)) {
                val enc = codec.encode("network_monitor", codec.canonicalJson(s.fields), event, Deflater())
                val back = codec.decode(
                    enc.body, enc.encoding, enc.dictVersion, enc.rawBytes, s.strippedKeys,
                    TelemetrySource.LIVE_SCAN, captured
                )
                assertEquals(fields, back)
            }
        }
    }

    // ---- canonical JSON --------------------------------------------------------------------

    @Test fun `types round-trip through canonical json`() {
        val fields = mapOf<String, Any?>(
            "int" to 7, "intNeg" to -3, "longSmall" to 7L, "longBig" to 1_729_612_345_678L,
            "zero" to 0L, "intMax" to Int.MAX_VALUE, "longMin" to Long.MIN_VALUE,
            "dbl" to 1.5, "dblWhole" to 2.0, "dblNegZero" to -0.0, "nan" to Double.NaN,
            "inf" to Double.POSITIVE_INFINITY, "ninf" to Double.NEGATIVE_INFINITY,
            "t" to true, "f" to false, "null" to null,
            "str" to "q\"\\\n\u0001é😀", "empty" to "",
            "bytes" to byteArrayOf(0, 1, -1, 127),
            "list" to listOf(1, "a", null, listOf(2L)),
            "set" to setOf("b", "a"),
            "map" to mapOf("z" to 1, "~tilde" to 2, "~L" to 3, "n" to mapOf("k" to listOf<Any?>())),
        )
        val json = codec.canonicalJson(fields)
        val back = codec.parse(json)!!
        assertEquals(fields.keys, back.keys)
        for ((k, v) in fields) {
            if (v is ByteArray) assertArrayEquals(v, back[k] as ByteArray)
            else if (v is Double && v.isNaN()) assertTrue((back[k] as Double).isNaN())
            else assertEquals("key $k", v, back[k])
        }
        assertEquals(java.lang.Double.doubleToRawLongBits(-0.0),
            java.lang.Double.doubleToRawLongBits(back["dblNegZero"] as Double))
        assertTrue(back["longSmall"] is Long)
        assertTrue(back["int"] is Int)
    }

    @Test fun `key order does not change the canonical form or hash`() {
        val a = linkedMapOf<String, Any?>("b" to 1, "a" to mapOf("y" to 1, "x" to 2), "s" to setOf(3, 1, 2))
        val b = linkedMapOf<String, Any?>("s" to setOf(2, 3, 1), "a" to mapOf("x" to 2, "y" to 1), "b" to 1)
        assertEquals(codec.canonicalJson(a), codec.canonicalJson(b))
        assertArrayEquals(HashKeys.h128(codec.canonicalJson(a)), HashKeys.h128(codec.canonicalJson(b)))
    }

    @Test fun `h128 is 16 bytes and keys compare by content`() {
        val h = HashKeys.h128("abc")
        assertEquals(16, h.size)
        assertArrayEquals(h, HashKeys.h128("abc".toByteArray()))
        assertEquals(HashKeys.key(h), HashKeys.key(h.copyOf()))
        assertEquals(mapOf(HashKeys.key(h) to 1)[HashKeys.key(h.copyOf())], 1)
    }

    // ---- encoding / compression ------------------------------------------------------------

    @Test fun `snapshot bodies are plain json and event bodies are deflate`() {
        val json = codec.canonicalJson(mapOf("a" to 1))
        val snap = codec.encode("app_scanner", json, false, Deflater())
        assertEquals(0, snap.encoding)
        assertEquals(json, String(snap.body, Charsets.UTF_8))
        assertEquals(snap.body.size, snap.rawBytes)
        val ev = codec.encode("network_monitor", json, true, Deflater())
        assertEquals(1, ev.encoding)
        assertTrue(ev.dictVersion >= 1)
        assertEquals(json.toByteArray().size, ev.rawBytes)
    }

    @Test fun `a reused deflater gives identical output`() {
        val d = Deflater()
        val json = codec.canonicalJson(mapOf("a" to "hello", "b" to 2))
        val first = codec.encode("network_monitor", json, true, d)
        codec.encode("network_monitor", codec.canonicalJson(mapOf("zzz" to "other")), true, d)
        assertArrayEquals(first.body, codec.encode("network_monitor", json, true, d).body)
    }

    /**
     * Fixture: 1,000 deterministic (seeded) [NetworkTelemetry] live-scan records built from a pool of
     * realistic package names, public IPv4/IPv6 addresses, ports and protocols, with epoch-ms
     * timestamps spread over a day. The pool is deliberately larger than the dictionary's samples.
     */
    @Test fun `event bodies compress at least 2_5x on 1000 network records`() {
        val rnd = Random(42)
        val apps = listOf(
            "com.android.chrome", "com.google.android.gms", "com.whatsapp", "org.mozilla.firefox",
            "com.discord", "com.reddit.frontpage", "com.netflix.mediaclient", "com.amazon.mShop.android.shopping",
            "com.twitter.android", "com.snapchat.android", "com.google.android.apps.photos", "com.dropbox.android",
            "com.slack", "us.zoom.videomeetings", "com.paypal.android.p2pmobile", null,
        )
        val protocols = listOf("TCP", "UDP", null)
        val ports = listOf(443, 443, 443, 80, 53, 5228, 8080, 993, 5222, 123)
        var raw = 0L
        var packed = 0L
        val d = Deflater()
        repeat(1000) {
            val ip = if (rnd.nextInt(10) == 0) "2607:f8b0:4004:${rnd.nextInt(0xfff).toString(16)}::200e"
            else "${listOf(142, 172, 157, 31, 104, 52, 13, 151, 185).random(rnd)}." +
                "${rnd.nextInt(256)}.${rnd.nextInt(256)}.${rnd.nextInt(1, 255)}"
            val rec = NetworkTelemetry(
                destinationIp = ip, destinationPort = ports.random(rnd), protocol = protocols.random(rnd),
                appUid = 10000 + rnd.nextInt(300), appName = apps.random(rnd),
                timestamp = 1_729_600_000_000L + rnd.nextLong(86_400_000L),
                source = TelemetrySource.LIVE_SCAN, capturedAt = captured,
            )
            val s = codec.strip(rec.toFieldMap(), rec.source, rec.capturedAt)
            val enc = codec.encode("network_monitor", codec.canonicalJson(s.fields), true, d)
            raw += enc.rawBytes
            packed += enc.body.size
        }
        val ratio = raw.toDouble() / packed
        println("MEASURED_COMPRESSION_RATIO=$ratio raw=$raw packed=$packed")
        assertTrue("ratio $ratio", ratio >= 2.5)
    }

    // ---- S6 --------------------------------------------------------------------------------

    @Test fun `S6 corrupt body decodes to null`() {
        val json = codec.canonicalJson(mapOf("a" to "x".repeat(200)))
        val enc = codec.encode("network_monitor", json, true, Deflater())
        val corrupt = enc.body.copyOf().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 0x5a).toByte() }
        assertNull(decode(enc, corrupt))
        assertNull(decode(enc, enc.body.copyOf(enc.body.size - 3)))
        assertNull(decode(enc, ByteArray(0)))
        assertNull(codec.decode("{not json".toByteArray(), 0, 0, 9, 0, TelemetrySource.LIVE_SCAN, captured))
        assertNull(codec.decode(json.toByteArray(), 0, 0, json.length + 1, 0, TelemetrySource.LIVE_SCAN, captured))
        assertNull(codec.decode(json.toByteArray(), 7, 0, json.length, 0, TelemetrySource.LIVE_SCAN, captured))
        assertNull(codec.decode(enc.body, 1, 99, enc.rawBytes, 0, TelemetrySource.LIVE_SCAN, captured))
        assertNotNull(decode(enc, enc.body))
    }

    @Test fun `S6 body inflating past rawBytes decodes to null without huge allocation`() {
        val json = codec.canonicalJson(mapOf("a" to "y".repeat(5_000_000)))
        val enc = codec.encode("network_monitor", json, true, Deflater())
        assertTrue(enc.body.size < 100_000)
        assertNull(codec.decode(enc.body, 1, enc.dictVersion, 100, 0, TelemetrySource.LIVE_SCAN, captured))
        assertNull(codec.decode(enc.body, 1, enc.dictVersion, Int.MAX_VALUE, 0, TelemetrySource.LIVE_SCAN, captured))
        assertNull(codec.decode(enc.body, 1, enc.dictVersion, -1, 0, TelemetrySource.LIVE_SCAN, captured))
        // rawBytes larger than the real size: the inflated length must match exactly
        assertNull(
            codec.decode(enc.body, 1, enc.dictVersion, enc.rawBytes + 10, 0, TelemetrySource.LIVE_SCAN, captured)
        )
    }

    private fun decode(enc: EncodedBody, body: ByteArray) = codec.decode(
        body, enc.encoding, enc.dictVersion, enc.rawBytes, 0, TelemetrySource.LIVE_SCAN, captured
    )
}

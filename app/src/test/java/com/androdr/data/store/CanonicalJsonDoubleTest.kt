package com.androdr.data.store

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import kotlin.random.Random

/**
 * #418: canonical JSON hashes a fact's bytes, so a double must format the same on every Android
 * version. `Double.toString` changed across Java releases (JDK-4511638: "2.0E-3" was "0.0020" before
 * JDK 19) and ART carries its own copy, so the canonical form uses an explicit exact-arithmetic
 * algorithm: the shortest decimal (at least two significant digits) that rounds back to the double,
 * nearest-even when two are equally short, laid out as `Double.toString` lays it out.
 */
class CanonicalJsonDoubleTest {

    private fun f(d: Double) = CanonicalJson.formatDouble(d)

    @Test fun `edge values format as the shortest round-tripping decimal`() {
        mapOf(
            0.0 to "0.0", -0.0 to "-0.0", 1.0 to "1.0", -1.0 to "-1.0", 2.0 to "2.0", 100.0 to "100.0",
            1.5 to "1.5", 0.1 to "0.1", 0.3 to "0.3", 0.1 + 0.2 to "0.30000000000000004",
            // Pre-JDK-19 Double.toString gave "0.0020" and "1.0E-5"-style drifts on these.
            2.0E-3 to "0.002", 0.001 to "0.001", 9.99E-4 to "9.99E-4", 1.0E-5 to "1.0E-5",
            9999999.0 to "9999999.0", 1.0E7 to "1.0E7", 1.2345678E7 to "1.2345678E7",
            1.0E23 to "1.0E23", 2.0E23 to "2.0E23", 8.41E21 to "8.41E21",
            123456789012345680.0 to "1.2345678901234568E17",
            Double.MAX_VALUE to "1.7976931348623157E308", Double.MIN_VALUE to "4.9E-324",
            java.lang.Double.MIN_NORMAL to "2.2250738585072014E-308",
            -123.456 to "-123.456", 4.35 to "4.35", 1.0 / 3 to "0.3333333333333333",
        ).forEach { (d, expected) -> assertEquals("format of $d", expected, f(d)) }
    }

    @Test fun `every formatted double parses back to the same bits`() {
        val rnd = Random(418)
        repeat(20_000) {
            val d = java.lang.Double.longBitsToDouble(rnd.nextLong())
            if (d.isNaN() || d.isInfinite()) return@repeat
            assertEquals(java.lang.Double.doubleToRawLongBits(d), java.lang.Double.doubleToRawLongBits(f(d).toDouble()))
        }
    }

    /** The host JVM (21) implements the JDK 19 shortest-decimal spec, an independent reference. */
    @Test fun `it agrees with the JDK 19+ Double toString on random doubles`() {
        assertTrue("reference needs JDK 19+", System.getProperty("java.specification.version")!!.toInt() >= 19)
        val rnd = Random(4180)
        repeat(20_000) {
            val d = if (it % 2 == 0) java.lang.Double.longBitsToDouble(rnd.nextLong()) else rnd.nextDouble(-1e9, 1e9)
            if (d.isNaN() || d.isInfinite()) return@repeat
            assertEquals(d.toString(), f(d))
        }
    }

    @Test fun `NaN and infinities stay tagged and doubles stay exact through write and parse`() {
        val json = CanonicalJson.write(
            mapOf("a" to Double.NaN, "b" to Double.NEGATIVE_INFINITY, "c" to 2.0E-3, "d" to -0.0, "e" to 3.0f),
        )
        assertEquals("{\"a\":{\"~D\":\"NaN\"},\"b\":{\"~D\":\"-Infinity\"},\"c\":0.002,\"d\":-0.0,\"e\":3.0}", json)
        val back = CanonicalJson.parse(json)!!
        assertTrue((back["a"] as Double).isNaN())
        assertEquals(Double.NEGATIVE_INFINITY, back["b"])
        assertEquals(2.0E-3, back["c"])
        assertEquals(
            java.lang.Double.doubleToRawLongBits(-0.0), java.lang.Double.doubleToRawLongBits(back["d"] as Double),
        )
    }

    /** The writer must not fall back to the platform's double formatting anywhere. */
    @Test fun `the canonical writer never uses platform double formatting`() {
        val src = listOf(File("src/main/java"), File("app/src/main/java")).first { it.isDirectory }
            .resolve("com/androdr/data/store/CanonicalJson.kt").readText()
        val writeDouble = src.substringAfter("private fun writeDouble").substringBefore("\n    private fun ")
        assertFalse("writeDouble appends a Double directly", Regex("""append\(d\)""").containsMatchIn(writeDouble))
        assertFalse(Regex("""\bd\.toString\(\)""").containsMatchIn(src))
        assertTrue(writeDouble.contains("formatDouble("))
    }
}

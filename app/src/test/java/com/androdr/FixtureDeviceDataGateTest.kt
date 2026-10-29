package com.androdr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Test fixtures are committed to a public repository, so they must not carry identifiers of a real
 * device. Fixtures copied from real bug reports are the risk: the first real-format fixture shipped
 * the test phone's build fingerprint (review E4 I1). This gate scans every file under
 * `src/test/resources/fixtures/` for a real-shaped build fingerprint, a serial number with a value,
 * and an IMEI-shaped 15-digit number.
 */
class FixtureDeviceDataGateTest {

    private fun fixtureDir(): File =
        listOf(File("src/test/resources/fixtures"), File("app/src/test/resources/fixtures")).first { it.isDirectory }

    @Test
    fun `no fixture carries a real build fingerprint, serial number or IMEI`() {
        val files = fixtureDir().walkTopDown().filter { it.isFile }.toList()
        assertTrue("the real-format fixture is scanned", files.any { "real" in it.name })
        val hits = files.flatMap { f ->
            f.readLines().mapIndexedNotNull { i, line -> deviceData(line)?.let { "${f.name}:${i + 1}: $it" } }
        }
        assertEquals("device identifiers in fixtures", emptyList<String>(), hits)
    }

    @Test
    fun `the gate catches each shape and spares synthetic or redacted values`() {
        val real = "Build fingerprint: 'brand/prod_x/dev:13/AAA1.220624.014/X123:user/release-keys'"
        assertEquals("build fingerprint", deviceData(real))
        assertEquals("build fingerprint",
            deviceData("[ro.build.fingerprint]: [brand/prod/dev:13/B/C:user/release-keys]"))
        assertEquals("serial number", deviceData("[ro.serialno]: [R58N12345AB]"))
        assertEquals("serial number", deviceData("ro.boot.serialno=R58N12345AB"))
        assertEquals("IMEI-shaped number", deviceData("imei: 356938035643809"))
        assertEquals(null,
            deviceData("Build fingerprint: '$SYNTHETIC_FINGERPRINT:13/AAAA.000000.000/0:user/release-keys'"))
        assertEquals(null, deviceData("ro.build.fingerprint=unisoc/redacted/redacted:12/R/7:user/release-keys"))
        assertEquals(null, deviceData("[ro.serialno]: []"))
        assertEquals("16 digits after 0x are an address", null, deviceData("0x0000000000000000-0x0000000000000000"))
        assertEquals("13-digit epoch millis", null, deviceData("time=1729600000000"))
    }

    companion object {
        /** The allowlisted synthetic fingerprint prefix fixtures use. */
        const val SYNTHETIC_FINGERPRINT = "vendor/product/device"

        private val FINGERPRINT =
            Regex("""[^/\s'\[=]+/[^/\s]+/[^:\s]+:[^/\s]+/[^/\s]+/[^:\s]+:user/release-keys""")
        private val SERIAL = Regex("""ro\.(boot\.)?serialno\]?\s*[:=]\s*\[?[^\[\]\s]+""")
        private val IMEI = Regex("""(?<![0-9A-Za-z])\d{15}(?![0-9A-Za-z])""")

        /** What kind of device identifier [line] carries, or null. */
        fun deviceData(line: String): String? = when {
            FINGERPRINT.containsMatchIn(line) && SYNTHETIC_FINGERPRINT !in line && "redacted" !in line ->
                "build fingerprint"
            SERIAL.containsMatchIn(line) -> "serial number"
            IMEI.containsMatchIn(line) -> "IMEI-shaped number"
            else -> null
        }
    }
}

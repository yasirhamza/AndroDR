package com.androdr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Test files are committed to a public repository, so they must not carry identifiers of a real
 * device. Fixtures copied from real bug reports are the risk: the first real-format fixture shipped
 * the test phone's build fingerprint (review E4 I1), and a test source can quote one just as easily.
 * This gate scans every file under `src/test/` (resources and Kotlin sources alike) for a
 * real-shaped build fingerprint (`user`, `userdebug` or `eng` builds, release, test or dev keys), a
 * serial number with a value, and an IMEI-shaped 15-digit number.
 *
 * A fingerprint is spared only when the matched fingerprint itself is synthetic (it starts with
 * [SYNTHETIC_FINGERPRINT]) or redacted (one of its own fields is `redacted`): a synthetic or
 * redacted value elsewhere on the line never excuses a real one (final review, triage #43).
 *
 * This file is not scanned: its examples are real-shaped on purpose.
 */
class FixtureDeviceDataGateTest {

    private fun testDir(): File = listOf(File("src/test"), File("app/src/test")).first { it.isDirectory }

    @Test
    fun `no test file carries a real build fingerprint, serial number or IMEI`() {
        val self = "${FixtureDeviceDataGateTest::class.simpleName}.kt"
        val files = testDir().walkTopDown().filter { it.isFile && it.name != self }.toList()
        assertTrue("the real-format fixture is scanned", files.any { "real" in it.name && it.extension == "txt" })
        assertTrue("Kotlin test sources are scanned", files.any { it.name == "StartupSweepTest.kt" })
        val hits = files.flatMap { f ->
            f.readLines().mapIndexedNotNull { i, line -> deviceData(line)?.let { "${f.path}:${i + 1}: $it" } }
        }
        assertEquals("device identifiers in test files", emptyList<String>(), hits)
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

    @Test
    fun `debug and test-key builds are caught, quoted in Kotlin or not`() {
        assertEquals("build fingerprint", deviceData("brand/prod/dev:14/UP1A.231005.007/123:userdebug/test-keys"))
        assertEquals("build fingerprint", deviceData("brand/prod/dev:14/UP1A.231005.007/123:eng/dev-keys"))
        assertEquals("build fingerprint", deviceData("brand/prod/dev:14/UP1A.231005.007/123:user/test-keys"))
        assertEquals("build fingerprint",
            deviceData("val fp = \"brand/prod/dev:14/UP1A.231005.007/123:userdebug/release-keys\""))
        assertEquals(null,
            deviceData("val fp = \"$SYNTHETIC_FINGERPRINT:14/UP1A.231005.007/123:userdebug/test-keys\""))
    }

    @Test
    fun `the allowlist is anchored to the matched fingerprint, not the line`() {
        val realFp = "brand/prod/dev:13/AAA1.220624.014/X123:user/release-keys"
        assertEquals("a synthetic one beside it does not excuse it", "build fingerprint",
            deviceData("'$SYNTHETIC_FINGERPRINT:13/A/0:user/release-keys' then '$realFp'"))
        assertEquals("'redacted' elsewhere on the line does not excuse it", "build fingerprint",
            deviceData("serial redacted; fingerprint $realFp"))
        assertEquals("the synthetic prefix later in the line does not excuse it", "build fingerprint",
            deviceData("$realFp # not $SYNTHETIC_FINGERPRINT"))
    }

    companion object {
        /** The allowlisted synthetic fingerprint prefix test files use. */
        const val SYNTHETIC_FINGERPRINT = "vendor/product/device"

        private val FINGERPRINT = Regex(
            """[^/\s'"\[=]+/[^/\s]+/[^:\s]+:[^/\s]+/[^/\s]+/[^:\s]+:(?:user|userdebug|eng)/(?:release|test|dev)-keys"""
        )
        private val SERIAL = Regex("""ro\.(boot\.)?serialno\]?\s*[:=]\s*\[?[^\[\]\s]+""")
        private val IMEI = Regex("""(?<![0-9A-Za-z])\d{15}(?![0-9A-Za-z])""")

        /** A matched fingerprint that is itself synthetic or redacted. */
        private fun spared(fingerprint: String): Boolean =
            fingerprint.startsWith(SYNTHETIC_FINGERPRINT) || "redacted" in fingerprint.split('/', ':')

        /** What kind of device identifier [line] carries, or null. */
        fun deviceData(line: String): String? = when {
            FINGERPRINT.findAll(line).any { !spared(it.value) } -> "build fingerprint"
            SERIAL.containsMatchIn(line) -> "serial number"
            IMEI.containsMatchIn(line) -> "IMEI-shaped number"
            else -> null
        }
    }
}

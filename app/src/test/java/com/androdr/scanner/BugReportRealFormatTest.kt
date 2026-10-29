package com.androdr.scanner

import android.net.Uri
import com.androdr.ioc.DeviceIdentity
import com.androdr.ioc.IndicatorResolver
import com.androdr.scanner.bugreport.BugreportModule
import com.androdr.scanner.bugreport.DumpsysClock
import com.androdr.scanner.bugreport.GetpropParser
import com.androdr.scanner.bugreport.ModuleResult
import com.androdr.scanner.bugreport.TombstoneParser
import com.androdr.scanner.bugreport.WakelockParser
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.ByteArrayOutputStream
import java.io.File
import java.time.ZoneId
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * The real [BugReportAnalyzer] on a zip laid out like a real `adb bugreport` (F916B, API 33):
 * main entry `dumpstate-<timestamp>.txt` after `dumpstate_board.txt`, and the real
 * `------ SYSTEM PROPERTIES (getprop) ------` title. Battery findings B6 (properties never read
 * on a real report) and B7 (the timestamped main entry was never opened).
 */
@RunWith(RobolectricTestRunner::class)
class BugReportRealFormatTest {

    /** Records the device identity and clock the analyzer hands to a section module. */
    private class Capture : BugreportModule {
        override val targetSections = listOf("package")
        var device: DeviceIdentity? = null
        var clock: DumpsysClock? = null
        override suspend fun analyze(
            sectionText: String,
            iocResolver: IndicatorResolver,
            device: DeviceIdentity,
            clock: DumpsysClock,
        ): ModuleResult {
            this.device = device
            this.clock = clock
            return ModuleResult()
        }
    }

    private fun fixtureText(): String {
        val name = "fixtures/bugreport-real-format-headers.txt"
        return listOf(File("src/test/resources/$name"), File("app/src/test/resources/$name"))
            .first { it.isFile }.readText()
    }

    /** The real entry order: a side file that also carries a getprop title comes first. */
    private fun realLayoutZip(main: String = "dumpstate-2026-10-29-08-18-37.txt"): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            for ((name, body) in listOf(
                "version.txt" to "2.0",
                "dumpstate_board.txt" to
                    "------ SYSTEM PROPERTIES (getprop) ------\n[persist.sys.timezone]: [Europe/Paris]\n",
                main to fixtureText(),
                "dumpstate_log.txt" to "log",
                "main_entry.txt" to main,
            )) {
                zip.putNextEntry(ZipEntry(name))
                zip.write(body.toByteArray())
                zip.closeEntry()
            }
        }
        return out.toByteArray()
    }

    private fun analyze(capture: Capture, bytes: ByteArray = realLayoutZip()) = runBlocking {
        BugReportAnalyzer(
            OrchestratorFixture.serving { bytes.inputStream() }, mockk(relaxed = true), setOf(capture),
            TombstoneParser(), WakelockParser(), GetpropParser(),
        ).analyze(Uri.parse("content://test/bugreport.zip"))
    }

    @Test
    fun `a real adb bugreport reads its timestamped main entry and its system properties`() {
        val capture = Capture()
        val result = analyze(capture)

        assertNotNull("the dumpstate-<timestamp>.txt sections were never read", capture.clock)
        assertEquals(ZoneId.of("Asia/Qatar"), capture.clock!!.zone)
        assertTrue(!capture.clock!!.assumedUtc)
        assertEquals(DeviceIdentity(manufacturer = "samsung", brand = "samsung"), capture.device)
        assertEquals(emptyList<String>(), result.importNotes)
        val props = result.telemetryBundle.systemPropertySnapshots.associate { it.key to it.value }
        assertEquals("Asia/Qatar", props["persist.sys.timezone"])
        assertEquals(9, props.size)
    }
}

package com.androdr.scanner

import com.androdr.ioc.IndicatorResolver
import com.androdr.ioc.OemPrefixResolver
import com.androdr.scanner.bugreport.AccessibilityModule
import com.androdr.scanner.bugreport.ActivityModule
import com.androdr.scanner.bugreport.AdbKeysModule
import com.androdr.scanner.bugreport.AppOpsModule
import com.androdr.scanner.bugreport.BatteryDailyModule
import com.androdr.scanner.bugreport.BugreportModule
import com.androdr.scanner.bugreport.DbInfoModule
import com.androdr.scanner.bugreport.GetpropParser
import com.androdr.scanner.bugreport.PlatformCompatModule
import com.androdr.scanner.bugreport.ReceiverModule
import com.androdr.scanner.bugreport.TombstoneParser
import com.androdr.scanner.bugreport.WakelockParser
import io.mockk.every
import io.mockk.mockk
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** A real [BugReportAnalyzer] over the minimal all-sections bug report (callers use Robolectric). */
internal object BugReportFixtures {
    private fun fixtureText(): String {
        val name = "fixtures/bugreport-minimal-all-sections.txt"
        return listOf(File("src/test/resources/$name"), File("app/src/test/resources/$name"))
            .first { it.isFile }.readText()
    }

    fun zipBytes(text: String = fixtureText()): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            zip.putNextEntry(ZipEntry("dumpstate.txt"))
            zip.write(text.toByteArray())
            zip.closeEntry()
        }
        return out.toByteArray()
    }

    fun modules(): Set<BugreportModule> {
        val oem = mockk<OemPrefixResolver>(relaxed = true)
        return setOf(
            AccessibilityModule(oem), ActivityModule(oem), AdbKeysModule(), AppOpsModule(),
            BatteryDailyModule(), DbInfoModule(), PlatformCompatModule(), ReceiverModule(oem),
        )
    }

    fun analyzer(bytes: ByteArray = zipBytes()): BugReportAnalyzer {
        val resolver = mockk<IndicatorResolver>(relaxed = true)
        every { resolver.isKnownBadPackage(any()) } returns null
        return BugReportAnalyzer(
            OrchestratorFixture.serving { bytes.inputStream() }, resolver, modules(),
            TombstoneParser(), WakelockParser(), GetpropParser(),
        )
    }
}

package com.androdr.scanner

import android.net.Uri
import com.androdr.data.model.Indicator
import com.androdr.data.store.rawFile
import com.androdr.ioc.BadPackageInfo
import com.androdr.ioc.DeviceIdentity
import com.androdr.scanner.bugreport.BatteryDailyModule
import com.androdr.scanner.bugreport.DumpsysClock
import com.androdr.sigma.Evidence
import com.androdr.sigma.SigmaRuleParser
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Ruling R28 (C3 fix round 1, review I1): the battery-stats "known-bad package uninstalled"
 * detection C3 removed from Kotlin is the bundled rule androdr-110. Driven through the real
 * BatteryDailyModule, a bug-report import session and the engine with its real package IOC lookup
 * wiring: an IOC-listed uninstall yields exactly one high androdr-110 finding with ioc_match evidence
 * and an open alert; a
 * clean uninstall, and an IOC-listed install or update, yield none.
 */
@RunWith(RobolectricTestRunner::class)
class BatteryUninstallIocRuleTest {
    private val rule =
        SigmaRuleParser.parse(rawFile("sigma_androdr_110_known_bad_package_uninstalled.yml").readText())!!
    private val f = OrchestratorFixture(engine = IntrusionLogZips.engine(rule), bugReportAnalyzer = mockk())
    private val uri = mockk<Uri>(relaxed = true)

    private val listed = setOf(BAD)

    init {
        every { f.indicatorResolver.isKnownBadPackage(any()) } answers {
            val pkg = firstArg<String>()
            if (pkg in listed) {
                BadPackageInfo(packageName = pkg, name = "mSpy", category = "STALKERWARE", severity = "CRITICAL",
                    description = "d")
            } else {
                null
            }
        }
        every { f.indicatorResolver.packageIndicator(any()) } answers {
            val pkg = firstArg<String>()
            if (pkg in listed) {
                Indicator(type = "package", value = pkg, family = "mSpy", source = "test", fetchedAt = 1L)
            } else {
                null
            }
        }
    }

    @After fun tearDown() = f.close()

    /** Imports a bug report whose batterystats section is [section], through the real module. */
    private fun import(section: String) = runBlocking {
        val typed = BatteryDailyModule().analyze(section, f.indicatorResolver, DeviceIdentity.UNKNOWN,
            DumpsysClock.ASSUMED_UTC).typed
        coEvery { f.bugReportAnalyzer.analyze(any()) } returns
            BugReportAnalyzer.BugReportAnalysisResult(telemetryBundle = typed)
        f.findingsOf(f.orchestrator.analyzeBugReport(uri).write!!.scan.id)
    }

    private fun section(vararg lines: String) = "Daily stats:\n  Current start time: 2026-03-28-01-00-01\n" +
        "  Package changes:\n" + lines.joinToString("\n") { "    $it" } + "\n"

    @Test
    fun `an uninstall of an IOC-listed package fires androdr-110 once, with ioc_match evidence`() {
        val result = import(section("-pkg=$BAD vers=100", "-pkg=$CLEAN vers=7"))

        val hits = result.filter { it.triggered && it.ruleId == "androdr-110" }
        assertEquals(1, hits.size)
        assertEquals(BAD, hits.single().matchContext["package_name"])
        val evidence = hits.single().evidence as Evidence.IocMatch
        assertEquals(BAD, evidence.matchedIndicator)
        // Owner decision 2026-10-29: high, not the retired row's informational, so it is a report
        // finding that counts toward the risk level and opens an alert someone has to close.
        assertEquals("high", hits.single().level)
        assertTrue("its Timeline finding row is written", f.count(
            "SELECT COUNT(*) FROM forensic_timeline WHERE ruleId = 'androdr-110'") == 1L)
        assertTrue("it opens one high alert", f.count(
            "SELECT COUNT(*) FROM alert WHERE ruleId = 'androdr-110' AND status = 'OPEN' AND level = 'high'") == 1L)
    }

    @Test
    fun `an uninstall of a clean package does not fire`() {
        val result = import(section("-pkg=$CLEAN vers=7"))
        assertTrue(result.none { it.triggered && it.ruleId == "androdr-110" })
    }

    @Test
    fun `an install or update of an IOC-listed package does not fire the uninstall rule`() {
        val result = import(section("+pkg=$BAD vers=100", "+pkg=$BAD vers=200"))
        assertTrue(result.none { it.triggered && it.ruleId == "androdr-110" })
    }

    private companion object {
        const val BAD = "com.mspy.android"
        const val CLEAN = "com.example.notes"
    }
}

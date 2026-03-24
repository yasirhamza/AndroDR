package com.androdr.scanner

import android.content.Context
import com.androdr.ioc.BadPackageInfo
import com.androdr.ioc.IocResolver
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream

class BugReportAnalyzerTest {

    private val mockContext: Context = mockk(relaxed = true)
    private val mockIocResolver: IocResolver = mockk()
    private lateinit var analyzer: BugReportAnalyzer

    @Before
    fun setUp() {
        every { mockIocResolver.isKnownBadPackage(any()) } returns null
        analyzer = BugReportAnalyzer(mockContext, mockIocResolver)
    }

    private fun streamOf(text: String) =
        ByteArrayInputStream(text.toByteArray(Charsets.UTF_8))

    // ── Spyware process name detection ────────────────────────────────────────

    @Test
    fun `spyware keyword triggers CRITICAL KnownMalware finding`() {
        val text = "I/ActivityManager: Start proc com.pegasus.spyservice for service"
        val findings = analyzer.analyzeTextEntry("logcat", streamOf(text))
        assertTrue(findings.any { it.severity == "CRITICAL" && it.category == "KnownMalware" })
    }

    @Test
    fun `each spyware family keyword is detected`() {
        val keywords = listOf("pegasus", "FlexiSPY", "mSpy", "cerberus", "droiddream", "spyware")
        keywords.forEach { keyword ->
            val findings = analyzer.analyzeTextEntry("logcat", streamOf("proc $keyword running"))
            assertTrue("Expected $keyword to be detected",
                findings.any { it.category == "KnownMalware" })
        }
    }

    @Test
    fun `clean process name does not trigger spyware finding`() {
        val text = "I/ActivityManager: Start proc com.legitimate.app for service"
        val findings = analyzer.analyzeTextEntry("logcat", streamOf(text))
        assertTrue(findings.none { it.category == "KnownMalware" })
    }

    // ── Base64 blob detection ─────────────────────────────────────────────────

    @Test
    fun `large base64 blob triggers HIGH SuspiciousData finding`() {
        val blob = "A".repeat(120) // 120 chars, all valid base64
        val text = "D/Upload: payload=$blob"
        val findings = analyzer.analyzeTextEntry("dumpstate", streamOf(text))
        assertTrue(findings.any { it.severity == "HIGH" && it.category == "SuspiciousData" })
    }

    @Test
    fun `base64 blob under 100 chars does not trigger finding`() {
        val blob = "A".repeat(80)
        val text = "D/Upload: payload=$blob"
        val findings = analyzer.analyzeTextEntry("dumpstate", streamOf(text))
        assertTrue(findings.none { it.category == "SuspiciousData" })
    }

    // ── C2 beacon detection ───────────────────────────────────────────────────

    @Test
    fun `C2 beacon pattern triggers CRITICAL C2Beacon finding`() {
        val text = "D/Network: HTTP POST to c2.evil.com every 300 seconds"
        val findings = analyzer.analyzeTextEntry("bugreport", streamOf(text))
        assertTrue(findings.any { it.severity == "CRITICAL" && it.category == "C2Beacon" })
    }

    @Test
    fun `HTTP POST without interval does not trigger C2 finding`() {
        val text = "D/Network: HTTP POST to api.example.com status=200"
        val findings = analyzer.analyzeTextEntry("bugreport", streamOf(text))
        assertTrue(findings.none { it.category == "C2Beacon" })
    }

    // ── Crash loop detection ──────────────────────────────────────────────────

    @Test
    fun `three crashes of same process triggers HIGH CrashLoop finding`() {
        val text = """
            E/AndroidRuntime: FATAL EXCEPTION: com.evil.process
            E/AndroidRuntime: FATAL EXCEPTION: com.evil.process
            E/AndroidRuntime: FATAL EXCEPTION: com.evil.process
        """.trimIndent()
        val findings = analyzer.analyzeTextEntry("logcat", streamOf(text))
        assertTrue(findings.any { it.severity == "HIGH" && it.category == "CrashLoop" })
    }

    @Test
    fun `two crashes of same process does not trigger CrashLoop finding`() {
        val text = """
            E/AndroidRuntime: FATAL EXCEPTION: com.some.process
            E/AndroidRuntime: FATAL EXCEPTION: com.some.process
        """.trimIndent()
        val findings = analyzer.analyzeTextEntry("logcat", streamOf(text))
        assertTrue(findings.none { it.category == "CrashLoop" })
    }

    @Test
    fun `crashes of different processes are counted independently`() {
        val text = """
            E/AndroidRuntime: FATAL EXCEPTION: com.proc.a
            E/AndroidRuntime: FATAL EXCEPTION: com.proc.b
            E/AndroidRuntime: FATAL EXCEPTION: com.proc.a
            E/AndroidRuntime: FATAL EXCEPTION: com.proc.b
            E/AndroidRuntime: FATAL EXCEPTION: com.proc.a
        """.trimIndent()
        val findings = analyzer.analyzeTextEntry("logcat", streamOf(text))
        // com.proc.a crashes 3 times → CrashLoop; com.proc.b only 2 times → no finding
        val crashLoops = findings.filter { it.category == "CrashLoop" }
        assertEquals(1, crashLoops.size)
        assertTrue(crashLoops[0].description.contains("com.proc.a"))
    }

    // ── Wakelock density detection ────────────────────────────────────────────

    @Test
    fun `high-density wakelock acquisitions trigger MEDIUM AbnormalWakelock finding`() {
        // 10 wakelocks in 20 lines = density 0.5 > threshold 0.2
        val lines = (1..10).joinToString("\n") { "PowerManager: WakeLock acquired by app" } +
            "\n" + (1..10).joinToString("\n") { "D/other: unrelated line $it" }
        val findings = analyzer.analyzeTextEntry("dumpstate", streamOf(lines))
        assertTrue(findings.any { it.severity == "MEDIUM" && it.category == "AbnormalWakelock" })
    }

    @Test
    fun `fewer than 10 wakelocks does not trigger AbnormalWakelock finding`() {
        val lines = (1..9).joinToString("\n") { "PowerManager: WakeLock acquired by app" }
        val findings = analyzer.analyzeTextEntry("dumpstate", streamOf(lines))
        assertTrue(findings.none { it.category == "AbnormalWakelock" })
    }

    // ── IOC database package matching ─────────────────────────────────────────

    @Test
    fun `known bad package in installed list triggers finding with IOC DB details`() {
        val stalkerwareInfo = BadPackageInfo(
            packageName = "com.flexispy.android",
            name = "FlexiSPY",
            category = "STALKERWARE",
            severity = "CRITICAL",
            description = "Commercial stalkerware."
        )
        every { mockIocResolver.isKnownBadPackage("com.flexispy.android") } returns stalkerwareInfo

        val text = "    package:com.flexispy.android"
        val findings = analyzer.analyzeTextEntry("dumpstate", streamOf(text))

        assertEquals(1, findings.size)
        val finding = findings[0]
        assertEquals("CRITICAL", finding.severity)
        assertEquals("KnownMalware", finding.category)
        assertTrue(finding.description.contains("FlexiSPY"))
        assertTrue(finding.description.contains("STALKERWARE"))
    }

    @Test
    fun `legitimate package in installed list produces no finding`() {
        every { mockIocResolver.isKnownBadPackage("com.google.android.gms") } returns null
        val text = "    package:com.google.android.gms"
        val findings = analyzer.analyzeTextEntry("dumpstate", streamOf(text))
        assertTrue(findings.none { it.category == "KnownMalware" })
    }

    @Test
    fun `finding severity comes from IOC database not hardcoded`() {
        val highSeverityInfo = BadPackageInfo(
            packageName = "com.some.spyware",
            name = "SomeSpyware",
            category = "SPYWARE",
            severity = "HIGH",
            description = "Moderate risk spyware."
        )
        every { mockIocResolver.isKnownBadPackage("com.some.spyware") } returns highSeverityInfo

        val text = "    package:com.some.spyware"
        val findings = analyzer.analyzeTextEntry("dumpstate", streamOf(text))

        assertEquals("HIGH", findings[0].severity)
    }

    // ── Clean input ───────────────────────────────────────────────────────────

    @Test
    fun `clean log text produces no findings`() {
        val text = """
            I/System: Boot completed
            D/PackageManager: Package com.google.android installed
            I/ActivityManager: Start proc com.android.phone
        """.trimIndent()
        val findings = analyzer.analyzeTextEntry("logcat", streamOf(text))
        assertTrue(findings.isEmpty())
    }

    @Test
    fun `empty input produces no findings`() {
        val findings = analyzer.analyzeTextEntry("logcat", streamOf(""))
        assertTrue(findings.isEmpty())
    }
}

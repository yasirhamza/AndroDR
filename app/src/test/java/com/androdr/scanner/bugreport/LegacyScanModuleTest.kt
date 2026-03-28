package com.androdr.scanner.bugreport

import com.androdr.ioc.BadPackageInfo
import com.androdr.ioc.IocResolver
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream

class LegacyScanModuleTest {

    private val mockIocResolver: IocResolver = mockk()
    private lateinit var module: LegacyScanModule

    @Before
    fun setUp() {
        every { mockIocResolver.isKnownBadPackage(any()) } returns null
        module = LegacyScanModule()
    }

    private fun streamOf(text: String) =
        ByteArrayInputStream(text.toByteArray(Charsets.UTF_8))

    // ── Spyware process name detection ────────────────────────────────────────

    @Test
    fun `spyware keyword triggers CRITICAL KnownMalware finding`() {
        val text = "I/ActivityManager: Start proc com.pegasus.spyservice for service"
        val findings = module.analyzeTextEntry("logcat", streamOf(text), mockIocResolver)
        assertTrue(findings.any { it.severity == "CRITICAL" && it.category == "KnownMalware" })
    }

    @Test
    fun `each spyware family keyword is detected`() {
        val keywords = listOf("pegasus", "FlexiSPY", "mSpy", "cerberus", "droiddream", "spyware")
        keywords.forEach { keyword ->
            val findings = module.analyzeTextEntry("logcat", streamOf("proc $keyword running"), mockIocResolver)
            assertTrue("Expected $keyword to be detected",
                findings.any { it.category == "KnownMalware" })
        }
    }

    // ── Base64 blob detection ─────────────────────────────────────────────────

    @Test
    fun `large base64 blob triggers HIGH SuspiciousData finding`() {
        val blob = "A".repeat(120)
        val text = "D/Upload: payload=$blob"
        val findings = module.analyzeTextEntry("dumpstate", streamOf(text), mockIocResolver)
        assertTrue(findings.any { it.severity == "HIGH" && it.category == "SuspiciousData" })
    }

    // ── C2 beacon detection ───────────────────────────────────────────────────

    @Test
    fun `C2 beacon pattern triggers CRITICAL C2Beacon finding`() {
        val text = "D/Network: HTTP POST to c2.evil.com every 300 seconds"
        val findings = module.analyzeTextEntry("bugreport", streamOf(text), mockIocResolver)
        assertTrue(findings.any { it.severity == "CRITICAL" && it.category == "C2Beacon" })
    }

    // ── Crash loop detection ──────────────────────────────────────────────────

    @Test
    fun `three crashes of same process triggers HIGH CrashLoop finding`() {
        val text = """
            E/AndroidRuntime: FATAL EXCEPTION: com.evil.process
            E/AndroidRuntime: FATAL EXCEPTION: com.evil.process
            E/AndroidRuntime: FATAL EXCEPTION: com.evil.process
        """.trimIndent()
        val findings = module.analyzeTextEntry("logcat", streamOf(text), mockIocResolver)
        assertTrue(findings.any { it.severity == "HIGH" && it.category == "CrashLoop" })
    }

    // ── IOC package matching ─────────────────────────────────────────────────

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
        val findings = module.analyzeTextEntry("dumpstate", streamOf(text), mockIocResolver)

        assertEquals(1, findings.size)
        val finding = findings[0]
        assertEquals("CRITICAL", finding.severity)
        assertEquals("KnownMalware", finding.category)
        assertTrue(finding.description.contains("FlexiSPY"))
        assertTrue(finding.description.contains("STALKERWARE"))
    }

    // ── Clean input ───────────────────────────────────────────────────────────

    @Test
    fun `clean log text produces no findings`() {
        val text = """
            I/System: Boot completed
            D/PackageManager: Package com.google.android installed
            I/ActivityManager: Start proc com.android.phone
        """.trimIndent()
        val findings = module.analyzeTextEntry("logcat", streamOf(text), mockIocResolver)
        assertTrue(findings.isEmpty())
    }

    @Test
    fun `empty input produces no findings`() {
        val findings = module.analyzeTextEntry("logcat", streamOf(""), mockIocResolver)
        assertTrue(findings.isEmpty())
    }

    // ── Timeline is always empty ─────────────────────────────────────────────

    @Test
    fun `timeline is always empty`() {
        val text = "I/ActivityManager: Start proc com.pegasus.spyservice for service"
        val findings = module.analyzeTextEntry("logcat", streamOf(text), mockIocResolver)
        // Findings exist but module always returns empty timeline
        assertTrue(findings.isNotEmpty())
        // Verify via analyzeRaw that timeline is empty
        val result = kotlinx.coroutines.runBlocking {
            module.analyzeRaw(
                sequenceOf("logcat" to streamOf(text) as java.io.InputStream),
                mockIocResolver
            )
        }
        assertTrue(result.timeline.isEmpty())
    }

    // ── targetSections is null ───────────────────────────────────────────────

    @Test
    fun `targetSections is null for raw entry scanning`() {
        assertTrue(module.targetSections == null)
    }
}

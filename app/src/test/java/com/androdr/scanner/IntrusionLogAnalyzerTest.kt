package com.androdr.scanner

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import com.androdr.sigma.Finding
import com.androdr.sigma.SigmaRuleEngine
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.InputStream

class IntrusionLogAnalyzerTest {

    private val engine = mockk<SigmaRuleEngine>(relaxed = true) {
        every { evaluateDns(any()) } returns emptyList()
        every { evaluateNetwork(any()) } returns emptyList()
        every { evaluateSecurityLog(any()) } returns emptyList()
    }

    // capturedAt must be at/after the imported events (see IntrusionLogParserTest);
    // event_time validation (#342) rejects events from the future relative to it.
    private val capturedAt = 1_787_400_400_000L

    private fun entry(name: String, vararg lines: String) =
        name to ByteArrayInputStream(lines.joinToString("\n").toByteArray())

    private val day1Dns = (
        """{"dns_event":{"event_id":0,"event_time":1787400345334,"package_name":"com.a",""" +
            """"hostname":"h1.example.com","ip_addresses":["/1.1.1.1"],"ip_addresses_count":1}}"""
        )
    private val day1Net = (
        """{"connect_event":{"event_id":1,"event_time":1787400345540,"package_name":"com.a",""" +
            """"port":443,"ip_address":"/1.1.1.1"}}"""
        )
    private val day2NetDupe = day1Net // same event_id 1 + event_time — overlapping-file duplicate
    private val day2Sec = """{"security_event":{"event_id":2,"event_time":1787400350000,"tag":210002,"data":["id"]}}"""

    @Test
    fun `parses matching entries only, dedups across files, computes stats`() {
        val result = IntrusionLogAnalyzer(mockk(relaxed = true), engine).analyzeEntries(
            sequenceOf(
                entry("2026-08-21.txt", day1Dns, day1Net),
                entry("2026-08-22.txt", day2NetDupe, day2Sec),
                entry("intrusion-logs/2026-08-20.txt"),          // one dir deep: included (empty)
                entry("README.md", "not a log line"),            // non-matching: ignored entirely
            ),
            uidResolver = { -1 }, capturedAt = capturedAt,
        )
        assertEquals(1, result.stats.dnsEventCount)
        assertEquals(1, result.stats.connectEventCount)
        assertEquals(1, result.stats.securityEventCount)
        assertEquals(1, result.stats.duplicatesCollapsed)
        assertEquals(0, result.stats.malformedLines)
        assertFalse(result.stats.truncated)
        assertEquals(1787400345334L, result.stats.earliestEventMs)
        assertEquals(1787400350000L, result.stats.latestEventMs)
    }

    /**
     * #356: a day rolls over into "(N)" continuation chunks every 8,192 lines —
     * roughly half of a real Z Fold8 export lives in them. The analyzer's own
     * copy of the per-day regex matched only the exact basename, so every chunk
     * was skipped silently: the events were never parsed and nothing said so.
     * Both the analyzer and the sniffer now share [ArtifactSniffer.isPerDayLogEntry].
     */
    @Test
    fun `continuation chunk entries are parsed, not skipped`() {
        val result = IntrusionLogAnalyzer(mockk(relaxed = true), engine).analyzeEntries(
            sequenceOf(
                entry("2026-08-22.txt", day1Dns),
                entry("2026-08-22(1).txt", day1Net),
                entry("2026-08-23(10).txt", day2Sec),
                entry("intrusion-logs/2026-08-21(2).txt"),   // one dir deep chunk: included (empty)
                // Too deep: still ignored. A DISTINCT dns line, so parsing it
                // would raise dnsEventCount to 2 rather than collapsing as a dupe.
                entry(
                    "a/b/2026-08-20(1).txt",
                    """{"dns_event":{"event_id":9,"event_time":1787400346000,"hostname":"deep.example.com"}}"""
                ),
            ),
            uidResolver = { -1 }, capturedAt = capturedAt,
        )
        assertEquals(1, result.stats.dnsEventCount)
        assertEquals(1, result.stats.connectEventCount)
        assertEquals(1, result.stats.securityEventCount)
        assertEquals(0, result.stats.malformedLines)
    }

    @Test
    fun `evaluates all three streams through the engine`() {
        val analyzer = IntrusionLogAnalyzer(mockk(relaxed = true), engine)
        analyzer.analyzeEntries(
            sequenceOf(entry("2026-08-22.txt", day1Dns, day1Net, day2Sec)),
            uidResolver = { -1 }, capturedAt = capturedAt,
        )
        verify(exactly = 1) { engine.evaluateDns(match { it.size == 1 }) }
        verify(exactly = 1) { engine.evaluateNetwork(match { it.size == 1 }) }
        verify(exactly = 1) { engine.evaluateSecurityLog(match { it.size == 1 }) }
    }

    /**
     * #342 B3: the stats must surface the TOTAL triggered-finding count so the
     * UI/report can show "kept N of M" once the persistence cap
     * ([ScanOrchestrator.FINDINGS_PERSIST_CAP]) truncates the set. Only triggered
     * findings count — untriggered ones are never persisted as rows.
     */
    @Test
    fun `stats surface the triggered finding count for the persistence cap`() {
        val e = mockk<SigmaRuleEngine>(relaxed = true) {
            every { evaluateDns(any()) } returns emptyList()
            every { evaluateNetwork(any()) } returns emptyList()
            every { evaluateSecurityLog(any()) } returns listOf(
                Finding(ruleId = "androdr-1", title = "t", level = "high", triggered = true),
                Finding(ruleId = "androdr-2", title = "t", level = "high", triggered = true),
                Finding(ruleId = "androdr-3", title = "t", level = "high", triggered = false),
            )
        }
        val result = IntrusionLogAnalyzer(mockk(relaxed = true), e).analyzeEntries(
            sequenceOf(entry("2026-08-22.txt", day2Sec)),
            uidResolver = { -1 }, capturedAt = capturedAt,
        )
        assertEquals(
            "only triggered findings count toward the cap",
            2, result.stats.triggeredFindingCount
        )
    }

    // Finding 3c: a crafted ZIP can raise an Error (OOM/StackOverflow), which no
    // `catch (Exception)` stops. analyze(uri) must catch Throwable and return a
    // graceful empty result rather than crashing the process.
    @Test
    fun `analyze contains a Throwable raised mid-read and returns empty`() {
        val boomStream = object : InputStream() {
            override fun read(): Int = throw OutOfMemoryError("boom")
            override fun read(b: ByteArray, off: Int, len: Int): Int = throw OutOfMemoryError("boom")
        }
        val resolver = mockk<ContentResolver> {
            every { openInputStream(any()) } returns boomStream
        }
        val context = mockk<Context> {
            every { contentResolver } returns resolver
        }
        val result = runBlocking {
            IntrusionLogAnalyzer(context, engine).analyze(mockk<Uri>(relaxed = true))
        }
        assertEquals(0, result.stats.dnsEventCount)
        assertTrue(result.findings.isEmpty())
    }

    // Finding 7: package-name-shape validation rejects junk with NO resolver call.
    @Test
    fun `bounded resolver rejects non-package-shaped strings without a resolver call`() {
        var calls = 0
        val resolver = boundedUidResolver({ calls++; 10001 })
        assertEquals(-1, resolver("not a package\n----"))
        assertEquals(-1, resolver(""))
        assertEquals(-1, resolver("nodot"))
        assertEquals(0, calls)
        assertFalse(isPlausiblePackageName("not a package"))
        assertFalse(isPlausiblePackageName("com.a".repeat(100))) // > 255 chars
        assertTrue(isPlausiblePackageName("com.samsung.android.intellivoiceservice"))
    }

    // Finding 7: a valid name resolves once and is cached; the cache is bounded,
    // so an evicted entry forces a fresh resolver call (unbounded would not).
    @Test
    fun `bounded resolver caches hits but evicts beyond the size cap`() {
        var calls = 0
        val resolver = boundedUidResolver({ calls++; 20000 }, maxCacheSize = 2)
        resolver("com.app.a") // call 1, cache [a]
        resolver("com.app.a") // cached, no call
        assertEquals(1, calls)
        resolver("com.app.b") // call 2, cache [a,b]
        resolver("com.app.c") // call 3, evicts a -> cache [b,c]
        resolver("com.app.a") // evicted -> call 4
        assertEquals(4, calls)
    }
}

package com.androdr.scanner

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import com.androdr.sigma.SigmaRuleEngine
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.InputStream

class IntrusionLogAnalyzerTest {

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

    private fun analyzer(resolver: com.androdr.ioc.IndicatorResolver = mockk(relaxed = true)) =
        IntrusionLogAnalyzer(mockk(relaxed = true), resolver)

    private fun analyze(
        vararg entries: Pair<String, java.io.InputStream>,
        chunks: CollectingChunks = CollectingChunks(),
        resolver: com.androdr.ioc.IndicatorResolver = mockk(relaxed = true),
    ) = runBlocking {
        analyzer(resolver).analyzeEntries(entries.asSequence(), uidResolver = { -1 }, capturedAt = capturedAt, chunks)
    }

    // Exact duplicates are no longer dropped here: the store collapses them (one fact, one
    // observation per import), so the analyzer counts records parsed; the orchestrator subtracts
    // the duplicates the store dropped (IntrusionLogImportTest).
    @Test
    fun `parses matching entries only, hands every record over, computes stats`() {
        val chunks = CollectingChunks()
        val result = analyze(
            entry("2026-08-21.txt", day1Dns, day1Net),
            entry("2026-08-22.txt", day2NetDupe, day2Sec),
            entry("intrusion-logs/2026-08-20.txt"),          // one dir deep: included (empty)
            entry("README.md", "not a log line"),            // non-matching: ignored entirely
            chunks = chunks,
        )
        assertEquals(1, result.stats.dnsEventCount)
        assertEquals(2, result.stats.connectEventCount)
        assertEquals(1, result.stats.securityEventCount)
        assertEquals(0, result.stats.malformedLines)
        assertFalse(result.stats.truncated)
        assertEquals(1787400345334L, result.stats.earliestEventMs)
        assertEquals(1787400350000L, result.stats.latestEventMs)
        assertEquals(
            "the overlapping-file duplicate keeps the same source key",
            listOf("connect_event 1 1787400345540", "connect_event 1 1787400345540"),
            chunks.records.getValue("network_monitor").map { it.sourceEventKey },
        )
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
        val result = analyze(
            entry("2026-08-22.txt", day1Dns),
            entry("2026-08-22(1).txt", day1Net),
            entry("2026-08-23(10).txt", day2Sec),
            entry("intrusion-logs/2026-08-21(2).txt"),   // one dir deep chunk: included (empty)
            // Too deep: still ignored. A DISTINCT dns line, so parsing it
            // would raise dnsEventCount to 2.
            entry(
                "a/b/2026-08-20(1).txt",
                """{"dns_event":{"event_id":9,"event_time":1787400346000,"hostname":"deep.example.com"}}"""
            ),
        )
        assertEquals(1, result.stats.dnsEventCount)
        assertEquals(1, result.stats.connectEventCount)
        assertEquals(1, result.stats.securityEventCount)
        assertEquals(0, result.stats.malformedLines)
    }

    @Test
    fun `hands all three streams over as store records with their source keys`() {
        val chunks = CollectingChunks()
        analyze(entry("2026-08-22.txt", day1Dns, day1Net, day2Sec), chunks = chunks)
        assertEquals(listOf("dns_event 0 1787400345334"),
            chunks.records.getValue("dns_monitor").map { it.sourceEventKey })
        assertEquals(1, chunks.records.getValue("network_monitor").size)
        assertEquals(listOf("security_event 2 1787400350000"),
            chunks.records.getValue("security_log").map { it.sourceEventKey })
        assertEquals("h1.example.com", chunks.records.getValue("dns_monitor").single().fields["domain"])
    }

    /** One pass, chunked: each type is handed over whenever its 5,000-record buffer fills. */
    @Test
    fun `each type is handed over in chunks of at most 5000`() {
        val lines = (0 until 12_001).map {
            """{"dns_event":{"event_id":$it,"event_time":${1787400000000L + it},"hostname":"h$it.example"}}"""
        }
        val chunks = CollectingChunks()
        val result = analyze(entry("2026-08-22.txt", *lines.toTypedArray()), entry("2026-08-23.txt", day2Sec),
            chunks = chunks)
        assertEquals(
            listOf("dns_monitor" to 5_000, "dns_monitor" to 5_000, "dns_monitor" to 2_001, "security_log" to 1),
            chunks.chunkSizes,
        )
        assertEquals(12_001, result.stats.dnsEventCount)
        assertEquals(1787400000000L, result.stats.earliestEventMs)
    }

    /**
     * Finding 3c: a crafted ZIP can raise an Error (OOM/StackOverflow), which no
     * `catch (Exception)` stops. analyze(uri) must still contain it — the process
     * must not die — but #356: it must REPORT the failure instead of answering
     * with an empty result.
     *
     * An empty result is indistinguishable from a genuinely empty log, so the
     * orchestrator persisted an empty import and ran its replace-on-reimport
     * sweep, deleting the PREVIOUS import's rows while the UI reported success.
     * A failed read must never destroy evidence or masquerade as an empty one.
     */
    @Test
    fun `analyze contains a Throwable raised mid-read and reports it as a failure`() {
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

        val thrown = runCatching {
            runBlocking {
                IntrusionLogAnalyzer(context, mockk(relaxed = true))
                    .analyze(mockk<Uri>(relaxed = true), CollectingChunks())
            }
        }.exceptionOrNull()

        assertTrue(
            "an Error must be contained (no process crash) but surfaced as a failure: $thrown",
            thrown is IntrusionLogAnalyzer.IntrusionLogAnalysisException
        )
        // Walk the chain: kotlinx-coroutines' stack-trace recovery re-creates the
        // thrown exception (it has a single-Throwable constructor) with the
        // original as its cause, so the Error can sit one link deeper.
        assertTrue(
            "the underlying Error must be kept in the cause chain for diagnostics: $thrown",
            generateSequence(thrown!!.cause) { it.cause }.any { it is OutOfMemoryError }
        )
    }

    /** An unreadable file is a failed import, not an empty one (#356). */
    @Test
    fun `analyze reports an unopenable uri as a failure rather than an empty import`() {
        val resolver = mockk<ContentResolver> {
            every { openInputStream(any()) } returns null
        }
        val context = mockk<Context> {
            every { contentResolver } returns resolver
        }

        val thrown = runCatching {
            runBlocking {
                IntrusionLogAnalyzer(context, mockk(relaxed = true))
                    .analyze(mockk<Uri>(relaxed = true), CollectingChunks())
            }
        }.exceptionOrNull()

        assertTrue(
            "a null stream means the file could not be read: $thrown",
            thrown is IntrusionLogAnalyzer.IntrusionLogAnalysisException
        )
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

    /** B5 fix round 1: a failing attribution prefetch must not fail the whole import. */
    @Test
    fun `a failing domain prefetch keeps the findings and records an attribution failure`() {
        val finding = Finding(ruleId = "androdr-003", title = "Malicious Domain", level = "critical",
            category = FindingCategory.APP_RISK)
        val e = mockk<SigmaRuleEngine>(relaxed = true) {
            every { evaluateRecords("dns_monitor", any(), any()) } returns listOf(finding)
        }
        val resolver = mockk<com.androdr.ioc.IndicatorResolver>(relaxed = true)
        io.mockk.coEvery { resolver.prefetchDomainIndicators(any()) } throws
            android.database.sqlite.SQLiteException("database disk image is malformed")
        val chunks = CollectingChunks(e)

        val result = analyze(entry("2026-08-22.txt", day1Dns), chunks = chunks, resolver = resolver)

        assertEquals(listOf(finding), chunks.findings)
        assertEquals("SQLiteException", result.scannerErrors.single { it.scanner == "attribution" }.exception)
    }

    /**
     * B5 fix round 2: cancelling an import must reach the attribution prefetch. The prefetch now
     * runs in the import's own coroutine, so a cancelled import stops its DAO lookups early.
     */
    @Test
    fun `cancelling the import stops the attribution prefetch early`() {
        val hosts = 200
        val dao = mockk<com.androdr.data.db.IndicatorDao>()
        val lookups = java.util.concurrent.atomic.AtomicInteger()
        val firstLookup = java.util.concurrent.CountDownLatch(1)
        io.mockk.coEvery { dao.getAllByType(any()) } returns emptyList()
        io.mockk.coEvery { dao.getValuesByType("domain") } returns (0 until hosts).map { "d$it.example" }
        io.mockk.coEvery { dao.getValuesByType(neq("domain")) } returns emptyList()
        io.mockk.coEvery { dao.lookup(any(), any()) } coAnswers {
            lookups.incrementAndGet(); firstLookup.countDown(); kotlinx.coroutines.delay(20); null
        }
        val resolver = com.androdr.ioc.IndicatorResolver(dao, mockk(relaxed = true), mockk(relaxed = true),
            mockk(relaxed = true), mockk { every { lookup(any()) } returns null })
        runBlocking { resolver.refreshCache() }
        val lines = (0 until hosts).map {
            """{"dns_event":{"event_id":$it,"event_time":${1787400345334L + it},"hostname":"d$it.example"}}"""
        }
        val job = kotlinx.coroutines.Job()
        var outcome: Result<IntrusionLogScan>? = null
        val worker = kotlin.concurrent.thread {
            outcome = runCatching {
                runBlocking(job) {
                    analyzer(resolver).analyzeEntries(
                        sequenceOf(entry("2026-08-22.txt", *lines.toTypedArray())),
                        uidResolver = { -1 }, capturedAt = capturedAt, chunks = CollectingChunks(),
                    )
                }
            }
        }
        assertTrue(firstLookup.await(10, java.util.concurrent.TimeUnit.SECONDS))
        job.cancel()
        worker.join(30_000)

        assertTrue("prefetch stopped early: ${lookups.get()} of $hosts lookups", lookups.get() < hosts / 2)
        assertTrue("cancellation propagates: $outcome",
            outcome?.exceptionOrNull() is kotlinx.coroutines.CancellationException)
    }
}

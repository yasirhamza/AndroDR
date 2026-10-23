package com.androdr.scanner

import android.net.Uri
import com.androdr.data.store.TelemetryStore
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.StoreRecord
import com.androdr.sigma.TestRuleRepo
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.spyk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * E1, writer half (telemetry store §4.1, §9): every real writer — the live scan, the intrusion-log
 * import and the bug-report import — evaluates exactly the chunk it persists (the same list, chunk
 * by chunk), and no production code evaluates outside the writer session.
 */
@RunWith(RobolectricTestRunner::class)
class WriterEvaluationTest {

    /** Spies the engine's evaluations and the store's persists of one fixture's writer. */
    private class Spied(engine: SigmaRuleEngine, real: IntrusionLogAnalyzer? = null,
                        bugReports: BugReportAnalyzer? = null) {
        val evaluated = mutableListOf<Pair<String, List<StoreRecord>>>()
        val persisted = mutableListOf<Pair<String, List<StoreRecord>>>()
        val spyEngine: SigmaRuleEngine = spyk(engine)
        val f = OrchestratorFixture(
            engine = spyEngine,
            bugReportAnalyzer = bugReports ?: mockk(relaxed = true),
            intrusionLogAnalyzer = real,
        )

        init {
            val store: TelemetryStore = spyk(f.w.f.store)
            f.w.store = store
            every { spyEngine.evaluateRecords(any(), any(), any()) } answers {
                evaluated += firstArg<String>() to secondArg<List<StoreRecord>>()
                callOriginal()
            }
            coEvery { store.persistChunk(any(), any(), any(), any(), any(), any(), any(), any(), any()) } coAnswers {
                persisted += arg<String>(1) to arg<List<StoreRecord>>(4)
                callOriginal()
            }
        }

        fun assertIdentical(minChunks: Int) {
            assertTrue("at least $minChunks chunks: ${persisted.size}", persisted.size >= minChunks)
            assertEquals("one evaluation per persisted chunk", persisted.size, evaluated.size)
            persisted.indices.forEach {
                assertEquals(persisted[it].first, evaluated[it].first)
                assertSame("chunk $it: evaluated and persisted are the same list", evaluated[it].second,
                    persisted[it].second)
            }
        }
    }

    @Test
    fun `E1 - the live scan evaluates exactly what it persists, chunk by chunk`() = runBlocking {
        val s = Spied(IntrusionLogZips.engine(
            IntrusionLogZips.rule("androdr-e1-app", "app_scanner", "package_name", "com.app5001", "high")))
        s.f.use { f ->
            coEvery { f.appScanner.collectTelemetry() } returns (0..5_001).map { OrchestratorFixture.app("com.app$it") }
            coEvery { f.dnsEventDao.getRecentSnapshot() } returns listOf(
                com.androdr.data.model.DnsEvent(id = 3, timestamp = 1L, domain = "a.example", appUid = 1,
                    appName = null, isBlocked = false, reason = null))
            coEvery { f.usageStatsScanner.collectEvents() } returns listOf(
                com.androdr.data.model.UsageEvent(5L, "com.a", "A", "app_foreground",
                    com.androdr.data.model.TelemetrySource.LIVE_SCAN, 6L))

            val scan = f.orchestrator.runFullScan()

            s.assertIdentical(minChunks = 4)
            assertEquals(listOf("app_scanner", "app_scanner", "dns_monitor", "usage_stats"),
                s.persisted.map { it.first })
            assertEquals("the second app chunk starts at ordinal 5000", 5_001, scan.findings.single().ordinal)
        }
    }

    @Test
    fun `E1 - the intrusion-log import evaluates exactly what it persists, chunk by chunk`() = runBlocking {
        val lines = (0 until 5_003).map {
            """{"security_event":{"event_id":$it,"event_time":${1787400000000L + it},"tag":210002,"data":["x"]}}"""
        } + """{"dns_event":{"event_id":9,"event_time":1787400345334,"hostname":"h.example"}}"""
        val zip = IntrusionLogZips.zip("2026-08-22.txt" to lines)
        val engine = IntrusionLogZips.engine(
            IntrusionLogZips.rule("androdr-e1-sec", "security_log", "tag_name", "adb_shell_cmd"))
        val real = IntrusionLogAnalyzer(OrchestratorFixture.serving { zip.inputStream() }, mockk(relaxed = true))
        val s = Spied(engine, real = real)
        s.f.use { f ->
            f.orchestrator.analyzeIntrusionLog(mockk<Uri>(relaxed = true))
            s.assertIdentical(minChunks = 3)
            assertEquals("a full chunk as it fills, then the rest per type", listOf(5_000, 1, 3),
                s.persisted.map { it.second.size })
        }
    }

    @Test
    fun `E1 - the bug-report import evaluates exactly what it persists, chunk by chunk`() = runBlocking {
        val analyzer = BugReportFixtures.analyzer()
        val s = Spied(IntrusionLogZips.engine(), bugReports = analyzer)
        s.f.use { f ->
            f.orchestrator.analyzeBugReport(mockk<Uri>(relaxed = true))
            s.assertIdentical(minChunks = 7)
        }
    }

    /**
     * Source gate: no production code evaluates rules outside the writer session — only
     * ChunkedScanWriter (the session's `evaluateRecords`) and SigmaRuleEngine's own typed
     * `evaluate*` delegation may call an `evaluate[A-Z]…` function. The evaluator internals
     * (SigmaRuleEvaluator, SigmaCorrelationEngine) are the engine itself. A writer's
     * `Session.evaluateStored` call is the session's own entry point and allowed.
     */
    @Test
    fun `source gate - no evaluate call outside the session and the typed delegation`() {
        val call = Regex("""\bevaluate[A-Z]\w*\s*\(""")
        val offenders = TestRuleRepo.mainSourceRoot().walkTopDown()
            .filter { it.isFile && it.extension == "kt" && it.name !in ALLOWED }
            .flatMap { f ->
                TestRuleRepo.stripKotlinComments(f.readText()).lines().mapIndexedNotNull { i, line ->
                    call.findAll(line).map { it.value }.filterNot { it.startsWith("evaluateStored") }
                        .firstOrNull()?.let { "${f.name}:${i + 1}: ${line.trim()}" }
                }
            }.toList()
        assertTrue("evaluate calls outside the writer session:\n${offenders.joinToString("\n")}", offenders.isEmpty())
        assertTrue("the scan must see the session file",
            TestRuleRepo.mainSourceRoot().walkTopDown().any { it.name == "ChunkedScanWriter.kt" })
    }

    private companion object {
        val ALLOWED = setOf("ChunkedScanWriter.kt", "SigmaRuleEngine.kt", "SigmaRuleEvaluator.kt",
            "SigmaCorrelationEngine.kt")
    }
}

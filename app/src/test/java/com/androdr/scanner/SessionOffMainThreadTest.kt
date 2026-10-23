package com.androdr.scanner

import android.net.Uri
import android.os.Looper
import com.androdr.data.model.TelemetrySource
import com.androdr.data.repo.ScanWriteRepository
import com.androdr.data.store.TelemetryStore
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.StoreRecord
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.spyk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.util.Collections

/**
 * A8 D2: the writer's CPU work — rule evaluation, a chunk's canonical JSON, Deflate and hashing
 * (`TelemetryStore.persistChunk`'s prepare step) and the finishing pass — never runs on the main
 * thread. The live scan was launched from a ViewModel scope (Dispatchers.Main) and nothing moved
 * its session off it; Room's `withTransaction` moves only the transaction itself.
 *
 * Under Robolectric the test thread is the main looper's thread, so each call below starts on
 * "Main" exactly as a ViewModel launch does.
 */
@RunWith(RobolectricTestRunner::class)
class SessionOffMainThreadTest {
    /** Each spied call's name and whether it ran on the main thread. */
    private val calls: MutableList<Pair<String, Boolean>> = Collections.synchronizedList(mutableListOf())

    private fun onMain() = Looper.getMainLooper().thread == Thread.currentThread()

    private fun spiedEngine(): SigmaRuleEngine = spyk(
        IntrusionLogZips.engine(IntrusionLogZips.rule("androdr-om-app", "app_scanner", "package_name", "com.evil")),
    ).also { e ->
        every { e.evaluateRecords(any(), any(), any()) } answers {
            calls += "evaluateRecords" to onMain()
            callOriginal()
        }
        every { e.loadBundledRules() } answers {
            calls += "loadBundledRules" to onMain()
            callOriginal()
        }
    }

    private fun spyStore(store: TelemetryStore): TelemetryStore = spyk(store).also { s ->
        coEvery { s.persistChunk(any(), any(), any(), any(), any(), any(), any(), any(), any()) } coAnswers {
            calls += "persistChunk" to onMain()
            callOriginal()
        }
    }

    private fun spyRepo(repo: ScanWriteRepository): ScanWriteRepository = spyk(repo).also { r ->
        coEvery { r.finish(any(), any(), any(), any(), any()) } coAnswers {
            calls += "finish" to onMain()
            callOriginal()
        }
    }

    private fun spy(f: OrchestratorFixture) {
        f.w.store = spyStore(f.w.store)
        f.w.repo = spyRepo(f.w.repo)
    }

    private fun assertOffMain(vararg expected: String) {
        assertTrue("the test starts on the main thread", onMain())
        val seen = synchronized(calls) { calls.toList() }
        for (name in expected) assertTrue("$name was called: $seen", seen.any { it.first == name })
        assertEquals("nothing ran on the main thread: $seen", emptyList<Pair<String, Boolean>>(),
            seen.filter { it.second })
    }

    @Test
    fun `a session driven from the main thread does its work off it`() = runBlocking {
        val w = WriterFixture()
        try {
            w.store = spyStore(w.store)
            w.repo = spyRepo(w.repo)
            val engine = spyk(w.engine).also { e ->
                every { e.evaluateRecords(any(), any(), any()) } answers {
                    calls += "evaluateRecords" to onMain()
                    callOriginal()
                }
            }
            val writer = ChunkedScanWriter(engine, w.store, w.repo, w.preflight, w.health)
            val session = writer.begin(w.scan(1L), liveEvents = true)
            session.append("app_scanner", TelemetrySource.LIVE_SCAN, 1L,
                listOf(StoreRecord(mapOf("package_name" to WriterFixture.EVIL_APP))))
            session.evaluateStored("app_scanner", sequenceOf(1L to StoreRecord(mapOf("package_name" to "com.x"))))
            session.finish()
            assertOffMain("evaluateRecords", "persistChunk", "finish")
        } finally {
            w.close()
        }
    }

    @Test
    fun `a live scan launched on the main thread does its work off it`() = runBlocking {
        val f = OrchestratorFixture(engine = spiedEngine())
        try {
            spy(f)
            coEvery { f.appScanner.collectTelemetry() } returns listOf(OrchestratorFixture.app("com.evil"))
            f.orchestrator.runFullScan()
            assertOffMain("loadBundledRules", "evaluateRecords", "persistChunk", "finish")
        } finally {
            f.close()
        }
    }

    @Test
    fun `a bug-report import launched on the main thread does its work off it`() = runBlocking {
        val f = OrchestratorFixture(engine = spiedEngine(), bugReportAnalyzer = BugReportFixtures.analyzer())
        try {
            spy(f)
            f.orchestrator.analyzeBugReport(mockk<Uri>(relaxed = true))
            assertOffMain("loadBundledRules", "evaluateRecords", "persistChunk", "finish")
        } finally {
            f.close()
        }
    }

    @Test
    fun `an intrusion-log import launched on the main thread does its work off it`() = runBlocking {
        val lines = listOf(
            """{"dns_event":{"event_id":0,"event_time":1787400345334,"package_name":"com.a",""" +
                """"hostname":"h1.example.com","ip_addresses":["/1.1.1.1"],"ip_addresses_count":1}}""",
            """{"security_event":{"event_id":2,"event_time":1787400350000,"tag":210002,"data":["id"]}}""",
        )
        val f = IntrusionLogZips.fixture(spiedEngine()) { IntrusionLogZips.zip("2026-08-22.txt" to lines) }
        try {
            spy(f)
            f.orchestrator.analyzeIntrusionLog(mockk<Uri>(relaxed = true))
            assertOffMain("loadBundledRules", "evaluateRecords", "persistChunk", "finish")
        } finally {
            f.close()
        }
    }
}

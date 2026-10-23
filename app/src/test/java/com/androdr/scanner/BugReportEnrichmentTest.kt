package com.androdr.scanner

import android.net.Uri
import com.androdr.data.model.ScanState
import com.androdr.data.store.StoreFixture
import com.androdr.sigma.StoreRecord
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Bug-report APK-hash enrichment reads the newest stored live scan's app records
 * (`TelemetryReader.latestLive`) instead of `ScanOrchestrator`'s deleted last-scan cache: records
 * captured within `APP_ENRICHMENT_MAX_AGE_MS` spare a fresh ~14 s app collection; older ones do not.
 */
@RunWith(RobolectricTestRunner::class)
class BugReportEnrichmentTest {
    private val uri = mockk<Uri>(relaxed = true)
    private val f = OrchestratorFixture(bugReportAnalyzer = mockk(relaxed = true))

    @Before fun setUp() {
        coEvery { f.bugReportAnalyzer.analyze(any()) } returns
            BugReportAnalyzer.BugReportAnalysisResult()
    }

    @After fun tearDown() = f.close()

    private fun app(pkg: String, hash: String) =
        StoreRecord(StoreFixture.app(pkg).fields + ("apk_hash" to hash))

    private suspend fun storeLiveScan(id: Long, capturedAt: Long) {
        f.w.f.scan(id)
        f.w.f.persist(id, "app_scanner", listOf(app("com.example.a", "a".repeat(64))), capturedAt = capturedAt)
        f.w.f.setState(id, ScanState.COMPLETE)
    }

    @Test
    fun `a recent stored live scan's app records spare a fresh collection`() = runBlocking {
        storeLiveScan(1_000L, capturedAt = System.currentTimeMillis())
        f.orchestrator.analyzeBugReport(uri)
        coVerify(exactly = 0) { f.appScanner.collectTelemetry() }
    }

    @Test
    fun `stored app records older than the window are not reused`() = runBlocking {
        storeLiveScan(1_000L, capturedAt = System.currentTimeMillis() - 10 * 60_000L)
        f.orchestrator.analyzeBugReport(uri)
        coVerify(exactly = 1) { f.appScanner.collectTelemetry() }
    }

    @Test
    fun `stored hashes are keyed by package, empty hashes skipped`() = runBlocking {
        storeLiveScan(1_000L, capturedAt = System.currentTimeMillis())
        val records = f.w.f.reader.latestLive("app_scanner", Long.MAX_VALUE / 2)!!
        assertEquals(mapOf("com.example.a" to "a".repeat(64)), ScanOrchestrator.storedHashByPackage(records))
    }
}

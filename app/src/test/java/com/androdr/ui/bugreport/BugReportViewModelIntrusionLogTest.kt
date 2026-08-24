package com.androdr.ui.bugreport

import android.net.Uri
import com.androdr.scanner.ArtifactType
import com.androdr.scanner.BugReportAnalyzer
import com.androdr.scanner.IntrusionLogAnalysisResult
import com.androdr.scanner.IntrusionLogStats
import com.androdr.scanner.ScanOrchestrator
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * #342 B1 (surfacing half): the intrusion-log analysis may succeed while the
 * PERSIST fails. When it does, [ScanOrchestrator.analyzeIntrusionLog] rethrows
 * [ScanOrchestrator.IntrusionLogPersistException]; the ViewModel must then show
 * an error and must NOT render the "Intrusion log analyzed — N events" summary
 * card for data that was never saved. The original code swallowed the persist
 * failure and returned the result, so the card rendered on a false success.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class BugReportViewModelIntrusionLogTest {

    private val mainDispatcher = UnconfinedTestDispatcher()

    @Before
    fun setUp() = Dispatchers.setMain(mainDispatcher)

    @After
    fun tearDown() = Dispatchers.resetMain()

    private fun stats() = IntrusionLogStats(
        dnsEventCount = 3, connectEventCount = 1, securityEventCount = 2,
        duplicatesCollapsed = 0, malformedLines = 0,
        earliestEventMs = null, latestEventMs = null
    )

    @Test
    fun `failed persist surfaces an error and no summary card`() = runTest {
        val orchestrator = mockk<ScanOrchestrator>()
        coEvery { orchestrator.analyzeArtifact(any()) } throws
            ScanOrchestrator.IntrusionLogPersistException(RuntimeException("db write failed"))
        val vm = BugReportViewModel(mockk(relaxed = true), orchestrator)

        vm.analyzeUri(mockk<Uri>(relaxed = true))

        assertNull("no summary card may render for data that was not saved", vm.intrusionLogSummary.value)
        assertNotNull("the persist failure must be surfaced", vm.errorMessage.value)
        assertTrue(
            "the message must be the honest 'failed to save' text: ${vm.errorMessage.value}",
            vm.errorMessage.value!!.contains("failed", ignoreCase = true)
        )
        assertTrue("no findings render on a failed persist", vm.findings.value.isEmpty())
        assertTrue(vm.analysisFinished.value)
    }

    @Test
    fun `successful import renders the summary card`() = runTest {
        val orchestrator = mockk<ScanOrchestrator>()
        val result = IntrusionLogAnalysisResult(
            findings = emptyList(), dnsEvents = emptyList(),
            networkEvents = emptyList(), securityEvents = emptyList(), stats = stats()
        )
        coEvery { orchestrator.analyzeArtifact(any()) } returns
            ScanOrchestrator.ArtifactAnalysis.IntrusionLog(result)
        val vm = BugReportViewModel(mockk(relaxed = true), orchestrator)

        vm.analyzeUri(mockk<Uri>(relaxed = true))

        assertNotNull("a successful import must render the summary card", vm.intrusionLogSummary.value)
        assertEquals(3, vm.intrusionLogSummary.value!!.dnsEventCount)
        assertNull("no error on success", vm.errorMessage.value)
    }

    // ── #356: the screen must name the artifact that was ACTUALLY analyzed ──
    //
    // One screen accepts both artifacts, so its result copy has to follow the
    // sniffer's routing decision. Without this flow the UI called every import a
    // "system diagnostic", which misidentifies an intrusion log importer's
    // evidence, and a stale label could survive a later failed import.

    @Test
    fun `an intrusion log import records INTRUSION_LOG as the analyzed artifact`() = runTest {
        val orchestrator = mockk<ScanOrchestrator>()
        val result = IntrusionLogAnalysisResult(
            findings = emptyList(), dnsEvents = emptyList(),
            networkEvents = emptyList(), securityEvents = emptyList(), stats = stats()
        )
        coEvery { orchestrator.analyzeArtifact(any()) } returns
            ScanOrchestrator.ArtifactAnalysis.IntrusionLog(result)
        val vm = BugReportViewModel(mockk(relaxed = true), orchestrator)

        vm.analyzeUri(mockk<Uri>(relaxed = true))

        assertEquals(ArtifactType.INTRUSION_LOG, vm.analyzedArtifact.value)
    }

    @Test
    fun `a bug report import records BUG_REPORT as the analyzed artifact`() = runTest {
        val orchestrator = mockk<ScanOrchestrator>()
        coEvery { orchestrator.analyzeArtifact(any()) } returns
            ScanOrchestrator.ArtifactAnalysis.BugReport(
                BugReportAnalyzer.BugReportAnalysisResult(findings = emptyList(), timeline = emptyList())
            )
        val vm = BugReportViewModel(mockk(relaxed = true), orchestrator)

        vm.analyzeUri(mockk<Uri>(relaxed = true))

        assertEquals(ArtifactType.BUG_REPORT, vm.analyzedArtifact.value)
    }

    @Test
    fun `a failed analysis clears the previous artifact label`() = runTest {
        val orchestrator = mockk<ScanOrchestrator>()
        val result = IntrusionLogAnalysisResult(
            findings = emptyList(), dnsEvents = emptyList(),
            networkEvents = emptyList(), securityEvents = emptyList(), stats = stats()
        )
        coEvery { orchestrator.analyzeArtifact(any()) } returns
            ScanOrchestrator.ArtifactAnalysis.IntrusionLog(result)
        val vm = BugReportViewModel(mockk(relaxed = true), orchestrator)
        vm.analyzeUri(mockk<Uri>(relaxed = true))
        assertEquals(ArtifactType.INTRUSION_LOG, vm.analyzedArtifact.value)

        coEvery { orchestrator.analyzeArtifact(any()) } throws
            ScanOrchestrator.UnrecognizedArtifactException()
        vm.analyzeUri(mockk<Uri>(relaxed = true))

        assertNull(
            "a stale label would attribute the old artifact's identity to a failed import",
            vm.analyzedArtifact.value
        )
    }
}

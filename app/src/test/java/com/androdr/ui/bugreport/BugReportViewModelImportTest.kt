package com.androdr.ui.bugreport

import android.net.Uri
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetryState
import com.androdr.data.store.Preflight
import com.androdr.scanner.BugReportAnalyzer
import com.androdr.scanner.ImportPreflight
import com.androdr.scanner.IntrusionLogAnalysisResult
import com.androdr.scanner.IntrusionLogStats
import com.androdr.scanner.ScanOrchestrator
import com.androdr.scanner.WriteResult
import io.mockk.coEvery
import io.mockk.coVerify
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

/** A7c: the import preflight dialog gates the import; the import card shows what was stored. */
@OptIn(ExperimentalCoroutinesApi::class)
class BugReportViewModelImportTest {

    @Before fun setUp() = Dispatchers.setMain(UnconfinedTestDispatcher())

    @After fun tearDown() = Dispatchers.resetMain()

    private val scan = ScanResult(
        id = 1L, timestamp = 1L, findings = emptyList(), bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0,
    )
    private val uri = mockk<Uri>(relaxed = true)

    private fun stats(truncated: Boolean = false) = IntrusionLogStats(
        dnsEventCount = 3, connectEventCount = 1, securityEventCount = 2, duplicatesCollapsed = 0,
        malformedLines = 0, earliestEventMs = null, latestEventMs = null, truncated = truncated,
    )

    private fun write(state: TelemetryState = TelemetryState.STORED, space: Long = 0L) =
        WriteResult(4, 2, 1, state, scan, spaceToFree = space)

    private fun orchestratorReturning(result: IntrusionLogAnalysisResult) = mockk<ScanOrchestrator> {
        coEvery { analyzeArtifact(any()) } returns ScanOrchestrator.ArtifactAnalysis.IntrusionLog(result)
    }

    private fun vm(orchestrator: ScanOrchestrator, preflight: Preflight) = BugReportViewModel(
        mockk(relaxed = true), orchestrator,
        mockk<ImportPreflight> { coEvery { check(any()) } returns preflight },
    )

    @Test
    fun `a tight preflight asks first and imports nothing until Import anyway`() = runTest {
        val orchestrator = orchestratorReturning(IntrusionLogAnalysisResult(emptyList(), stats(), write = write()))
        val vm = vm(orchestrator, Preflight.Tight(estimate = 500L, free = 900L))

        vm.onFilePicked(uri)

        assertEquals(PreflightPrompt(uri, 500L, 900L), vm.preflightPrompt.value)
        coVerify(exactly = 0) { orchestrator.analyzeArtifact(any()) }
        assertNull(vm.analyzedArtifact.value)

        vm.confirmImportAnyway()

        assertNull(vm.preflightPrompt.value)
        coVerify(exactly = 1) { orchestrator.analyzeArtifact(uri) }
        assertNotNull(vm.importCard.value)
    }

    @Test
    fun `an unknown size is offered as unknown, not as zero`() = runTest {
        val orchestrator = orchestratorReturning(IntrusionLogAnalysisResult(emptyList(), stats()))
        val vm = vm(orchestrator, Preflight.Tight(null, 900L))
        vm.onFilePicked(uri)
        assertNull(vm.preflightPrompt.value!!.estimateBytes)
    }

    @Test
    fun `cancelling the preflight imports nothing`() = runTest {
        val orchestrator = orchestratorReturning(IntrusionLogAnalysisResult(emptyList(), stats()))
        val vm = vm(orchestrator, Preflight.Tight(1L, 1L))
        vm.onFilePicked(uri)
        vm.dismissPreflight()
        assertNull(vm.preflightPrompt.value)
        coVerify(exactly = 0) { orchestrator.analyzeArtifact(any()) }
    }

    @Test
    fun `enough space imports without a prompt`() = runTest {
        val orchestrator = orchestratorReturning(IntrusionLogAnalysisResult(emptyList(), stats()))
        val vm = vm(orchestrator, Preflight.Ok)
        vm.onFilePicked(uri)
        assertNull(vm.preflightPrompt.value)
        coVerify(exactly = 1) { orchestrator.analyzeArtifact(uri) }
    }

    @Test
    fun `an intrusion log card shows the write counts and the truncation bound`() = runTest {
        val vm = vm(
            orchestratorReturning(IntrusionLogAnalysisResult(emptyList(), stats(truncated = true), write = write())),
            Preflight.Ok,
        )
        vm.onFilePicked(uri)
        val card = vm.importCard.value!!
        assertEquals(listOf(4, 2, 1), listOf(card.newFacts, card.alreadyStored, card.duplicatesDropped))
        assertEquals(listOf(ImportCard.INTRUSION_LIMIT), card.trippedBounds)
    }

    @Test
    fun `a bug report card shows bound trips and the evaluate-only space message`() = runTest {
        val orchestrator = mockk<ScanOrchestrator> {
            coEvery { analyzeArtifact(any()) } returns ScanOrchestrator.ArtifactAnalysis.BugReport(
                BugReportAnalyzer.BugReportAnalysisResult(
                    findings = emptyList(), timeline = emptyList(), boundTrips = listOf("M: stopped at 9 records"),
                    write = write(TelemetryState.FAILED, space = 123L),
                )
            )
        }
        val vm = vm(orchestrator, Preflight.Ok)
        vm.onFilePicked(uri)
        val card = vm.importCard.value!!
        assertEquals(listOf("M: stopped at 9 records"), card.trippedBounds)
        assertEquals(ImportNotice.FreeSpace(123L), card.notice)
    }

    @Test
    fun `a failed import shows no card, and the previous card is cleared`() = runTest {
        val orchestrator = orchestratorReturning(IntrusionLogAnalysisResult(emptyList(), stats(), write = write()))
        val vm = vm(orchestrator, Preflight.Ok)
        vm.onFilePicked(uri)
        assertNotNull(vm.importCard.value)

        coEvery { orchestrator.analyzeArtifact(any()) } throws
            ScanOrchestrator.BugReportPersistException(RuntimeException("disk"))
        vm.onFilePicked(uri)

        assertNull("no card may claim facts that were not stored", vm.importCard.value)
        assertTrue(vm.errorMessage.value!!.contains("nothing was imported"))
    }

    @Test
    fun `source gate - the file picker goes through the preflight`() {
        val src = java.io.File("src/main/java/com/androdr/ui/bugreport/BugReportScreen.kt").readText()
        assertTrue(src.contains("viewModel.onFilePicked(it)"))
        assertTrue("the picker must not bypass the preflight", !src.contains("viewModel.analyzeUri("))
        assertTrue(src.contains("import_preflight_anyway"))
    }
}

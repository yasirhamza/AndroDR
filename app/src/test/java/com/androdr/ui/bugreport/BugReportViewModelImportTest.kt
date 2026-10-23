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
        orchestrator,
        mockk<ImportPreflight> { coEvery { check(any()) } returns preflight }, mockk(relaxed = true),
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
        assertEquals(ImportNotice.LowSpace(4, 123L, null), card.notice)
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
    fun `a preflight that throws asks with an unknown size and invents no free-space figure`() = runTest {
        val orchestrator = orchestratorReturning(IntrusionLogAnalysisResult(emptyList(), stats()))
        val vm = BugReportViewModel(
            orchestrator,
            mockk<ImportPreflight> { coEvery { check(any()) } throws IllegalStateException("provider gone") },
            mockk(relaxed = true),
        )
        vm.onFilePicked(uri)
        val prompt = vm.preflightPrompt.value!!
        assertTrue(prompt.sizeUnknown)
        assertNull("0 B free would be made up", prompt.freeBytes)
    }

    @Test
    fun `only a known estimate is presented as low space`() {
        assertTrue(PreflightPrompt(uri, null, 40L shl 30).sizeUnknown)
        assertTrue(!PreflightPrompt(uri, 500L, 600L).sizeUnknown)
    }

    @Test
    fun `the preflight estimate reaches the card of a low-space import`() = runTest {
        val orchestrator = orchestratorReturning(
            IntrusionLogAnalysisResult(emptyList(), stats(), write = write(TelemetryState.FAILED, space = 5L))
        )
        val vm = vm(orchestrator, Preflight.Tight(estimate = 800L, free = 900L))
        vm.onFilePicked(uri)
        vm.confirmImportAnyway()
        assertEquals(ImportNotice.LowSpace(4, 5L, 800L), vm.importCard.value!!.notice)
    }

    @Test
    fun `a second pick while the size check runs is ignored`() = runTest {
        val gate = kotlinx.coroutines.CompletableDeferred<Preflight>()
        val checker = mockk<ImportPreflight> { coEvery { check(any()) } coAnswers { gate.await() } }
        val orchestrator = orchestratorReturning(IntrusionLogAnalysisResult(emptyList(), stats()))
        val vm = BugReportViewModel(orchestrator, checker, mockk(relaxed = true))
        vm.onFilePicked(uri)
        assertTrue(vm.checkingSize.value)
        vm.onFilePicked(uri)
        gate.complete(Preflight.Ok)
        coVerify(exactly = 1) { checker.check(any()) }
        coVerify(exactly = 1) { orchestrator.analyzeArtifact(any()) }
        assertTrue(!vm.checkingSize.value)
    }

    @Test
    fun `source gate - copy never claims nothing was stored and the unknown size has its own title`() {
        val strings = java.io.File("src/main/res/values/strings.xml").readText()
        assertTrue(strings.contains("import_preflight_title_unknown"))
        assertTrue("no blanket 'keeps no records' promise", !strings.contains("keeps no records"))
        assertTrue("no 'checked but not stored' without the stored count",
            !strings.contains("so the records were checked but not stored"))
        val composables = java.io.File("src/main/java/com/androdr/ui/bugreport/ImportComposables.kt").readText()
        assertTrue(composables.contains("import_preflight_title_unknown"))
    }

    @Test
    fun `source gate - the file picker goes through the preflight`() {
        val src = java.io.File("src/main/java/com/androdr/ui/bugreport/BugReportScreen.kt").readText()
        assertTrue(src.contains("viewModel.onFilePicked(it)"))
        assertTrue("the picker must not bypass the preflight", !src.contains("viewModel.analyzeUri("))
        val composables = java.io.File("src/main/java/com/androdr/ui/bugreport/ImportComposables.kt").readText()
        assertTrue(composables.contains("import_preflight_anyway"))
    }
}

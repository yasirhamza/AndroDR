package com.androdr.ui.apps

import com.androdr.data.db.PrivacyDao
import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyScan
import com.androdr.data.model.PrivacyTrackerEvidence
import com.androdr.data.repo.FindingsRepository
import com.androdr.data.repo.SettingsRepository
import com.androdr.privacy.InspectOutcome
import com.androdr.privacy.InstalledVersions
import com.androdr.privacy.model.TrackerCategory
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class AppScanViewModelPrivacyTest {
    @Before fun setUp() = Dispatchers.setMain(UnconfinedTestDispatcher())

    @After fun tearDown() = Dispatchers.resetMain()

    private val scan = PrivacyScan(
        id = 1, startedAt = 10, finishedAt = 20, appsTotal = 1, appsInspected = 1, appsPartial = 0, appsFailed = 0,
        registrySize = 428, registrySha256 = "", dnsWindowStart = 0, dnsCoverageDays = 7,
        usageCoverageFrom = null, networkStatus = "COMPLETE",
    )
    private val results = listOf(
        PrivacyAppResult(1, "ads", 5, "Ads", false, InspectOutcome.INSPECTED.name, null),
    )

    private fun ev(id: Int, cats: String) = PrivacyTrackerEvidence(
        1, "ads", id, "T$id", "https://t$id.example", cats, true, 0, 0, null, null, null, false,
    )

    private val evidence = listOf(ev(1, "Advertisement"), ev(2, "Analytics"))

    private fun vm(
        scanValue: PrivacyScan? = scan,
        refused: Set<TrackerCategory> = setOf(TrackerCategory.ADVERTISEMENT),
        installed: Map<String, Long> = mapOf("ads" to 5L),
    ): AppScanViewModel {
        val findings = mockk<FindingsRepository>(relaxed = true) { every { latestLive() } returns flowOf(null) }
        val dao = mockk<PrivacyDao> {
            every { latestCompleted() } returns MutableStateFlow(scanValue)
            every { results(any()) } returns flowOf(results)
            every { evidence(any()) } returns flowOf(evidence)
        }
        val settings = mockk<SettingsRepository>(relaxed = true) {
            every { refusedTrackerCategories } returns MutableStateFlow(refused)
        }
        val versions = mockk<InstalledVersions> { coEvery { versionCodes(any()) } returns installed }
        return AppScanViewModel(findings, dao, settings, versions)
    }

    private fun AppScanViewModel.crossover(): PrivacyCrossover {
        // WhileSubscribed: keep a collector alive so the upstream runs under the unconfined dispatcher.
        privacyByPackage.onEach { }.launchIn(CoroutineScope(Dispatchers.Main))
        return privacyByPackage.value
    }

    @Test fun `privacyByPackage reflects the latest scan under the current threshold`() {
        val row = vm().crossover().byPackage.getValue("ads")
        assertEquals(2, row.trackers.size)
        assertEquals(1, row.refusedInCode)
    }

    @Test fun `empty without a privacy scan`() {
        val c = vm(scanValue = null).crossover()
        assertNull(c.scannedAt)
        assertTrue(c.byPackage.isEmpty())
    }

    @Test fun `an app updated since the privacy scan has no line`() {
        val c = vm(installed = mapOf("ads" to 6L)).crossover()
        assertTrue(c.byPackage.isEmpty())
    }

    @Test fun `scannedAt is the scan's finish time`() {
        assertEquals(20L, vm().crossover().scannedAt)
    }

    @Test fun `versionCodes is asked only for packages that have trackers, once per distinct input`() {
        val withNone = results + PrivacyAppResult(1, "clean", 3, "Clean", false, InspectOutcome.INSPECTED.name, null)
        // Not a StateFlow: it re-emits an equal list, as Room does on any write to the table.
        val resultsFlow = MutableSharedFlow<List<PrivacyAppResult>>(replay = 1)
        resultsFlow.tryEmit(withNone)
        val asked = mutableListOf<List<String>>()
        val findings = mockk<FindingsRepository>(relaxed = true) { every { latestLive() } returns flowOf(null) }
        val dao = mockk<PrivacyDao> {
            every { latestCompleted() } returns MutableStateFlow(scan)
            every { results(any()) } returns resultsFlow
            every { evidence(any()) } returns flowOf(evidence)
        }
        val settings = mockk<SettingsRepository>(relaxed = true) {
            every { refusedTrackerCategories } returns MutableStateFlow(setOf(TrackerCategory.ADVERTISEMENT))
        }
        val versions = mockk<InstalledVersions> {
            coEvery { versionCodes(any()) } answers {
                asked += firstArg<List<String>>()
                mapOf("ads" to 5L, "clean" to 3L)
            }
        }
        val vm = AppScanViewModel(findings, dao, settings, versions)
        val c = vm.crossover()
        assertEquals(setOf("ads"), c.byPackage.keys)
        assertTrue(resultsFlow.tryEmit(withNone.map { it.copy() })) // equal content, new instance
        assertEquals(listOf(listOf("ads")), asked)
    }
}

package com.androdr.ui.privacy

import com.androdr.R
import com.androdr.data.db.PrivacyDao
import com.androdr.data.model.NetworkStatus
import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyScan
import com.androdr.data.model.PrivacyTrackerEvidence
import com.androdr.data.repo.SettingsRepository
import com.androdr.privacy.InspectOutcome
import com.androdr.privacy.PrivacyRanking
import com.androdr.privacy.PrivacyScanProgress
import com.androdr.privacy.PrivacyScanRunner
import com.androdr.privacy.RowSection
import com.androdr.privacy.model.TrackerCategory
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class PrivacyViewModelTest {
    @Before fun setUp() = Dispatchers.setMain(UnconfinedTestDispatcher())

    @After fun tearDown() = Dispatchers.resetMain()

    private fun scan(status: NetworkStatus = NetworkStatus.COMPLETE, days: Int = 7) = PrivacyScan(
        id = 1, startedAt = 10, finishedAt = 20, appsTotal = 3, appsInspected = 2, appsPartial = 0, appsFailed = 1,
        registrySize = 428, registrySha256 = "", dnsWindowStart = 0, dnsCoverageDays = days,
        usageCoverageFrom = null, networkStatus = status.name,
    )

    private val results = listOf(
        PrivacyAppResult(1, "ads", 1, "Ads", false, InspectOutcome.INSPECTED.name, null),
        PrivacyAppResult(1, "broken", 1, "Broken", false, InspectOutcome.COULD_NOT_INSPECT.name, "unreadable"),
        PrivacyAppResult(1, "sys", 1, "Sys", true, InspectOutcome.INSPECTED.name, null),
    )
    private fun ev(pkg: String, id: Int, name: String) = PrivacyTrackerEvidence(
        1, pkg, id, name, "https://$name.example", "Advertisement", true, 0, 0, null, null, null, false,
    )

    private val evidence = listOf(
        ev("ads", 1, "AdCo"),
        ev("sys", 2, "AdCo2"),
    )

    private class Fixture(scanValue: PrivacyScan?) {
        val scanFlow = MutableStateFlow(scanValue)
        val refused = MutableStateFlow(setOf(TrackerCategory.ADVERTISEMENT))
        val showSystem = MutableStateFlow(false)
        val progress = MutableStateFlow<PrivacyScanProgress>(PrivacyScanProgress.Idle)
        val available = MutableStateFlow(true)
    }

    private fun vm(f: Fixture, runner: PrivacyScanRunner = runner(f)): PrivacyViewModel {
        val dao = mockk<PrivacyDao> {
            every { latestCompleted() } returns f.scanFlow
            every { results(any()) } returns flowOf(results)
            every { evidence(any()) } returns flowOf(evidence)
        }
        val settings = mockk<SettingsRepository>(relaxed = true) {
            every { refusedTrackerCategories } returns f.refused
            every { privacyShowSystemApps } returns f.showSystem
        }
        return PrivacyViewModel(dao, runner, settings)
    }

    private fun runner(f: Fixture) = mockk<PrivacyScanRunner>(relaxed = true) {
        every { progress } returns f.progress
        every { registryAvailable } returns f.available
        every { start() } returns true
        coEvery { deleteAll() } returns true
    }

    @Test fun `sections come from PrivacyRanking with the current settings`() = runTest {
        val f = Fixture(scan())
        val vm = vm(f)
        val s = vm.state.first { it.scan != null }
        assertEquals(PrivacyRanking.rows(results, evidence, f.refused.value, false), s.sections)
        assertEquals(428, s.registrySizeAtScan)
        assertEquals(7, s.networkDays)
        assertEquals(f.refused.value, s.refused)
        assertEquals(PrivacyRanking.byTracker(s.sections.flatMap { it.second }), s.byTracker)
        f.showSystem.value = true
        f.refused.value = setOf(TrackerCategory.PROFILING)
        val s2 = vm.state.first { it.showSystemApps }
        assertEquals(PrivacyRanking.rows(results, evidence, setOf(TrackerCategory.PROFILING), true), s2.sections)
        assertTrue(s2.sections.toMap().getValue(RowSection.OTHER).any { it.packageName == "sys" })
    }

    @Test fun `no scan yields empty state`() = runTest {
        val s = vm(Fixture(null)).state.first()
        assertNull(s.scan)
        assertNull(s.registrySizeAtScan)
    }

    @Test fun `runScan delegates to the runner`() = runTest {
        val f = Fixture(scan())
        val r = runner(f)
        val vm = vm(f, r)
        vm.runScan()
        verify(exactly = 1) { r.start() }
        assertNull(vm.message.value)
    }

    @Test fun `runScan when one is running exposes privacy_running_elsewhere`() = runTest {
        val f = Fixture(scan())
        val r = runner(f)
        every { r.start() } returns false
        val vm = vm(f, r)
        vm.runScan()
        assertEquals(R.string.privacy_running_elsewhere, vm.message.value)
        vm.messageShown()
        assertNull(vm.message.value)
    }

    @Test fun `deleteResults delegates to the runner`() = runTest {
        val f = Fixture(scan())
        val r = runner(f)
        val vm = vm(f, r)
        vm.deleteResults()
        coVerify(exactly = 1) { r.deleteAll() }
        assertNull(vm.message.value)
    }

    @Test fun `a refused delete exposes privacy_delete_refused`() = runTest {
        val f = Fixture(scan())
        val r = runner(f)
        coEvery { r.deleteAll() } returns false
        val vm = vm(f, r)
        vm.deleteResults()
        assertEquals(R.string.privacy_delete_refused, vm.message.value)
    }

    @Test fun `networkStatus TRUNCATED and FAILED expose their lines`() = runTest {
        val f = Fixture(scan(NetworkStatus.TRUNCATED))
        val vm = vm(f)
        assertEquals(R.string.privacy_network_truncated, vm.state.first { it.scan != null }.networkNotice)
        f.scanFlow.value = scan(NetworkStatus.FAILED)
        val failed = vm.state.first { it.scan?.networkStatus == "FAILED" }
        assertEquals(R.string.privacy_network_failed, failed.networkNotice)
        f.scanFlow.value = scan(NetworkStatus.COMPLETE)
        assertNull(vm.state.first { it.scan?.networkStatus == "COMPLETE" }.networkNotice)
    }

    @Test fun `a FAILED network step never yields the no-monitor line`() = runTest {
        val f = Fixture(scan(NetworkStatus.FAILED, days = 0))
        val s = vm(f).state.first { it.scan != null }
        assertEquals(NetworkCoverage.Hidden, s.networkCoverage)
        assertEquals(R.string.privacy_network_failed, s.networkNotice)
    }

    @Test fun `a COMPLETE step with zero days yields the no-monitor line`() = runTest {
        val s = vm(Fixture(scan(NetworkStatus.COMPLETE, days = 0))).state.first { it.scan != null }
        assertEquals(NetworkCoverage.NoMonitor, s.networkCoverage)
        assertNull(s.networkNotice)
    }

    @Test fun `a TRUNCATED step with days yields coverage plus the truncated line`() = runTest {
        val s = vm(Fixture(scan(NetworkStatus.TRUNCATED, days = 4))).state.first { it.scan != null }
        assertEquals(NetworkCoverage.Days(4), s.networkCoverage)
        assertEquals(R.string.privacy_network_truncated, s.networkNotice)
    }

    @Test fun `no scan and a PENDING scan show no coverage line`() = runTest {
        assertEquals(NetworkCoverage.Hidden, PrivacyUiState().networkCoverage)
        val s = vm(Fixture(scan(NetworkStatus.PENDING, days = 0))).state.first { it.scan != null }
        assertEquals(NetworkCoverage.Hidden, s.networkCoverage)
    }

    @Test fun `a null registry disables Run and exposes registry-unavailable`() = runTest {
        val f = Fixture(scan())
        f.available.value = false
        val s = vm(f).state.first { it.scan != null }
        assertFalse(s.registryAvailable)
        assertFalse(s.canRun)
    }

    @Test fun `a later successful refresh enables Run without recreating the ViewModel`() = runTest {
        val f = Fixture(scan())
        f.available.value = false
        val vm = vm(f)
        assertFalse(vm.state.first { it.scan != null }.canRun)
        f.available.value = true
        assertTrue(vm.state.first { it.registryAvailable }.canRun)
    }

    @Test fun `Run is disabled while a scan is in progress`() = runTest {
        val f = Fixture(scan())
        val vm = vm(f)
        f.progress.value = PrivacyScanProgress.Running(3, 10)
        val s = vm.state.first { it.progress is PrivacyScanProgress.Running }
        assertFalse(s.canRun)
    }

    @Test fun `settings setters write through`() = runTest {
        val f = Fixture(scan())
        val settings = mockk<SettingsRepository>(relaxed = true) {
            every { refusedTrackerCategories } returns f.refused
            every { privacyShowSystemApps } returns f.showSystem
        }
        val dao = mockk<PrivacyDao> { every { latestCompleted() } returns f.scanFlow }
        val vm = PrivacyViewModel(dao, runner(f), settings)
        vm.setRefused(setOf(TrackerCategory.LOCATION))
        vm.setShowSystemApps(true)
        coVerify { settings.setRefusedTrackerCategories(setOf(TrackerCategory.LOCATION)) }
        coVerify { settings.setPrivacyShowSystemApps(true) }
    }
}

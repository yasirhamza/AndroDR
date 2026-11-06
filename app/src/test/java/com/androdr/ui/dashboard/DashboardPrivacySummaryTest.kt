package com.androdr.ui.dashboard

import com.androdr.data.db.PrivacyDao
import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyScan
import com.androdr.data.model.PrivacyTrackerEvidence
import com.androdr.data.repo.SettingsRepository
import com.androdr.privacy.InspectOutcome
import com.androdr.privacy.PrivacyRanking
import com.androdr.privacy.RowSection
import com.androdr.privacy.model.TrackerCategory
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DashboardPrivacySummaryTest {
    private val scan = PrivacyScan(
        id = 1, startedAt = 10, finishedAt = 20, appsTotal = 3, appsInspected = 2, appsPartial = 0,
        appsFailed = 1, registrySize = 5, registrySha256 = "", dnsWindowStart = 0, dnsCoverageDays = 0,
        usageCoverageFrom = null, networkStatus = "COMPLETE",
    )

    private fun result(pkg: String, outcome: InspectOutcome, system: Boolean = false) =
        PrivacyAppResult(1, pkg, 1, pkg, system, outcome.name, null)

    private fun ev(pkg: String, id: Int, cat: String) =
        PrivacyTrackerEvidence(1, pkg, id, "T$id", "https://t", cat, true, 0, 0, null, null, null, true)

    private val results = listOf(
        result("ads", InspectOutcome.INSPECTED),
        result("crash", InspectOutcome.INSPECTED),
        result("sys", InspectOutcome.INSPECTED, system = true),
        result("broken", InspectOutcome.COULD_NOT_INSPECT),
    )
    private val evidence = listOf(
        ev("ads", 1, "Advertisement"), ev("crash", 2, "Crash reporting"), ev("sys", 3, "Advertisement"),
    )

    private fun dao(s: PrivacyScan?) = mockk<PrivacyDao> {
        every { latestCompleted() } returns flowOf(s)
        every { results(any()) } returns flowOf(results)
        every { evidence(any()) } returns flowOf(evidence)
    }

    private fun settings(refused: MutableStateFlow<Set<TrackerCategory>>, sys: MutableStateFlow<Boolean>) =
        mockk<SettingsRepository> {
            every { refusedTrackerCategories } returns refused
            every { privacyShowSystemApps } returns sys
        }

    @Test fun `null when never scanned`() = runTest {
        val s = settings(MutableStateFlow(emptySet()), MutableStateFlow(false))
        assertNull(privacySummaryFlow(dao(null), s).first())
    }

    @Test fun `failed clause present when notInspected greater than zero`() = runTest {
        val s = settings(MutableStateFlow(setOf(TrackerCategory.ADVERTISEMENT)), MutableStateFlow(false))
        val summary = privacySummaryFlow(dao(scan), s).first()!!
        assertEquals(1, summary.notInspected)
        assertEquals(1, summary.crossing)
        assertEquals(20L, summary.scannedAt)
    }

    @Test fun `changing the refused set or the system toggle changes the summary exactly as the screen rows`() =
        runTest {
            val refused = MutableStateFlow(setOf(TrackerCategory.ADVERTISEMENT))
            val sys = MutableStateFlow(false)
            val flow = privacySummaryFlow(dao(scan), settings(refused, sys))
            val sets = listOf(
                setOf(TrackerCategory.ADVERTISEMENT),
                setOf(TrackerCategory.ADVERTISEMENT, TrackerCategory.CRASH_REPORTING),
                emptySet(),
            )
            for (r in sets) {
                for (show in listOf(false, true)) {
                    refused.value = r
                    sys.value = show
                    val summary = flow.first()!!
                    val rows = PrivacyRanking.rows(results, evidence, r, show).toMap()
                    val crossing = rows[RowSection.CROSSING].orEmpty()
                    assertEquals("refused=$r show=$show", crossing.size, summary.crossing)
                    assertEquals(crossing.count { it.newCrossing }, summary.newCrossing)
                    val incomplete = rows.values.flatten().count { it.outcome != InspectOutcome.INSPECTED }
                    assertEquals(incomplete, summary.notInspected)
                }
            }
        }
}

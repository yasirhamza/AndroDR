package com.androdr.ui.timeline

import com.androdr.data.db.TimelineFilter
import com.androdr.data.model.TelemetrySource
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/**
 * C5 filter bar (ruling R30): one dismissible chip per active filter, the Filters button's count is
 * the number of chips, dismissing a chip clears exactly that filter, and the search text reaches
 * the filter ([TimelineFilter.query]) only after a quiet 300 ms.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class TimelineViewModelTest {
    private val dispatcher = StandardTestDispatcher()

    @Before fun setUp() = Dispatchers.setMain(dispatcher)

    @After fun tearDown() = Dispatchers.resetMain()

    private fun vm() = TimelineViewModel(
        appContext = mockk(relaxed = true),
        db = mockk(relaxed = true),
        entries = mockk(relaxed = true),
        knownAppResolver = mockk(relaxed = true),
        sigmaRuleEngine = mockk(relaxed = true),
        scanRepository = mockk(relaxed = true),
        reportExporter = mockk(relaxed = true),
        clusterMembers = mockk(relaxed = true),
        signalMembers = mockk(relaxed = true),
    )

    /** Every filter the bar can show, set at once. */
    private fun TestScope.loaded(): TimelineViewModel = vm().apply {
        setScanFilter(7L)
        setPackageFilter("com.bank")
        setSourceFilter(TelemetrySource.BUGREPORT_IMPORT)
        toggleSeverity("HIGH")
        toggleSeverity("CRITICAL")
        setDateRange(1_000L, 1_000L + DAY)
        setFindingsAndEvidenceOnly(true)
        setSearchText("overlay")
        advanceTimeBy(SEARCH_SETTLE)
        runCurrent()
    }

    @Test
    fun `no filter, no chip`() = runTest(dispatcher) {
        assertEquals(emptyList<ActiveFilter>(), activeFiltersOf(vm().filter.value))
    }

    @Test
    fun `one chip per active filter, and the count is the chips`() = runTest(dispatcher) {
        val chips = activeFiltersOf(loaded().filter.value)
        assertEquals(
            listOf(
                ActiveFilter.Scan(7L),
                ActiveFilter.Package("com.bank"),
                ActiveFilter.Source(TelemetrySource.BUGREPORT_IMPORT),
                ActiveFilter.Severity("CRITICAL"),
                ActiveFilter.Severity("HIGH"),
                ActiveFilter.DateRange(1_000L, 1_000L + DAY),
                ActiveFilter.FindingsOnly,
            ),
            chips,
        )
        assertEquals("the search is its own field, not a chip", 7, chips.size)
    }

    @Test
    fun `dismissing a chip clears exactly that filter`() = runTest(dispatcher) {
        val full = loaded().filter.value
        for (chip in activeFiltersOf(full)) {
            val vm = loaded()
            vm.dismiss(chip)
            val after = vm.filter.value
            assertEquals("dismissing $chip", activeFiltersOf(full) - chip, activeFiltersOf(after))
            val expected = when (chip) {
                is ActiveFilter.Scan -> full.copy(scanId = null)
                is ActiveFilter.Package -> full.copy(packageName = null)
                is ActiveFilter.Source -> full.copy(source = null)
                is ActiveFilter.Severity -> full.copy(levels = full.levels - chip.level)
                is ActiveFilter.DateRange -> full.copy(from = null, to = null)
                ActiveFilter.FindingsOnly -> full.copy(findingsAndEvidenceOnly = false)
            }
            assertEquals("dismissing $chip", expected, after)
        }
    }

    @Test
    fun `the search text reaches the filter after a quiet 300 ms, trimmed`() = runTest(dispatcher) {
        val vm = vm()
        vm.setSearchText("ov")
        advanceTimeBy(100L)
        vm.setSearchText(" overlay ")
        advanceTimeBy(250L)
        runCurrent()
        assertNull("still typing", vm.filter.value.query)
        assertEquals(" overlay ", vm.searchText.value)
        advanceTimeBy(SEARCH_SETTLE)
        runCurrent()
        assertEquals("overlay", vm.filter.value.query)
        vm.setSearchText("   ")
        advanceTimeBy(SEARCH_SETTLE)
        runCurrent()
        assertNull("a blank search is no search", vm.filter.value.query)
    }

    private companion object {
        const val DAY = 86_400_000L
        const val SEARCH_SETTLE = 301L
    }
}

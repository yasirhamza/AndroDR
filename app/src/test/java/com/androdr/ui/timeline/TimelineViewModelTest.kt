package com.androdr.ui.timeline

import com.androdr.data.db.TimelineFilter
import com.androdr.data.model.TelemetrySource
import androidx.lifecycle.SavedStateHandle
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.launch
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

    private fun vm(
        saved: SavedStateHandle = SavedStateHandle(),
        entries: TimelineEntries = mockk(relaxed = true),
    ) = TimelineViewModel(
        appContext = mockk(relaxed = true),
        db = mockk(relaxed = true),
        entries = entries,
        knownAppResolver = mockk(relaxed = true),
        sigmaRuleEngine = mockk(relaxed = true),
        scanRepository = mockk(relaxed = true),
        reportExporter = mockk(relaxed = true),
        clusterMembers = mockk(relaxed = true),
        signalMembers = mockk(relaxed = true),
        savedState = saved,
    ).also { it.io = dispatcher }

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

    /**
     * C5 review I1: a deep link applies once per navigation entry. Recreation (rotation) re-delivers
     * the same arguments to the same ViewModel, and process death to a new one over the same saved
     * state; neither brings back a chip the user dismissed.
     */
    @Test
    fun `a dismissed deep-link chip stays gone after rotation and after process death`() = runTest(dispatcher) {
        val saved = SavedStateHandle()
        val vm = vm(saved)
        vm.applyDeepLink("com.x", 7L)
        runCurrent()
        assertEquals(listOf(ActiveFilter.Scan(7L), ActiveFilter.Package("com.x")), activeFiltersOf(vm.filter.value))
        vm.dismiss(ActiveFilter.Package("com.x"))
        runCurrent()

        vm.applyDeepLink("com.x", 7L) // rotation: the screen's effect runs again with the same arguments
        runCurrent()
        assertEquals(listOf(ActiveFilter.Scan(7L)), activeFiltersOf(vm.filter.value))

        val restored = vm(saved) // process death: a new ViewModel over the entry's saved state
        restored.applyDeepLink("com.x", 7L)
        runCurrent()
        assertEquals("kept as the user left it", listOf(ActiveFilter.Scan(7L)), activeFiltersOf(restored.filter.value))
    }

    @Test
    fun `a blank deep-link package means no package filter`() = runTest(dispatcher) {
        val vm = vm()
        vm.applyDeepLink("  ", null)
        assertEquals(emptyList<ActiveFilter>(), activeFiltersOf(vm.filter.value))
    }

    /** C5 review I2: the unfiltered pinned findings show only while nothing narrows the list. */
    @Test
    fun `the pinned findings hide while a search or any filter is active`() = runTest(dispatcher) {
        val none = TimelineFilter()
        assertEquals(true, showPinnedFindings(none, activeFiltersOf(none)))
        val searched = none.copy(query = "overlay")
        assertEquals(false, showPinnedFindings(searched, activeFiltersOf(searched)))
        assertEquals("a blank query is no search", true, showPinnedFindings(none.copy(query = " "), emptyList()))
        for (chip in activeFiltersOf(loaded().filter.value)) {
            assertEquals("with $chip", false, showPinnedFindings(none, listOf(chip)))
        }
    }

    /** C5 review I3: a failing count shows no count; it never crashes the screen. */
    @Test
    fun `a throwing count leaves totalCount null`() = runTest(dispatcher) {
        val failing = mockk<TimelineEntries> {
            coEvery { count(any()) } throws IllegalStateException("no query solution")
        }
        val vm = vm(entries = failing)
        backgroundScope.launch { vm.totalCount.collect {} }
        advanceTimeBy(SEARCH_SETTLE)
        runCurrent()
        assertNull(vm.totalCount.value)
        assertNull(vm.dayCount(0L))

        val working = mockk<TimelineEntries> { coEvery { count(any()) } returns 5L }
        val ok = vm(entries = working)
        backgroundScope.launch { ok.totalCount.collect {} }
        advanceTimeBy(SEARCH_SETTLE)
        runCurrent()
        assertEquals("positive control", 5L, ok.totalCount.value)
    }

    /** Ruling R33: "Show only this app" sets the exact package filter, a dismissible chip. */
    @Test
    fun `show only this app sets the package filter as a chip`() = runTest(dispatcher) {
        val vm = vm()
        vm.toggleSeverity("HIGH")
        vm.showOnlyApp("com.bank")
        assertEquals(listOf(ActiveFilter.Package("com.bank"), ActiveFilter.Severity("HIGH")),
            activeFiltersOf(vm.filter.value))
        vm.dismiss(ActiveFilter.Package("com.bank"))
        assertEquals(listOf(ActiveFilter.Severity("HIGH")), activeFiltersOf(vm.filter.value))
    }

    private companion object {
        const val DAY = 86_400_000L
        const val SEARCH_SETTLE = 301L
    }
}

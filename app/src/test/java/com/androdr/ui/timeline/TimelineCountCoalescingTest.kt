package com.androdr.ui.timeline

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/**
 * C4 review I4: Timeline counts re-run once per burst of table changes, not once per change (a live
 * DNS IOC burst or a scan's finish invalidates many times), and the ViewModel's count trigger is
 * built that way.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class TimelineCountCoalescingTest {

    @Test
    fun `a burst of changes bumps the count version once`() = runTest {
        val changes = MutableSharedFlow<Unit>()
        val versions = mutableListOf<Int>()
        val job = launch { changes.coalescedVersions(300L).toList(versions) }
        runCurrent()
        repeat(20) {
            changes.emit(Unit)
            advanceTimeBy(10L)
        }
        advanceTimeBy(400L)
        repeat(5) {
            changes.emit(Unit)
            advanceTimeBy(50L)
        }
        advanceTimeBy(400L)
        job.cancel()
        assertEquals("two bursts, two bumps", listOf(0, 1, 2), versions)
    }

    @Test
    fun `the ViewModel's count trigger is the coalesced one`() {
        val src = listOf(File("src/main/java"), File("app/src/main/java")).first { it.isDirectory }
            .resolve("com/androdr/ui/timeline/TimelineViewModel.kt").readText()
        val trigger = src.substringAfter("private val tableVersion").substringBefore("stateIn")
        assertEquals(true, trigger.contains(".coalescedVersions("))
    }
}

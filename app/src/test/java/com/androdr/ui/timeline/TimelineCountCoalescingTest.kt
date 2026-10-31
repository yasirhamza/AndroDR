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

    /** #418: a debounce alone never fires while changes keep coming closer than the quiet window. */
    @Test
    fun `a continuous stream still bumps once per max wait`() = runTest {
        val changes = MutableSharedFlow<Unit>()
        val versions = mutableListOf<Int>()
        val job = launch { changes.coalescedVersions(quietMs = 300L, maxWaitMs = 2_000L).toList(versions) }
        runCurrent()
        repeat(100) { // a change every 100 ms for 10 s: never 300 ms of quiet
            changes.emit(Unit)
            advanceTimeBy(100L)
        }
        val duringStream = versions.toList()
        advanceTimeBy(400L)
        job.cancel()
        // Bumps at 2, 4, 6 and 8 s; the window ending at 10 s fires on the next tick.
        assertEquals("one bump per 2 s window while the stream ran", listOf(0, 1, 2, 3, 4), duringStream)
        assertEquals("the last window still bumps", listOf(0, 1, 2, 3, 4, 5), versions)
    }

    @Test
    fun `upstream completion flushes a pending burst`() = runTest {
        val versions = kotlinx.coroutines.flow.flowOf(Unit, Unit, Unit).coalescedVersions(300L, 2_000L).toList()
        assertEquals(listOf(0, 1), versions)
    }

    @Test
    fun `the ViewModel's count trigger is the coalesced one`() {
        val src = listOf(File("src/main/java"), File("app/src/main/java")).first { it.isDirectory }
            .resolve("com/androdr/ui/timeline/TimelineViewModel.kt").readText()
        val trigger = src.substringAfter("private val tableVersion").substringBefore("stateIn")
        assertEquals(true, trigger.contains(".coalescedVersions("))
    }
}

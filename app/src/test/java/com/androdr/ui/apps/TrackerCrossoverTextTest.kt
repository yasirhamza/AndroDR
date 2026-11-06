package com.androdr.ui.apps

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.androdr.privacy.AppPrivacyRow
import com.androdr.privacy.InspectOutcome
import com.androdr.privacy.TrackerRow
import com.androdr.privacy.model.TrackerCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** I1: the Apps-tab line never counts network-only trackers as found in code. */
@RunWith(RobolectricTestRunner::class)
class TrackerCrossoverTextTest {
    private val res = ApplicationProvider.getApplicationContext<Context>().resources

    private fun tracker(id: Int, inCode: Boolean, lookups: Int = 0) = TrackerRow(
        trackerId = id, name = "T$id", website = "", categories = setOf(TrackerCategory.ADVERTISEMENT),
        rawCategories = listOf("Advertisement"), inCode = inCode, lookups = lookups, lookupDays = 1,
        background = null, firstSeen = null, lastSeen = null, newSinceLastScan = false,
    )

    private fun app(outcome: InspectOutcome, trackers: List<TrackerRow>, refusedInCode: Int) =
        AppPrivacyRow("p", 1, "App", false, outcome, "r", trackers, refusedInCode, emptySet(), false)

    @Test fun `network-only trackers are not counted in the code count or the threshold count`() {
        val row = app(
            InspectOutcome.INSPECTED,
            listOf(tracker(1, true), tracker(2, true, lookups = 3), tracker(3, false, 5), tracker(4, false, 1)),
            refusedInCode = 1,
        )
        assertEquals(
            "Trackers in code: 2 (1 crosses your threshold); looked up domains of 2 more",
            TrackerCrossoverText.line(row, res),
        )
    }

    @Test fun `the network clause appears only when there are network-only trackers`() {
        val line = TrackerCrossoverText.line(app(InspectOutcome.INSPECTED, listOf(tracker(1, true)), 0), res)
        assertEquals("Trackers in code: 1 (0 cross your threshold)", line)
        assertFalse(line, line.contains("looked up"))
    }

    @Test fun `the threshold clause agrees in number`() {
        val row = app(InspectOutcome.INSPECTED, listOf(tracker(1, true), tracker(2, true)), refusedInCode = 2)
        assertEquals("Trackers in code: 2 (2 cross your threshold)", TrackerCrossoverText.line(row, res))
    }

    @Test fun `a PARTIAL app shows the partly inspected tag`() {
        val line = TrackerCrossoverText.line(app(InspectOutcome.PARTIAL, listOf(tracker(1, true)), 1), res)
        assertEquals("Trackers in code: 1 (1 crosses your threshold) (partly inspected)", line)
    }

    @Test fun `an app whose code was not inspected never states a code count`() {
        val line = TrackerCrossoverText.line(
            app(InspectOutcome.COULD_NOT_INSPECT, listOf(tracker(3, false, 5)), 0), res,
        )
        assertEquals("Its code could not be inspected; looked up domains of 1 tracker", line)
        assertFalse(line, line.contains("in code:"))
        assertTrue(line, line.contains("could not be inspected"))
    }
}

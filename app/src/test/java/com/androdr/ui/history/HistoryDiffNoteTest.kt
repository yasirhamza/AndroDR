package com.androdr.ui.history

import com.androdr.R
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Ruling R44 follow-up (review E4): an import has no "since previous scan" diff, and its History card
 * must not claim "First scan — no comparison available". It says imports are not compared.
 */
class HistoryDiffNoteTest {

    @Test
    fun `an import says it is not compared, whatever its position`() {
        for (source in listOf(TelemetrySource.BUGREPORT_IMPORT, TelemetrySource.INTRUSION_LOG_IMPORT)) {
            assertEquals(R.string.history_import_not_compared, diffNote(source, isFirstScan = false, hasDiff = false))
            assertEquals(R.string.history_import_not_compared, diffNote(source, isFirstScan = true, hasDiff = false))
        }
    }

    @Test
    fun `a live scan without a diff is a first scan, with one shows the diff`() {
        assertEquals(R.string.first_scan_no_comparison,
            diffNote(TelemetrySource.LIVE_SCAN, isFirstScan = false, hasDiff = false))
        assertEquals(R.string.first_scan_no_comparison,
            diffNote(TelemetrySource.LIVE_SCAN, isFirstScan = true, hasDiff = true))
        assertNull(diffNote(TelemetrySource.LIVE_SCAN, isFirstScan = false, hasDiff = true))
    }
}

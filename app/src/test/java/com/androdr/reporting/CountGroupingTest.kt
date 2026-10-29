package com.androdr.reporting

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.androdr.R
import com.androdr.data.model.ScanResult
import com.androdr.data.store.BodyStats
import com.androdr.ui.history.scanCountLines
import com.androdr.ui.settings.TelemetryCleanup
import com.androdr.ui.settings.cleanupMessage
import com.androdr.ui.settings.stats
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.util.Locale

/**
 * Battery B4: record counts showed without digit grouping ("125000 distinct records", "100000
 * telemetry record(s)"). Counts in the Settings storage rows, the export dialogs, History rows and
 * the import card use the locale's grouping.
 */
@RunWith(RobolectricTestRunner::class)
class CountGroupingTest {
    private lateinit var saved: Locale

    @Before fun setUp() {
        saved = Locale.getDefault()
        Locale.setDefault(Locale.US)
    }

    @After fun tearDown() = Locale.setDefault(saved)

    @Test
    fun `counts use the locale's grouping`() {
        assertEquals("125,000", groupedCount(125_000L, Locale.US))
        assertEquals("125.000", groupedCount(125_000L, Locale.GERMANY))
        assertEquals("999", groupedCount(999L, Locale.US))
        assertEquals("125,000", groupedCount(125_000L))
    }

    @Test
    fun `settings storage rows and the cleanup message are grouped`() {
        assertTrue(stats(BodyStats(125_000L, 2_048L, 0L)).startsWith("125,000 distinct records"))
        assertEquals("Removed 100,000 old telemetry record(s).", cleanupMessage(TelemetryCleanup.Done(100_000L)))
    }

    @Test
    fun `the export dialogs are grouped`() {
        val estimate = ExportEstimate(100_000L, 1_024L, listOf("apps"))
        assertTrue(estimate.jsonlText(), estimate.jsonlText().contains("100,000 telemetry record(s)"))
        assertTrue(estimate.text(), estimate.text().contains("Includes 100,000 telemetry record(s)"))
    }

    @Test
    fun `a history row's counts are grouped`() {
        val scan = ScanResult(id = 1L, timestamp = 1L, bugReportFindings = emptyList(), riskySideloadCount = 1_500,
            knownMalwareCount = 2, triggeredCount = 125_000)
        assertEquals(
            "• 125,000 finding(s) triggered\n• 2 known malware app(s)\n• 1,500 sideloaded app(s)",
            scanCountLines(scan),
        )
    }

    @Test
    fun `the import card counts are grouped`() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        assertEquals("125,000 new · 2,000 already stored · 0 duplicates dropped",
            ctx.getString(R.string.import_card_counts, 125_000, 2_000, 0))
        assertTrue(ctx.getString(R.string.import_card_low_space_some, 12_345).contains("12,345 new records"))
        assertTrue(ctx.getString(R.string.import_card_not_stored_some, 12_345).contains("12,345 new records"))
        assertTrue(ctx.resources.getQuantityString(R.plurals.import_card_findings_unsaved, 12_345, 12_345L, "1 MB")
            .startsWith("12,345 findings"))
        assertTrue(ctx.resources.getQuantityString(R.plurals.import_card_findings_unsaved_unknown, 12_345, 12_345L)
            .startsWith("12,345 findings"))
    }
}

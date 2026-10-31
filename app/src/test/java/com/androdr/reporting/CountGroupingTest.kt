package com.androdr.reporting

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.androdr.R
import com.androdr.data.db.ServiceSummary
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TelemetryState
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
        val res = ApplicationProvider.getApplicationContext<Context>().resources
        assertTrue(stats(res, BodyStats(125_000L, 2_048L, 0L)).startsWith("125,000 distinct records"))
        assertEquals("Removed 100,000 old telemetry records.", cleanupMessage(res, TelemetryCleanup.Done(100_000L)))
        assertEquals("Removed 1 old telemetry record.", cleanupMessage(res, TelemetryCleanup.Done(1L)))
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
    fun `the History summary sheet's counts are grouped, the report's telemetry line is not`() {
        val summary = ReportSummary(TelemetrySource.LIVE_SCAN, "LOW", 1_500, 0, 0, 0, 0, TelemetryState.STORED,
            listOf(ServiceSummary("app_scanner", 125_000)))
        val lines = summary.lines()
        assertTrue(lines.toString(), "App issues: 1,500" in lines)
        assertTrue(lines.toString(),
            "Stored telemetry: 125,000 record(s) from 1 source(s), captured with this scan." in lines)
        assertTrue(lines.toString(), lines.any { it.endsWith("(app_scanner): 125,000 record(s)") })
        assertEquals("the exported report keeps plain numbers",
            "Stored telemetry: 125000 record(s) from 1 source(s), captured with this scan.",
            telemetryLine(TelemetryState.STORED, 125_000, 1))
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

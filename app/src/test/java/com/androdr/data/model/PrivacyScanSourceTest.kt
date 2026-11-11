package com.androdr.data.model

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.androdr.reporting.ReportSummary
import com.androdr.ui.timeline.telemetrySourceLabel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

/**
 * `PRIVACY_SCAN` marks only the Timeline entries a privacy scan writes (spec 2026-11-10 §5.5). No security
 * scan, import, stored record or finding ever carries it, so the places that describe a security scan's
 * source refuse it rather than invent a label.
 */
@RunWith(RobolectricTestRunner::class)
class PrivacyScanSourceTest {

    @Test fun `the Source filter labels the privacy scan`() {
        val res = ApplicationProvider.getApplicationContext<Context>().resources
        assertEquals("Privacy scan", res.getString(telemetrySourceLabel(TelemetrySource.PRIVACY_SCAN)))
    }

    @Test fun `a security scan summary refuses a privacy-scan source`() {
        val summary = ReportSummary(TelemetrySource.PRIVACY_SCAN, "LOW", 0, 0, 0, 0, 0, TelemetryState.STORED,
            emptyList())
        assertThrows(IllegalStateException::class.java) { summary.lines() }
    }

    @Test fun `PRIVACY_SCAN appears only where privacy Timeline entries are written, filtered or labelled`() {
        val root = listOf(File("src/main/java"), File("app/src/main/java")).first { it.isDirectory }
        val users = root.walkTopDown()
            .filter { it.isFile && it.extension == "kt" && it.readText().contains("PRIVACY_SCAN") }
            .map { it.relativeTo(root).path }
            .toSortedSet()
        val extra = users - ALLOWED
        assertTrue("PRIVACY_SCAN used outside its allowed places: $extra", extra.isEmpty())
        assertTrue("the enum must define it", "com/androdr/data/model/TelemetrySource.kt" in users)
    }

    private companion object {
        /** Where the source may be named: the enum, the switches that must cover it, and the privacy entries' paths. */
        val ALLOWED = setOf(
            "com/androdr/data/model/TelemetrySource.kt",
            "com/androdr/ui/timeline/TimelineFilterSheet.kt",
            "com/androdr/data/repo/DeletionAudit.kt",
            "com/androdr/reporting/AlertReportSource.kt",
            "com/androdr/reporting/ReportSummary.kt",
            "com/androdr/ui/history/HistoryScreen.kt",
            "com/androdr/privacy/PrivacyTimelineRows.kt",
            "com/androdr/data/repo/TimelineRowDeleter.kt",
            "com/androdr/data/db/ForensicTimelineEventDao.kt",
            "com/androdr/data/db/TimelineQueries.kt",
            "com/androdr/data/db/TimelineFilter.kt",
            "com/androdr/ui/timeline/TimelineViewModel.kt",
            "com/androdr/ui/timeline/TimelineScreen.kt",
            "com/androdr/ui/timeline/TimelineEventCard.kt",
            "com/androdr/ui/timeline/TimelinePrivacy.kt",
            "com/androdr/ui/settings/SettingsViewModel.kt",
        )
    }
}

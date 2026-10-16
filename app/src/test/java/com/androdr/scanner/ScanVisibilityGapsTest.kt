package com.androdr.scanner

import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScannerFailure
import com.androdr.ioc.CampaignRegistry
import com.androdr.ioc.FeedCoverage
import com.androdr.reporting.ReportFormatter
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Final review item 2(a): the rules-repo ioc-data and the MVT collections are the only
 * sources that carry campaign keys. When either did not load, "not detected" for a campaign
 * was checked without it, so the scan says so under the existing FEEDS_NOT_LOADED heading.
 */
class ScanVisibilityGapsTest {

    private fun feeds(gaps: List<ScannerFailure>) = gaps.filter { it.scanner == "threat_intel" }

    @Test
    fun `rules-repo rows missing records one feeds entry naming the missing source`() {
        val gaps = feeds(scanVisibilityGaps(FeedCoverage(rows = 500, rulesRepoLoaded = false, mvtLoaded = true), true))
        val entry = gaps.single()
        assertEquals(NotEvaluatedReason.FEEDS_NOT_LOADED.sentinel, entry.exception)
        assertTrue(entry.message, entry.message.orEmpty().contains("AndroDR's own indicator list did not load"))
    }

    @Test
    fun `MVT rows missing records one feeds entry naming the missing source`() {
        val entry = feeds(scanVisibilityGaps(FeedCoverage(500, rulesRepoLoaded = true, mvtLoaded = false), true))
            .single()
        assertEquals(NotEvaluatedReason.FEEDS_NOT_LOADED.sentinel, entry.exception)
        assertTrue(entry.message, entry.message.orEmpty().contains("MVT spyware indicator lists did not load"))
    }

    @Test
    fun `both missing still records a single entry`() {
        val entry = feeds(scanVisibilityGaps(FeedCoverage(500, rulesRepoLoaded = false, mvtLoaded = false), true))
            .single()
        assertTrue(entry.message.orEmpty().contains("AndroDR's own indicator list"))
        assertTrue(entry.message.orEmpty().contains("MVT spyware indicator lists"))
    }

    @Test
    fun `both campaign sources present records no feeds entry`() {
        assertTrue(feeds(scanVisibilityGaps(FeedCoverage(500, rulesRepoLoaded = true, mvtLoaded = true), true))
            .isEmpty())
    }

    @Test
    fun `an empty table keeps the original message`() {
        val entry = feeds(scanVisibilityGaps(FeedCoverage(0, rulesRepoLoaded = false, mvtLoaded = false), true))
            .single()
        assertEquals("threat-intel feeds not loaded yet", entry.message)
    }

    @Test
    fun `a failing source query records the visibility_gaps failure and no feeds entry`() = runTest {
        val gaps = visibilityGapsOrFailure({ throw android.database.sqlite.SQLiteException("disk") }, true)
        assertTrue(feeds(gaps).isEmpty())
        assertEquals("SQLiteException", gaps.single { it.scanner == "visibility_gaps" }.exception)
    }

    @Test
    fun `missing rules-repo rows put the scope pointer and the detail in the report`() {
        val gaps = scanVisibilityGaps(FeedCoverage(500, rulesRepoLoaded = false, mvtLoaded = true), true)
        val scan = ScanResult(id = 1L, timestamp = 1_711_900_800_000L, findings = emptyList(),
            bugReportFindings = emptyList(), riskySideloadCount = 0, knownMalwareCount = 0, scannerErrors = gaps)
        val registry = CampaignRegistry.parseBundled(listOf(File("src/main/res/raw/known_campaigns.json"),
            File("app/src/main/res/raw/known_campaigns.json")).first { it.isFile }.readText())
        val report = ReportFormatter.formatScanReport(scan, emptyList(), emptyList(), versionName = "test",
            campaigns = registry, ruleCategoryById = emptyMap())
        assertTrue(report, report.contains(
            "  1 check(s) could not run -- see ${ReportFormatter.NOT_CHECKED_SECTION} below."))
        assertTrue(report, report.contains("  ${NotEvaluatedReason.FEEDS_NOT_LOADED.heading}:"))
        assertTrue(report, report.contains("    - AndroDR's own indicator list did not load"))
    }
}

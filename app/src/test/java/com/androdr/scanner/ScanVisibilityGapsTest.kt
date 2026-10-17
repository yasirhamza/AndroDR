package com.androdr.scanner

import com.androdr.data.model.MISSING_SOURCE_MVT
import com.androdr.data.model.MISSING_SOURCE_RULES_REPO
import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScannerFailure
import com.androdr.ioc.CampaignRegistry
import com.androdr.ioc.FeedCoverage
import com.androdr.reporting.ReportFormatter
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Final review item 2(a): the rules-repo ioc-data and the MVT collections are the only
 * sources that carry campaign keys. When either did not load, "not detected" for a campaign
 * was checked without it, so the scan says so under CAMPAIGN_SOURCES_NOT_LOADED. FEEDS_NOT_LOADED
 * (and its "only the bundled lists were checked" heading) stays for an empty table only.
 */
class ScanVisibilityGapsTest {

    private fun feeds(gaps: List<ScannerFailure>) = gaps.filter { it.scanner == "threat_intel" }

    @Test
    fun `rules-repo rows missing records one feeds entry naming the missing source`() {
        val gaps = feeds(scanVisibilityGaps(FeedCoverage(rows = 500, rulesRepoLoaded = false, mvtLoaded = true), true))
        val entry = gaps.single()
        assertEquals(NotEvaluatedReason.CAMPAIGN_SOURCES_NOT_LOADED.sentinel, entry.exception)
        assertTrue(entry.message, entry.message.orEmpty().contains("the rules-repo threat lists did not load"))
    }

    @Test
    fun `MVT rows missing records one feeds entry naming the missing source`() {
        val entry = feeds(scanVisibilityGaps(FeedCoverage(500, rulesRepoLoaded = true, mvtLoaded = false), true))
            .single()
        assertEquals(NotEvaluatedReason.CAMPAIGN_SOURCES_NOT_LOADED.sentinel, entry.exception)
        assertTrue(entry.message, entry.message.orEmpty().contains("the MVT collections did not load"))
    }

    @Test
    fun `both missing still records a single entry`() {
        val entry = feeds(scanVisibilityGaps(FeedCoverage(500, rulesRepoLoaded = false, mvtLoaded = false), true))
            .single()
        assertEquals(NotEvaluatedReason.CAMPAIGN_SOURCES_NOT_LOADED.sentinel, entry.exception)
        assertTrue(entry.message.orEmpty().contains("the rules-repo threat lists"))
        assertTrue(entry.message.orEmpty().contains("the MVT collections"))
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
        assertEquals(NotEvaluatedReason.FEEDS_NOT_LOADED.sentinel, entry.exception)
        assertEquals("threat-intel feeds not loaded yet", entry.message)
    }

    @Test
    fun `a failing source query records the visibility_gaps failure and no feeds entry`() = runTest {
        val gaps = visibilityGapsOrFailure({ throw android.database.sqlite.SQLiteException("disk") }, true)
        assertTrue(feeds(gaps).isEmpty())
        assertEquals("SQLiteException", gaps.single { it.scanner == "visibility_gaps" }.exception)
    }

    private fun report(coverage: FeedCoverage): String {
        val gaps = scanVisibilityGaps(coverage, true)
        val scan = ScanResult(id = 1L, timestamp = 1_711_900_800_000L, findings = emptyList(),
            bugReportFindings = emptyList(), riskySideloadCount = 0, knownMalwareCount = 0, scannerErrors = gaps)
        val registry = CampaignRegistry.parseBundled(listOf(File("src/main/res/raw/known_campaigns.json"),
            File("app/src/main/res/raw/known_campaigns.json")).first { it.isFile }.readText())
        return ReportFormatter.formatScanReport(scan, emptyList(), emptyList(), versionName = "test",
            campaigns = registry, ruleScopes = emptyMap(), ruleCategoryById = emptyMap())
    }

    @Test
    fun `missing rules-repo rows put the scope pointer and the true heading in the report`() {
        val report = report(FeedCoverage(500, rulesRepoLoaded = false, mvtLoaded = true))
        assertTrue(report, report.contains(
            "  1 check(s) could not run -- see ${ReportFormatter.NOT_CHECKED_SECTION} below."))
        assertTrue(report, report.contains("  ${NotEvaluatedReason.CAMPAIGN_SOURCES_NOT_LOADED.heading}:"))
        assertTrue(report, report.contains("    - the rules-repo threat lists did not load"))
    }

    @Test
    fun `missing MVT rows use the campaign-sources heading`() {
        val report = report(FeedCoverage(500, rulesRepoLoaded = true, mvtLoaded = false))
        assertTrue(report, report.contains("  ${NotEvaluatedReason.CAMPAIGN_SOURCES_NOT_LOADED.heading}:"))
        assertTrue(report, report.contains("    - the MVT collections did not load"))
    }

    @Test
    fun `the feeds-not-loaded heading never appears when the table has rows`() {
        for (c in listOf(FeedCoverage(500, false, true), FeedCoverage(500, true, false),
            FeedCoverage(500, false, false), FeedCoverage(500, true, true))) {
            val report = report(c)
            assertFalse(report, report.contains(NotEvaluatedReason.FEEDS_NOT_LOADED.heading))
            val gaps = scanVisibilityGaps(c, true)
            assertTrue(gaps.none { it.exception == NotEvaluatedReason.FEEDS_NOT_LOADED.sentinel })
        }
    }

    @Test
    fun `an empty table uses the feeds-not-loaded heading, not the campaign one`() {
        val report = report(FeedCoverage(0, rulesRepoLoaded = false, mvtLoaded = false))
        assertTrue(report, report.contains("  ${NotEvaluatedReason.FEEDS_NOT_LOADED.heading}:"))
        assertFalse(report, report.contains(NotEvaluatedReason.CAMPAIGN_SOURCES_NOT_LOADED.heading))
    }

    @Test
    fun `campaign-sources entry records which sources were missing`() {
        fun sources(rulesRepo: Boolean, mvt: Boolean) = scanVisibilityGaps(
            FeedCoverage(rows = 10, rulesRepoLoaded = rulesRepo, mvtLoaded = mvt), dnsMonitorRunning = true,
        ).single().missingSources
        assertEquals(listOf(MISSING_SOURCE_MVT), sources(rulesRepo = true, mvt = false))
        assertEquals(listOf(MISSING_SOURCE_RULES_REPO), sources(rulesRepo = false, mvt = true))
        assertEquals(listOf(MISSING_SOURCE_RULES_REPO, MISSING_SOURCE_MVT), sources(rulesRepo = false, mvt = false))
    }
}

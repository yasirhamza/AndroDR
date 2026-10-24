package com.androdr.data.db

import androidx.sqlite.db.SimpleSQLiteQuery
import com.androdr.data.store.StoreFixture
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Query plans of the D2 statements (spec §9 plan gate): the extended fact pin test behind
 * `deleteUnobservedUnpinned`, the set-based alert insert and attach, the `INSERT … SELECT` of a scan's
 * finding rows, and the current-findings and paging reads all walk an index — none reads a whole
 * `scan_finding`, `alert`, `telemetry_record` or `scan_record` table, and none sorts in a TEMP B-TREE.
 * (`ScanResult` holds one row per scan; reading it whole for the newest live scan is bounded.)
 */
@RunWith(RobolectricTestRunner::class)
class FindingQueryPlanTest {
    private val f = StoreFixture()

    @After fun tearDown() = f.close()

    private fun plan(sql: String): List<String> = f.db.openHelper.readableDatabase
        .query(SimpleSQLiteQuery("EXPLAIN QUERY PLAN " + sql.replace(Regex(":[A-Za-z]+"), "1")))
        .use { c -> buildList { while (c.moveToNext()) add(c.getString(c.getColumnIndexOrThrow("detail"))) } }

    /** Aliases and names under which the guarded tables appear in these statements. */
    private val guarded = setOf("sf", "scan_finding", "a", "pa", "alert", "pf", "f", "telemetry_record", "u",
        "scan_record", "o", "vo", "p", "forensic_timeline", "m", "signal_member")

    /**
     * A whole-table read of a guarded table — including a full walk of one of its indices
     * (`SCAN x USING INDEX …`, review Minor 9); only a covering-index walk or a SEARCH passes.
     */
    private fun fullScanOfGuarded(line: String): Boolean {
        val t = line.replace(Regex("^[|`\\s-]+"), "")
        if (!t.startsWith("SCAN ") || t.contains("USING COVERING INDEX")) return false
        val name = t.removePrefix("SCAN ").substringBefore(' ')
        return name in guarded
    }

    private fun assertIndexed(what: String, sql: String, mustUse: List<String> = emptyList()) {
        val p = plan(sql)
        val bad = p.filter(::fullScanOfGuarded)
        assertTrue("$what reads a whole guarded table:\n${p.joinToString("\n")}", bad.isEmpty())
        assertTrue("$what sorts in a temp b-tree:\n${p.joinToString("\n")}", p.none { "TEMP B-TREE" in it })
        for (index in mustUse) assertTrue("$what does not use $index:\n${p.joinToString("\n")}", p.any { index in it })
    }

    @Test
    fun `the extended pin test uses the scan_finding and alert recordId indices`() {
        assertIndexed("deleteUnobservedUnpinned",
            "SELECT f.id FROM telemetry_record f WHERE f.id IN (1, 2) AND ${PinnedFact.UNOBSERVED} " +
                "AND NOT ${PinnedFact.SQL}",
            listOf("index_scan_finding_recordId", "index_alert_recordId", "index_scan_record_recordId"))
        assertIndexed("gcUnobservedUnpinned",
            "SELECT f.id FROM telemetry_record f WHERE f.id > 0 AND ${PinnedFact.UNOBSERVED} " +
                "AND NOT ${PinnedFact.SQL} ORDER BY f.id LIMIT 500",
            listOf("index_scan_finding_recordId", "index_alert_recordId"))
    }

    @Test
    fun `alert insert, attach and re-surface use the alert key indices`() {
        assertIndexed("alert insert", OPEN_ALERTS_FOR_SCAN, listOf("index_scan_finding_scanId_alertKey"))
        assertIndexed("attach", ATTACH_ALERTS_FOR_SCAN,
            listOf("index_scan_finding_scanId_alertKey", "index_alert_alertKey"))
        assertIndexed("re-surface", TOUCH_ALERTS_FOR_SCAN, listOf("index_scan_finding_scanId_alertKey"))
    }

    @Test
    fun `the INSERT SELECT of finding rows walks one scan's triggered findings in order`() {
        assertIndexed("finding rows", INSERT_FINDING_ROWS, listOf("index_scan_finding_scanId_triggered"))
    }

    @Test
    fun `current findings and the paged lists use indices`() {
        assertIndexed("current state findings", CURRENT_STATE, listOf("index_scan_finding_scanId_triggered"))
        assertIndexed("open alert count", OPEN_ALERT_COUNT, listOf("index_alert_status_lastActivityAt"))
        assertIndexed("open alerts page", OPEN_ALERTS_AFTER, listOf("index_alert_status_lastActivityAt"))
        assertIndexed("a scan's findings page", FINDINGS_PAGE, listOf("index_scan_finding_scanId_triggered"))
    }

    @Test
    fun `the gate flags a whole-table read and a temp b-tree`() {
        assertTrue(fullScanOfGuarded("SCAN sf"))
        assertTrue(fullScanOfGuarded("|--SCAN alert"))
        assertTrue(!fullScanOfGuarded("SCAN l"))
        assertTrue("a full index walk is a whole-table read", fullScanOfGuarded("SCAN sf USING INDEX ix"))
        assertTrue(!fullScanOfGuarded("SEARCH sf USING INDEX index_scan_finding_scanId_triggered (scanId=?)"))
        assertTrue(plan("SELECT * FROM scan_finding ORDER BY level").any { "TEMP B-TREE" in it })
        assertTrue(plan("SELECT * FROM alert WHERE level = 'x'").any(::fullScanOfGuarded))
    }
}

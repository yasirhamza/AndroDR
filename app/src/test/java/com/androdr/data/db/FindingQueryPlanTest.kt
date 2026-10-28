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
     * A whole-table read of a guarded table — including a full walk of one of its indices, covering
     * or not (`SCAN x USING [COVERING] INDEX …`, review Minors 9 and H); only a SEARCH passes.
     */
    private fun fullScanOfGuarded(line: String): Boolean {
        val t = line.replace(Regex("^[|`\\s-]+"), "")
        if (!t.startsWith("SCAN ")) return false
        val name = t.removePrefix("SCAN ").substringBefore(' ')
        return name in guarded
    }

    private fun assertIndexed(
        what: String, sql: String, mustUse: List<String> = emptyList(), groupBySort: Boolean = false,
        groupOrderSort: Boolean = false,
    ) {
        val p = plan(sql)
        val bad = p.filter(::fullScanOfGuarded)
        assertTrue("$what reads a whole guarded table:\n${p.joinToString("\n")}", bad.isEmpty())
        // A GROUP BY over one scan's rows (bounded output: one row per rule) may sort in SQLite's own
        // temp b-tree, never the Java heap; an ORDER BY sort is never allowed, except — opt-in, per
        // statement ([groupOrderSort]) — ordering a GROUP BY's output (groups, not rows) under a LIMIT.
        val sorts = p.filter {
            "TEMP B-TREE" in it && !(groupBySort && "GROUP BY" in it) && !(groupOrderSort && "ORDER BY" in it)
        }
        assertTrue("$what sorts in a temp b-tree:\n${p.joinToString("\n")}", sorts.isEmpty())
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

    /** Review Minor H: the fix round's statements are plan-gated too. */
    @Test
    fun `the diff, summary and batched-delete statements use indices`() {
        assertIndexed("triggered rule counts", TRIGGERED_RULE_COUNTS, listOf("index_scan_finding_scanId_triggered"),
            groupBySort = true)
        assertIndexed("summary counts", SUMMARY_COUNTS, listOf("index_scan_finding_scanId_triggered"))
        assertIndexed("rule sample", RULE_SAMPLE, listOf("index_scan_finding_scanId_triggered"))
        assertIndexed("batched delete", DELETE_FINDINGS_BATCH, listOf("index_scan_finding_scanId"))
        assertIndexed("a deleted scan's unobserved finding pins", UNOBSERVED_FINDING_PINS,
            listOf("index_scan_finding_scanId_triggered", "index_scan_record_scanId_recordId"))
    }

    /**
     * D3 (spec §5.4): the open-alert groups walk index `(status, ruleId, matchedValue, lastActivityAt)`
     * with no GROUP BY sort; ordering the groups by latest activity sorts groups only (bounded by
     * distinct rule × matched value, never by alerts). The group close, the report's alert stream, the
     * deletion audit and "Clear all"'s scan-less delete use indices.
     */
    @Test
    fun `the alert groups, group close, report stream, deletion audit and clear-all use indices`() {
        val groupIndex = "index_alert_status_ruleId_matchedValue_lastActivityAt"
        assertIndexed("open alert groups", OPEN_ALERT_GROUPS_AFTER, listOf(groupIndex), groupOrderSort = true)
        assertTrue("grouping needs no sort", plan(OPEN_ALERT_GROUPS_AFTER).none { "GROUP BY" in it && "TEMP" in it })
        // SQLite may pick either alert index that leads with the equality columns; both are a SEARCH.
        assertIndexed("group close", CLOSE_ALERT_GROUP, listOf("SEARCH alert USING INDEX index_alert_"))
        assertIndexed("report alert groups", ALERT_REPORT_GROUPS_AFTER, listOf(groupIndex), groupOrderSort = true)
        assertIndexed("a group's sample", ALERT_GROUP_SAMPLE, listOf(groupIndex))
        assertIndexed("open alert levels", OPEN_ALERT_LEVELS, listOf("index_alert_status_level"))
        assertIndexed("audit groups of a scan", AUDIT_GROUPS_FOR_SCAN, listOf("index_scan_finding_scanId_triggered"),
            groupBySort = true, groupOrderSort = true)
        assertIndexed("audit JSON rows of a scan", AUDIT_JSON_ROWS_FOR_SCAN,
            listOf("index_scan_finding_scanId_triggered"))
        // "Clear all" removes every scan-less or orphaned row up to clearMaxRowId: a rowid range read,
        // never a scan of the table beyond it.
        assertIndexed("clear-all scan-less rows", DELETE_SCAN_LESS_THROUGH, listOf("INTEGER PRIMARY KEY (rowid<?)"))
    }

    /**
     * D4 (spec §5.1 Retention, §5.6): each retention batch reads one scan's observations through index
     * `(scanId, eventTime)` — old live events by range, snapshots by `eventTime IS NULL` — and deletes
     * them by rowid; the prune finds its rows through an index and tests the surviving-signal exemption
     * through `signal_member (kind, refId)`. None reads a whole guarded table or sorts.
     */
    @Test
    fun `retention batches and the prune use indices`() {
        val obsIndex = "index_scan_record_scanId_eventTime"
        assertIndexed("retention event batch", RETENTION_EVENT_BATCH, listOf("$obsIndex (scanId=? AND eventTime<?)"))
        assertIndexed("retention snapshot batch", RETENTION_SNAPSHOT_BATCH,
            listOf("$obsIndex (scanId=? AND eventTime=?)"))
        assertIndexed("retention delete", DELETE_OBSERVATION_ROWS, listOf("INTEGER PRIMARY KEY (rowid=?)"))
        val memberIndex = "index_signal_member_kind_refId"
        assertIndexed("prune delete", PRUNE_DELETE, listOf(memberIndex))
        assertIndexed("prune pins", PRUNE_RECORD_IDS, listOf(memberIndex))
        assertIndexed("prune signals", PRUNE_SIGNAL_IDS, listOf(memberIndex))
        // D4 fix m5: the prune's rows are a range of index (telemetrySource, createdAt), never every live row.
        val pruneRange = "SEARCH forensic_timeline USING INDEX index_forensic_timeline_telemetrySource_createdAt " +
            "(telemetrySource=? AND createdAt<?)"
        for (sql in listOf(PRUNE_DELETE, PRUNE_RECORD_IDS, PRUNE_SIGNAL_IDS)) {
            assertTrue("the prune reads a createdAt range:\n${plan(sql)}", plan(sql).any { it.contains(pruneRange) })
        }
    }

    @Test
    fun `the gate flags a whole-table read and a temp b-tree`() {
        assertTrue(fullScanOfGuarded("SCAN sf"))
        assertTrue(fullScanOfGuarded("|--SCAN alert"))
        assertTrue(!fullScanOfGuarded("SCAN l"))
        assertTrue("a full index walk is a whole-table read", fullScanOfGuarded("SCAN sf USING INDEX ix"))
        assertTrue("so is a covering one", fullScanOfGuarded("SCAN alert USING COVERING INDEX ix"))
        assertTrue(plan("SELECT COUNT(*) FROM scan_finding").any(::fullScanOfGuarded))
        assertTrue(!fullScanOfGuarded("SEARCH sf USING INDEX index_scan_finding_scanId_triggered (scanId=?)"))
        assertTrue(plan("SELECT * FROM scan_finding ORDER BY level").any { "TEMP B-TREE" in it })
        assertTrue(plan("SELECT * FROM alert WHERE level = 'x'").any(::fullScanOfGuarded))
    }
}

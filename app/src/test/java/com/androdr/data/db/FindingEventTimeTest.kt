package com.androdr.data.db

import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import com.androdr.sigma.TAXONOMY_CONTRACT_TABLE
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * C4 re-review n1: an import finding row inherits the event time of the record it matched, whatever
 * the service calls its event-time field (`event_time_ms`, `timestamp`, `crash_timestamp`,
 * `acquired_at`), with its precision. Before, only `event_time_ms` was read, so battery, security
 * log, DNS, connection, usage, install-history, tombstone and wakelock findings were dated 0
 * ("Unknown date").
 */
class FindingEventTimeTest {
    private val scan = ScanResult(id = 9L, timestamp = 9L, findings = emptyList(), bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0, source = TelemetrySource.BUGREPORT_IMPORT)

    private fun finding(context: Map<String, String>) = Finding(ruleId = "r", title = "t", level = "high",
        category = FindingCategory.APP_RISK, matchContext = context)

    @Test
    fun `every event service's time field dates its import finding row`() {
        val services = TAXONOMY_CONTRACT_TABLE.filterValues { it.eventTimeField != null }
        assertEquals("every event service is covered", 9, services.size)
        for ((service, contract) in services) {
            val row = finding(mapOf(contract.eventTimeField!! to "1729000000000"))
                .toForensicTimelineEvent(scan, isBugreport = true)
            assertEquals(service, 1_729_000_000_000L, row.startTimestamp)
            assertEquals(service, "exact", row.timestampPrecision)
        }
    }

    @Test
    fun `a day-precision record dates its row date-only, and no time stays Unknown`() {
        val day = finding(mapOf("timestamp" to "1774656000000", "timestamp_precision" to "day"))
            .toForensicTimelineEvent(scan, isBugreport = true)
        assertEquals(1_774_656_000_000L, day.startTimestamp)
        assertEquals("day", day.timestampPrecision)
        val none = finding(mapOf("package_name" to "com.x")).toForensicTimelineEvent(scan, isBugreport = true)
        assertEquals(0L, none.startTimestamp)
        val live = finding(mapOf("timestamp" to "5")).toForensicTimelineEvent(
            scan.copy(source = TelemetrySource.LIVE_SCAN), isBugreport = false)
        assertEquals("live scans keep the scan time", 9L, live.startTimestamp)
    }
}

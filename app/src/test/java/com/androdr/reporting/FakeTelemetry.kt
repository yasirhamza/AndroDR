package com.androdr.reporting

import com.androdr.data.db.ServiceSummary
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.data.store.DecodedRecord
import com.androdr.ioc.Campaign
import com.androdr.sigma.TimePrecision
import kotlinx.coroutines.runBlocking
import java.io.StringWriter

/**
 * An in-memory [StoredTelemetrySource]: one scan's records by service, and the latest event time
 * it reports. Every scan id reads the same records; provenance across scans is pinned against the
 * real store in ReportProvenanceTest.
 */
internal class FakeTelemetry(
    private val records: Map<String, List<Map<String, Any?>>> = emptyMap(),
    private val latestEvent: Long? = null,
) : StoredTelemetrySource {
    override suspend fun services(scanId: Long): List<ServiceSummary> =
        records.entries.sortedBy { it.key }.map { ServiceSummary(it.key, it.value.size) }

    override suspend fun forEach(scanId: Long, service: String, block: suspend (DecodedRecord) -> Unit) {
        records[service].orEmpty().forEachIndexed { i, fields ->
            block(
                DecodedRecord(
                    factId = i.toLong(), scanId = scanId, service = service, ordinal = i,
                    source = TelemetrySource.LIVE_SCAN, capturedAt = 0L, eventTime = null,
                    precision = TimePrecision.EXACT, category = null, fields = fields, summary = null,
                )
            )
        }
    }

    override suspend fun latestEventTime(scanId: Long): Long? = latestEvent
}

/** The report for [scan] as text, through the one formatter entry point. */
@Suppress("LongParameterList")
internal fun reportText(
    scan: ScanResult,
    logLines: List<String> = emptyList(),
    mode: ExportMode = ExportMode.BOTH,
    telemetry: StoredTelemetrySource = FakeTelemetry(),
    campaigns: List<Campaign> = emptyList(),
    ruleScopes: Map<String, RuleScope> = emptyMap(),
    ruleCategoryById: Map<String, String> = emptyMap(),
): String = runBlocking {
    val out = StringWriter()
    ReportFormatter.writeScanReport(
        out, scan, FindingsView(scan.findings, campaigns, ruleScopes, ruleCategoryById), logLines, telemetry,
        mode, versionName = "test",
    )
    out.toString()
}

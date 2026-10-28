package com.androdr.data.model

import androidx.room.Embedded
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * One finding of one scan (spec §5.4 `scan_finding`), always inserted, never shared across scans.
 *
 * - [findingJson] is the serialized `Finding`; it omits `matchContext` only when [recordId] is set
 *   (the matched record is a stored fact and readers rebuild it from there). Correlation and
 *   evaluate-only findings, and findings migrated from schema 20, keep it.
 * - Untriggered (safe-state) findings are stored only for snapshot services.
 * - [alertKey] is set for triggered [FindingKind.ALERT] findings only ([com.androdr.data.repo.AlertIdentity]);
 *   [alertId] is attached in the session's finishing transaction, which leaves no key unattached.
 * - [evidenceJson]: the full finding (with `matchContext`) of a row that may open a new alert, so
 *   `finish` can create the alert's authoritative evidence set-based; cleared once alerts exist.
 * - [row]: the Timeline row of a triggered finding, built when the finding is recorded, so `finish`
 *   writes this scan's finding rows with one `INSERT … SELECT` (null for untriggered and migrated
 *   findings, and for correlation findings, whose row is their signal).
 */
@Entity(
    tableName = "scan_finding",
    indices = [
        Index("recordId"),
        Index(value = ["scanId", "alertKey"]),
        Index(value = ["scanId", "triggered"]),
    ],
)
@Suppress("LongParameterList")
class ScanFinding(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val scanId: Long,
    val ruleId: String,
    val triggered: Boolean,
    val level: String,
    val category: String,
    val kind: FindingKind,
    val recordId: Long?,
    val service: String,
    val ordinal: Int,
    val alertKey: ByteArray?,
    val alertId: Long?,
    val findingJson: String,
    /** The evidence's matched value, for keyed rows (the opened alert's group, spec §5.4). */
    val matchedValue: String? = null,
    val evidenceJson: String?,
    @Embedded(prefix = "row_")
    val row: FindingRowColumns?,
)

/**
 * The `forensic_timeline` columns of one triggered finding's Timeline row (as
 * `SessionHooks.findingRow` builds it); `finish` copies them with `INSERT … SELECT`, adding the
 * scan id, `ruleId`, `level`, `recordId` and `createdAt`.
 */
@Suppress("LongParameterList")
class FindingRowColumns(
    val startTimestamp: Long,
    val timestampPrecision: String,
    val source: String,
    val category: String,
    val description: String,
    val details: String,
    val packageName: String,
    val appName: String,
    val apkHash: String,
    val iocIndicator: String,
    val iocType: String,
    val iocSource: String,
    val campaignName: String,
    val correlationId: String,
    val attackTechniqueId: String,
    val telemetrySource: TelemetrySource,
) {
    companion object {
        fun of(row: ForensicTimelineEvent) = FindingRowColumns(
            startTimestamp = row.startTimestamp, timestampPrecision = row.timestampPrecision, source = row.source,
            category = row.category, description = row.description, details = row.details,
            packageName = row.packageName, appName = row.appName, apkHash = row.apkHash,
            iocIndicator = row.iocIndicator, iocType = row.iocType, iocSource = row.iocSource,
            campaignName = row.campaignName, correlationId = row.correlationId,
            attackTechniqueId = row.attackTechniqueId, telemetrySource = row.telemetrySource,
        )
    }
}

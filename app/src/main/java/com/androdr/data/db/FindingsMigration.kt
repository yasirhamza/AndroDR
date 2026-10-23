package com.androdr.data.db

import android.content.ContentValues
import android.database.sqlite.SQLiteDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.androdr.data.model.FindingKind
import com.androdr.data.model.moreSevereLevel
import com.androdr.data.repo.AlertIdentity
import com.androdr.data.store.HashKeys
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
import java.nio.ByteBuffer

/**
 * v21 (spec §5.4 Migration 20 → 21): per-scan findings move from the `ScanResult.findings` JSON
 * column into `scan_finding`, lasting `alert`s are created, and `ScanResult` gains the summary
 * columns `triggeredCount` / `maxLevel`.
 *
 * - **Reading**: each scan's `findings` is read in 256 KB `substr` chunks ([MigrationFindingsReader]);
 *   a corrupt or oversized value keeps its scan with zero findings, so the upgrade always completes.
 * - **Rebuild**: API 26 SQLite has no `DROP COLUMN`, so `ScanResult` is rebuilt as `ScanResult_new`,
 *   copied, and renamed after the findings were read from the old table.
 * - **Kind** ([FindingKind]): a finding carrying `recordId` (a Phase C late-IOC re-check) is
 *   resolved by that fact; a schema-20 finding with `service`/`ordinal` through its own scan's
 *   observation; an older one by [FindingKinds.noFact] over the [FrozenRuleServices] tables.
 *   `CORRELATION` findings and unknown rule ids are STATE (no alert).
 * - **Alerts**: one per alert key over `COMPLETE` scans, opened by the earliest finding with that key
 *   (its `findingJson`, which keeps `matchContext`, becomes the evidence). OPEN when a finding with
 *   that key is no older than 30 days at upgrade time, otherwise CLOSED "migrated (older than 30 days)".
 * - Migrated findings keep `matchContext`; their Timeline rows already exist (written at the time).
 * - `forensic_timeline.level` is backfilled again for any finding row still missing it.
 */
class FindingsMigration(private val clock: () -> Long = System::currentTimeMillis) : Migration(20, 21) {

    override fun migrate(db: SupportSQLiteDatabase) {
        SCHEMA_21_DDL.forEach(db::execSQL)
        db.execSQL(
            "INSERT INTO ScanResult_new (id, timestamp, bugReportFindings, riskySideloadCount, knownMalwareCount, " +
                "scannerErrors, source, state, telemetryState, triggeredCount, maxLevel) SELECT id, timestamp, " +
                "bugReportFindings, riskySideloadCount, knownMalwareCount, scannerErrors, source, state, " +
                "telemetryState, 0, NULL FROM ScanResult"
        )
        val now = clock()
        val openers = HashMap<ByteBuffer, Opener>()
        val scans = db.query("SELECT id, timestamp, state FROM ScanResult ORDER BY timestamp, id").use { c ->
            buildList { while (c.moveToNext()) add(Triple(c.getLong(0), c.getLong(1), c.getString(2))) }
        }
        for ((scanId, timestamp, state) in scans) {
            val summary = migrateScan(db, scanId, timestamp, state == COMPLETE, openers)
            db.execSQL(
                "UPDATE ScanResult_new SET triggeredCount = ?, maxLevel = ? WHERE id = ?",
                arrayOf(summary.triggered, summary.maxLevel, scanId)
            )
        }
        backfillFindingLevels(db)
        db.execSQL("DROP TABLE ScanResult")
        db.execSQL("ALTER TABLE ScanResult_new RENAME TO ScanResult")
        createAlerts(db, openers.values, now)
    }

    private class Summary(var triggered: Int = 0, var maxLevel: String? = null)

    /** The earliest finding with one alert key (its scan_finding row) and the latest scan time with it. */
    private class Opener(val rowId: Long, var lastActivityAt: Long)

    private fun migrateScan(
        db: SupportSQLiteDatabase, scanId: Long, timestamp: Long, complete: Boolean,
        openers: HashMap<ByteBuffer, Opener>,
    ): Summary {
        val summary = Summary()
        val all = MigrationFindingsReader.read(db, scanId)
            .mapNotNull { f -> migrated(db, scanId, f)?.let { f to it } }
        for ((f, m) in all) {
            if (m.triggered) {
                summary.triggered++
                summary.maxLevel = moreSevereLevel(summary.maxLevel, m.level)
            }
            // Untriggered findings are stored only for snapshot services (spec §5.4).
            if (!m.triggered && m.service in FrozenRuleServices.EVENT_TIME_FIELD_BY_SERVICE) continue
            val rowId = db.insert("scan_finding", SQLiteDatabase.CONFLICT_ABORT, m.values(scanId, f.toString()))
            val key = m.alertKey?.takeIf { complete }
            if (key != null) {
                val opener = openers.getOrPut(HashKeys.key(key)) { Opener(rowId, timestamp) }
                if (timestamp > opener.lastActivityAt) opener.lastActivityAt = timestamp
            }
        }
        return summary
    }

    private class Migrated(
        val ruleId: String, val triggered: Boolean, val level: String, val category: String,
        val service: String?, val ordinal: Int, val recordId: Long?, val kind: FindingKind, val alertKey: ByteArray?,
    ) {
        fun values(scanId: Long, json: String) = ContentValues().apply {
            put("scanId", scanId)
            put("ruleId", ruleId)
            put("triggered", if (triggered) 1 else 0)
            put("level", level)
            put("category", category)
            put("kind", kind.name)
            put("recordId", recordId)
            put("service", service.orEmpty())
            put("ordinal", ordinal)
            put("alertKey", alertKey)
            put("findingJson", json)
        }
    }

    /** One legacy finding, classified (null when it names no rule). */
    private fun migrated(db: SupportSQLiteDatabase, scanId: Long, f: JsonObject): Migrated? {
        val ruleId = f.str("ruleId")?.takeIf { it.isNotEmpty() } ?: return null
        val triggered = (f["triggered"] as? JsonPrimitive)?.booleanOrNull ?: true
        val category = f.str("category").orEmpty()
        val service = f.str("service")?.takeIf { it.isNotEmpty() } ?: FrozenRuleServices.SERVICE_BY_RULE[ruleId]
        val ordinal = (f["ordinal"] as? JsonPrimitive)?.intOrNull ?: -1
        val context = (f["matchContext"] as? JsonObject).orEmpty()
            .mapValues { (_, v) -> (v as? JsonPrimitive)?.contentOrNull.orEmpty() }
        val claimed = (f["recordId"] as? JsonPrimitive)?.longOrNull
        val fact = when {
            claimed != null -> factEvent(db, claimed)?.let { claimed to it }
            service != null && ordinal >= 0 -> observedFact(db, scanId, service, ordinal)
            else -> null
        }
        val eventField = service?.let { FrozenRuleServices.EVENT_TIME_FIELD_BY_SERVICE[it] }
        val kind = when {
            category == CORRELATION -> FindingKind.STATE
            fact != null -> if (fact.second) FindingKind.ALERT else FindingKind.STATE
            else -> FindingKinds.noFact(service, eventField, context)
        }
        val recordId = fact?.first
        val alertKey = if (triggered && kind == FindingKind.ALERT) {
            val d = AlertIdentity.Discriminator.ofJson(f["evidence"] as? JsonObject)
            if (recordId != null) {
                AlertIdentity.recordKey(ruleId, recordId, d)
            } else {
                AlertIdentity.noFactKey(ruleId, d, FindingKinds.eventTime(eventField, context), scanId, ordinal)
            }
        } else {
            null
        }
        return Migrated(ruleId, triggered, f.str("level").orEmpty(), category, service, ordinal, recordId, kind,
            alertKey)
    }

    /** Whether fact [id] is an event (null when the fact no longer exists). */
    private fun factEvent(db: SupportSQLiteDatabase, id: Long): Boolean? =
        db.query("SELECT eventTime FROM telemetry_record WHERE id = ?", arrayOf<Any>(id)).use { c ->
            if (c.moveToFirst()) !c.isNull(0) else null
        }

    /** The fact this scan observed at (service, ordinal), and whether it is an event. */
    private fun observedFact(
        db: SupportSQLiteDatabase, scanId: Long, service: String, ordinal: Int,
    ): Pair<Long, Boolean>? =
        db.query(
            "SELECT o.recordId, f.eventTime FROM scan_record o JOIN telemetry_record f ON f.id = o.recordId " +
                "WHERE o.scanId = ? AND o.service = ? AND o.ordinal = ?",
            arrayOf<Any>(scanId, service, ordinal)
        ).use { c -> if (c.moveToFirst()) c.getLong(0) to !c.isNull(1) else null }

    private fun createAlerts(db: SupportSQLiteDatabase, openers: Collection<Opener>, now: Long) {
        val cutoff = now - OPEN_WINDOW_MS
        for (o in openers.sortedBy { it.rowId }) {
            val open = o.lastActivityAt >= cutoff
            db.execSQL(
                "INSERT INTO alert (alertKey, ruleId, status, openedAt, openedScanId, lastActivityAt, closedAt, " +
                    "closedReason, closedWithCredential, level, recordId, evidenceJson) SELECT sf.alertKey, " +
                    "sf.ruleId, ?, s.timestamp, sf.scanId, ?, ?, ?, 0, sf.level, sf.recordId, sf.findingJson " +
                    "FROM scan_finding sf JOIN ScanResult s ON s.id = sf.scanId WHERE sf.id = ?",
                arrayOf<Any?>(
                    if (open) "OPEN" else "CLOSED", o.lastActivityAt, if (open) null else now,
                    if (open) null else MIGRATED_CLOSED_REASON, o.rowId,
                )
            )
        }
        db.execSQL(
            "UPDATE scan_finding SET alertId = (SELECT a.id FROM alert a WHERE a.alertKey = scan_finding.alertKey) " +
                "WHERE alertKey IS NOT NULL"
        )
    }

    private fun JsonObject.str(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull

    companion object {
        const val MIGRATED_CLOSED_REASON = "migrated (older than 30 days)"
        const val OPEN_WINDOW_MS = 30L * 24 * 60 * 60 * 1000
        private const val COMPLETE = "COMPLETE"
        private const val CORRELATION = "CORRELATION"

        /** Room's schema-21 DDL for the new tables, and the rebuilt `ScanResult` (renamed at the end). */
        private val SCHEMA_21_DDL = listOf(
            "CREATE TABLE IF NOT EXISTS `scan_finding` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                "`scanId` INTEGER NOT NULL, `ruleId` TEXT NOT NULL, `triggered` INTEGER NOT NULL, " +
                "`level` TEXT NOT NULL, `category` TEXT NOT NULL, `kind` TEXT NOT NULL, `recordId` INTEGER, " +
                "`service` TEXT NOT NULL, `ordinal` INTEGER NOT NULL, `alertKey` BLOB, `alertId` INTEGER, " +
                "`findingJson` TEXT NOT NULL, `evidenceJson` TEXT, `row_startTimestamp` INTEGER, " +
                "`row_timestampPrecision` TEXT, `row_source` TEXT, `row_category` TEXT, `row_description` TEXT, " +
                "`row_details` TEXT, `row_packageName` TEXT, `row_appName` TEXT, `row_apkHash` TEXT, " +
                "`row_iocIndicator` TEXT, `row_iocType` TEXT, `row_iocSource` TEXT, `row_campaignName` TEXT, " +
                "`row_correlationId` TEXT, `row_attackTechniqueId` TEXT, `row_telemetrySource` TEXT)",
            "CREATE INDEX IF NOT EXISTS `index_scan_finding_recordId` ON `scan_finding` (`recordId`)",
            "CREATE INDEX IF NOT EXISTS `index_scan_finding_scanId_alertKey` " +
                "ON `scan_finding` (`scanId`, `alertKey`)",
            "CREATE INDEX IF NOT EXISTS `index_scan_finding_scanId_triggered` " +
                "ON `scan_finding` (`scanId`, `triggered`)",
            "CREATE TABLE IF NOT EXISTS `alert` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                "`alertKey` BLOB NOT NULL, `ruleId` TEXT NOT NULL, `status` TEXT NOT NULL, " +
                "`openedAt` INTEGER NOT NULL, `openedScanId` INTEGER NOT NULL, `lastActivityAt` INTEGER NOT NULL, " +
                "`closedAt` INTEGER, " +
                "`closedReason` TEXT, `closedWithCredential` INTEGER NOT NULL DEFAULT 0, `level` TEXT NOT NULL, " +
                "`recordId` INTEGER, `evidenceJson` TEXT NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_alert_alertKey` ON `alert` (`alertKey`)",
            "CREATE INDEX IF NOT EXISTS `index_alert_ruleId_status` ON `alert` (`ruleId`, `status`)",
            "CREATE INDEX IF NOT EXISTS `index_alert_recordId` ON `alert` (`recordId`)",
            "CREATE INDEX IF NOT EXISTS `index_alert_status_lastActivityAt` ON `alert` (`status`, `lastActivityAt`)",
            "CREATE TABLE IF NOT EXISTS `ScanResult_new` (`id` INTEGER NOT NULL, `timestamp` INTEGER NOT NULL, " +
                "`bugReportFindings` TEXT NOT NULL, `riskySideloadCount` INTEGER NOT NULL, " +
                "`knownMalwareCount` INTEGER NOT NULL, `scannerErrors` TEXT NOT NULL, `source` TEXT NOT NULL, " +
                "`state` TEXT NOT NULL DEFAULT 'COMPLETE', `telemetryState` TEXT NOT NULL DEFAULT 'NONE', " +
                "`triggeredCount` INTEGER NOT NULL DEFAULT 0, `maxLevel` TEXT, PRIMARY KEY(`id`))",
        )
    }
}

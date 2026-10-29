package com.androdr.data.db

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull

val MIGRATION_1_2 = object : Migration(1, 2) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE IF NOT EXISTS ioc_entries (
                packageName TEXT NOT NULL PRIMARY KEY,
                name        TEXT NOT NULL,
                category    TEXT NOT NULL,
                severity    TEXT NOT NULL,
                description TEXT NOT NULL,
                source      TEXT NOT NULL,
                fetchedAt   INTEGER NOT NULL
            )
            """.trimIndent()
        )
    }
}

val MIGRATION_2_3 = object : Migration(2, 3) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE IF NOT EXISTS domain_ioc_entries (
                domain       TEXT NOT NULL PRIMARY KEY,
                campaignName TEXT NOT NULL,
                severity     TEXT NOT NULL,
                source       TEXT NOT NULL,
                fetchedAt    INTEGER NOT NULL
            )
            """.trimIndent()
        )
    }
}

val MIGRATION_3_4 = object : Migration(3, 4) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE IF NOT EXISTS known_app_entries (
                packageName TEXT NOT NULL PRIMARY KEY,
                displayName TEXT NOT NULL,
                category    TEXT NOT NULL,
                sourceId    TEXT NOT NULL,
                fetchedAt   INTEGER NOT NULL
            )
            """.trimIndent()
        )
    }
}

val MIGRATION_4_5 = object : Migration(4, 5) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE IF NOT EXISTS cert_hash_ioc_entries (
                certHash    TEXT NOT NULL PRIMARY KEY,
                familyName  TEXT NOT NULL,
                category    TEXT NOT NULL,
                severity    TEXT NOT NULL,
                description TEXT NOT NULL,
                source      TEXT NOT NULL,
                fetchedAt   INTEGER NOT NULL
            )
            """.trimIndent()
        )
    }
}

val MIGRATION_5_6 = object : Migration(5, 6) {
    override fun migrate(database: SupportSQLiteDatabase) {
        // 1. Add CVE entries table
        database.execSQL(
            """
            CREATE TABLE IF NOT EXISTS cve_entries (
                cveId              TEXT NOT NULL PRIMARY KEY,
                description        TEXT NOT NULL,
                severity           TEXT NOT NULL,
                fixedInPatchLevel  TEXT NOT NULL,
                cisaDateAdded      TEXT NOT NULL,
                isActivelyExploited INTEGER NOT NULL,
                vendorProject      TEXT NOT NULL,
                product            TEXT NOT NULL,
                lastUpdated        INTEGER NOT NULL
            )
            """.trimIndent()
        )

        // 2. Migrate ScanResult: replace appRisks+deviceFlags columns with findings
        // SQLite doesn't support DROP COLUMN, so recreate the table
        database.execSQL(
            """
            CREATE TABLE IF NOT EXISTS ScanResult_new (
                id                 INTEGER NOT NULL PRIMARY KEY,
                timestamp          INTEGER NOT NULL,
                findings           TEXT NOT NULL,
                bugReportFindings  TEXT NOT NULL,
                riskySideloadCount INTEGER NOT NULL,
                knownMalwareCount  INTEGER NOT NULL
            )
            """.trimIndent()
        )
        // Copy compatible columns; old scan data is lost (findings column gets empty list)
        database.execSQL(
            """
            INSERT INTO ScanResult_new (id, timestamp, findings, bugReportFindings, riskySideloadCount, knownMalwareCount)
            SELECT id, timestamp, '[]', bugReportFindings, riskySideloadCount, knownMalwareCount
            FROM ScanResult
            """.trimIndent()
        )
        database.execSQL("DROP TABLE ScanResult")
        database.execSQL("ALTER TABLE ScanResult_new RENAME TO ScanResult")
    }
}

val MIGRATION_6_7 = object : Migration(6, 7) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL("""
            CREATE TABLE IF NOT EXISTS forensic_timeline (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                timestamp           INTEGER NOT NULL,
                timestampPrecision  TEXT NOT NULL DEFAULT 'exact',
                source              TEXT NOT NULL,
                category            TEXT NOT NULL,
                description         TEXT NOT NULL,
                details             TEXT NOT NULL DEFAULT '',
                severity            TEXT NOT NULL,
                packageName         TEXT NOT NULL DEFAULT '',
                appName             TEXT NOT NULL DEFAULT '',
                processUid          INTEGER NOT NULL DEFAULT -1,
                iocIndicator        TEXT NOT NULL DEFAULT '',
                iocType             TEXT NOT NULL DEFAULT '',
                iocSource           TEXT NOT NULL DEFAULT '',
                campaignName        TEXT NOT NULL DEFAULT '',
                correlationId       TEXT NOT NULL DEFAULT '',
                ruleId              TEXT NOT NULL DEFAULT '',
                scanResultId        INTEGER NOT NULL DEFAULT -1,
                attackTechniqueId   TEXT NOT NULL DEFAULT '',
                isFromBugreport     INTEGER NOT NULL DEFAULT 0,
                isFromRuntime       INTEGER NOT NULL DEFAULT 0,
                createdAt           INTEGER NOT NULL
            )
        """.trimIndent())
        @Suppress("MaxLineLength") // Index names must match Room's auto-generated convention
        val indexes = listOf(
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_timestamp ON forensic_timeline(timestamp)",
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_severity ON forensic_timeline(severity)",
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_packageName ON forensic_timeline(packageName)",
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_source ON forensic_timeline(source)"
        )
        indexes.forEach { database.execSQL(it) }
    }
}

val MIGRATION_7_8 = object : Migration(7, 8) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL(
            "ALTER TABLE forensic_timeline ADD COLUMN apkHash TEXT NOT NULL DEFAULT ''"
        )
    }
}

@Suppress("LongMethod", "MagicNumber") // Migration creates table and copies data from 3 legacy tables
val MIGRATION_8_9 = object : Migration(8, 9) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL("""
            CREATE TABLE IF NOT EXISTS indicators (
                type        TEXT NOT NULL,
                value       TEXT NOT NULL,
                name        TEXT NOT NULL DEFAULT '',
                campaign    TEXT NOT NULL DEFAULT '',
                severity    TEXT NOT NULL DEFAULT 'HIGH',
                description TEXT NOT NULL DEFAULT '',
                source      TEXT NOT NULL,
                fetchedAt   INTEGER NOT NULL,
                PRIMARY KEY(type, value)
            )
        """.trimIndent())
        database.execSQL(
            "CREATE INDEX IF NOT EXISTS index_indicators_type_value ON indicators(type, value)"
        )
        // Migrate existing IOC data into the unified table
        database.execSQL("""
            INSERT OR REPLACE INTO indicators (type, value, name, campaign, severity, description, source, fetchedAt)
            SELECT 'package', packageName, name, category, severity, description, source, fetchedAt
            FROM ioc_entries
        """.trimIndent())
        database.execSQL("""
            INSERT OR REPLACE INTO indicators (type, value, name, campaign, severity, description, source, fetchedAt)
            SELECT 'domain', domain, '', campaignName, severity, '', source, fetchedAt
            FROM domain_ioc_entries
        """.trimIndent())
        database.execSQL("""
            INSERT OR REPLACE INTO indicators (type, value, name, campaign, severity, description, source, fetchedAt)
            SELECT 'cert_hash', certHash, familyName, category, severity, description, source, fetchedAt
            FROM cert_hash_ioc_entries
        """.trimIndent())
    }
}

@Suppress("MagicNumber")
val MIGRATION_9_10 = object : Migration(9, 10) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL("DROP TABLE IF EXISTS ioc_entries")
        database.execSQL("DROP TABLE IF EXISTS domain_ioc_entries")
        database.execSQL("DROP TABLE IF EXISTS cert_hash_ioc_entries")
    }
}

/**
 * Adds the scannerErrors column to ScanResult. Old rows are backfilled with
 * an empty JSON list so historical scans are treated as "fully succeeded"
 * (no failures recorded). New scans starting from this version onward will
 * populate this column with any per-scanner exceptions recorded during the
 * telemetry-collection phase; see ScanOrchestrator.trackScanner().
 */
@Suppress("MagicNumber")
val MIGRATION_10_11 = object : Migration(10, 11) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL(
            "ALTER TABLE ScanResult ADD COLUMN scannerErrors TEXT NOT NULL DEFAULT '[]'"
        )
    }
}

/**
 * Sprint 75: ForensicTimelineEvent gains range semantics + a kind discriminator
 * so correlation signals (derived from SIGMA rules operating over time windows)
 * can live in the same table as raw events. Existing rows are backfilled via
 * SQL column defaults (`endTimestamp = NULL`, `kind = 'event'`), and the legacy
 * `timestamp` column is renamed to `startTimestamp`.
 */
@Suppress("MagicNumber")
val MIGRATION_11_12 = object : Migration(11, 12) {
    override fun migrate(db: SupportSQLiteDatabase) {
        // Additive: new nullable column for range end
        db.execSQL("ALTER TABLE forensic_timeline ADD COLUMN endTimestamp INTEGER DEFAULT NULL")
        // Additive: discriminator distinguishing raw events from correlation signals
        db.execSQL("ALTER TABLE forensic_timeline ADD COLUMN kind TEXT NOT NULL DEFAULT 'event'")
        // Rename timestamp -> startTimestamp (Room 2.4+ / SQLite 3.25+ supports RENAME COLUMN)
        db.execSQL("ALTER TABLE forensic_timeline RENAME COLUMN timestamp TO startTimestamp")
        // Drop the old index and recreate it against the renamed column, plus a new kind index.
        db.execSQL("DROP INDEX IF EXISTS index_forensic_timeline_timestamp")
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_startTimestamp " +
                "ON forensic_timeline(startTimestamp)"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_kind " +
                "ON forensic_timeline(kind)"
        )
    }
}

/**
 * Sprint 75 follow-up: backfill `correlationId = 'dns:<iocIndicator>'` on
 * existing DNS-sourced rows so historical Graphite/Paragon-style findings can
 * be linked to their triggering ioc_match rows by the Timeline UI. Without
 * this backfill, every pre-fix scan leaves orphaned findings on the timeline
 * that render as generic, indistinguishable cards with no jump-to-evidence
 * path.
 *
 * Two row classes get the update:
 *  - rows with `iocType = 'domain'` (the post-fix Finding.toForensicTimelineEvent
 *    convention) or `category = 'ioc_match'` (raw DnsEvent-derived rows), and
 *  - only rows where correlationId is currently empty/null (so re-running
 *    the migration is idempotent by construction).
 */
@Suppress("MagicNumber")
val MIGRATION_12_13 = object : Migration(12, 13) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL(
            """
            UPDATE forensic_timeline
            SET correlationId = 'dns:' || iocIndicator
            WHERE (correlationId IS NULL OR correlationId = '')
              AND iocIndicator IS NOT NULL
              AND iocIndicator != ''
              AND (iocType = 'domain' OR category = 'ioc_match')
            """.trimIndent()
        )
    }
}

/**
 * Sprint 75 second follow-up: backfill packageName + correlationId on
 * historical bug-report `permission_use` rows. Before commit 2a6e3071
 * (2026-04-08 PR #76), `AppOpsModule` emitted TimelineEvents without
 * `packageName`, so those rows persisted with empty package and had no
 * way to synthesize a `pkg:<packageName>` correlationId in the UI or
 * the CSV export. The description field is structured — "<pkg> used
 * <op> at <time>" — so the package prefix can be recovered with a
 * substring extract.
 *
 * Also stamps `pkg:<packageName>` on ANY row that has a non-blank
 * packageName but an empty correlationId, so historical package_install
 * rows, lifecycle events, and findings all join their app's cluster
 * when exported. The Timeline UI was already doing this at read time
 * via `effectiveCorrelationId()`, but that computation never reached
 * the CSV export — this migration closes the gap for old data once
 * and for all.
 *
 * Idempotent: both UPDATEs filter on `= ''`, so re-running the
 * migration on already-backfilled rows is a no-op.
 */
@Suppress("MagicNumber")
val MIGRATION_13_14 = object : Migration(13, 14) {
    override fun migrate(db: SupportSQLiteDatabase) {
        // Step 1: extract package name from "<pkg> used <op>" descriptions
        // on permission_use rows that lost their packageName field.
        db.execSQL(
            """
            UPDATE forensic_timeline
            SET packageName = substr(description, 1, instr(description, ' used ') - 1)
            WHERE category = 'permission_use'
              AND (packageName IS NULL OR packageName = '')
              AND instr(description, ' used ') > 0
            """.trimIndent()
        )

        // Step 2: backfill pkg:<packageName> correlationId on every row
        // whose correlationId is blank and packageName is now populated.
        // Skip rows where a dns:... correlationId was already stamped in
        // MIGRATION_12_13 — that's the DNS cluster key and takes precedence.
        db.execSQL(
            """
            UPDATE forensic_timeline
            SET correlationId = 'pkg:' || packageName
            WHERE (correlationId IS NULL OR correlationId = '')
              AND packageName IS NOT NULL
              AND packageName != ''
            """.trimIndent()
        )
    }
}

/**
 * Unified telemetry/findings refactor (plan 2, phase C): consolidate
 * `isFromBugreport` / `isFromRuntime` booleans on `forensic_timeline`
 * into a single `telemetrySource` TEXT column holding the
 * `TelemetrySource` enum name (LIVE_SCAN | BUGREPORT_IMPORT).
 *
 * Strategy: recreate the table without the legacy booleans and
 * populate `telemetrySource` from the old values via CASE. Table
 * recreation keeps us compatible with SQLite versions that lack
 * DROP COLUMN (API < 34).
 *
 * See docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md §4.
 */
@Suppress("MagicNumber", "LongMethod")
val MIGRATION_14_15 = object : Migration(14, 15) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE forensic_timeline_new (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                startTimestamp      INTEGER NOT NULL,
                endTimestamp        INTEGER DEFAULT NULL,
                kind                TEXT NOT NULL DEFAULT 'event',
                timestampPrecision  TEXT NOT NULL DEFAULT 'exact',
                source              TEXT NOT NULL,
                category            TEXT NOT NULL,
                description         TEXT NOT NULL,
                details             TEXT NOT NULL DEFAULT '',
                severity            TEXT NOT NULL,
                packageName         TEXT NOT NULL DEFAULT '',
                appName             TEXT NOT NULL DEFAULT '',
                processUid          INTEGER NOT NULL DEFAULT -1,
                iocIndicator        TEXT NOT NULL DEFAULT '',
                iocType             TEXT NOT NULL DEFAULT '',
                iocSource           TEXT NOT NULL DEFAULT '',
                campaignName        TEXT NOT NULL DEFAULT '',
                apkHash             TEXT NOT NULL DEFAULT '',
                correlationId       TEXT NOT NULL DEFAULT '',
                ruleId              TEXT NOT NULL DEFAULT '',
                scanResultId        INTEGER NOT NULL DEFAULT -1,
                attackTechniqueId   TEXT NOT NULL DEFAULT '',
                telemetrySource     TEXT NOT NULL DEFAULT 'LIVE_SCAN',
                createdAt           INTEGER NOT NULL
            )
        """.trimIndent())

        db.execSQL("""
            INSERT INTO forensic_timeline_new (
                id, startTimestamp, endTimestamp, kind, timestampPrecision,
                source, category, description, details, severity,
                packageName, appName, processUid, iocIndicator, iocType,
                iocSource, campaignName, apkHash, correlationId, ruleId,
                scanResultId, attackTechniqueId, telemetrySource, createdAt
            )
            SELECT
                id, startTimestamp, endTimestamp, kind, timestampPrecision,
                source, category, description, details, severity,
                packageName, appName, processUid, iocIndicator, iocType,
                iocSource, campaignName, apkHash, correlationId, ruleId,
                scanResultId, attackTechniqueId,
                CASE
                    WHEN isFromBugreport = 1 THEN 'BUGREPORT_IMPORT'
                    ELSE 'LIVE_SCAN'
                END,
                createdAt
            FROM forensic_timeline
        """.trimIndent())

        db.execSQL("DROP TABLE forensic_timeline")
        db.execSQL("ALTER TABLE forensic_timeline_new RENAME TO forensic_timeline")

        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_startTimestamp " +
                "ON forensic_timeline(startTimestamp)"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_severity " +
                "ON forensic_timeline(severity)"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_packageName " +
                "ON forensic_timeline(packageName)"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_source " +
                "ON forensic_timeline(source)"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_kind " +
                "ON forensic_timeline(kind)"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_telemetrySource " +
                "ON forensic_timeline(telemetrySource)"
        )
    }
}

/**
 * Plan 3 phase A: remove `severity` column from `forensic_timeline`.
 *
 * Timeline events are telemetry — pure observation, no severity. Severity
 * lives only on findings produced by the rule engine. This migration drops
 * the column and its index, completing the Layer 1 / Layer 2 separation
 * from spec §3.
 *
 * SQLite supports DROP COLUMN only from 3.35 / API 34; the portable
 * pattern is table recreation. See MIGRATION_14_15 for the same technique.
 */
@Suppress("MagicNumber", "LongMethod")
val MIGRATION_15_16 = object : Migration(15, 16) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE forensic_timeline_new (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                startTimestamp      INTEGER NOT NULL,
                endTimestamp        INTEGER DEFAULT NULL,
                kind                TEXT NOT NULL DEFAULT 'event',
                timestampPrecision  TEXT NOT NULL DEFAULT 'exact',
                source              TEXT NOT NULL,
                category            TEXT NOT NULL,
                description         TEXT NOT NULL,
                details             TEXT NOT NULL DEFAULT '',
                packageName         TEXT NOT NULL DEFAULT '',
                appName             TEXT NOT NULL DEFAULT '',
                processUid          INTEGER NOT NULL DEFAULT -1,
                iocIndicator        TEXT NOT NULL DEFAULT '',
                iocType             TEXT NOT NULL DEFAULT '',
                iocSource           TEXT NOT NULL DEFAULT '',
                campaignName        TEXT NOT NULL DEFAULT '',
                apkHash             TEXT NOT NULL DEFAULT '',
                correlationId       TEXT NOT NULL DEFAULT '',
                ruleId              TEXT NOT NULL DEFAULT '',
                scanResultId        INTEGER NOT NULL DEFAULT -1,
                attackTechniqueId   TEXT NOT NULL DEFAULT '',
                telemetrySource     TEXT NOT NULL DEFAULT 'LIVE_SCAN',
                createdAt           INTEGER NOT NULL
            )
        """.trimIndent())

        db.execSQL("""
            INSERT INTO forensic_timeline_new (
                id, startTimestamp, endTimestamp, kind, timestampPrecision,
                source, category, description, details,
                packageName, appName, processUid, iocIndicator, iocType,
                iocSource, campaignName, apkHash, correlationId, ruleId,
                scanResultId, attackTechniqueId, telemetrySource, createdAt
            )
            SELECT
                id, startTimestamp, endTimestamp, kind, timestampPrecision,
                source, category, description, details,
                packageName, appName, processUid, iocIndicator, iocType,
                iocSource, campaignName, apkHash, correlationId, ruleId,
                scanResultId, attackTechniqueId, telemetrySource, createdAt
            FROM forensic_timeline
        """.trimIndent())

        db.execSQL("DROP TABLE forensic_timeline")
        db.execSQL("ALTER TABLE forensic_timeline_new RENAME TO forensic_timeline")

        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_startTimestamp " +
                "ON forensic_timeline(startTimestamp)"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_packageName " +
                "ON forensic_timeline(packageName)"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_source " +
                "ON forensic_timeline(source)"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_kind " +
                "ON forensic_timeline(kind)"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_telemetrySource " +
                "ON forensic_timeline(telemetrySource)"
        )
        // Note: no severity index — the column no longer exists.
    }
}

/**
 * v17: per-feed threat-intel refresh health (#236). One row per logical feed,
 * recording last attempt/success and failure streak so a channel outage stops
 * being invisible (previously masked by a global MAX(fetchedAt) that any single
 * healthy feed kept fresh).
 */
val MIGRATION_16_17 = object : Migration(16, 17) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS feed_health (
                feedId               TEXT NOT NULL PRIMARY KEY,
                lastAttemptAt        INTEGER NOT NULL,
                lastSuccessAt        INTEGER NOT NULL,
                lastError            TEXT,
                consecutiveFailures  INTEGER NOT NULL
            )
            """.trimIndent()
        )
    }
}

/**
 * v18: what produced a scan (#356). Adds `ScanResult.source`
 * ([com.androdr.data.model.TelemetrySource]); imports stamp
 * BUGREPORT_IMPORT / INTRUSION_LOG_IMPORT so History can label them instead of
 * showing every row as if the device had been scanned live. Old rows are
 * backfilled with LIVE_SCAN, which is what they were.
 */
@Suppress("MagicNumber")
val MIGRATION_17_18 = object : Migration(17, 18) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL(
            "ALTER TABLE ScanResult ADD COLUMN source TEXT NOT NULL DEFAULT 'LIVE_SCAN'"
        )
    }
}

/**
 * v19: one attribution layout for every indicator type (#<pr>). v18 stored the
 * family in `name` and the category in `campaign` for packages/certs/hashes, but
 * domain rows kept their label in `campaign` with `name` empty; nothing could
 * read a domain's family, so domain findings lost attribution.
 *
 * Drop-and-recreate, not copy (owner decision, plan gate round 2): copying ~670k
 * rows inside Room's upgrade transaction can't reliably recover from a mid-copy
 * failure (SQLite may roll back the whole transaction -> crash on every launch).
 * The table is a cache: IndicatorRefreshOnEmpty enqueues a one-time refresh on
 * the first open, and the bundled lists cover cold start until it completes.
 */
@Suppress("MagicNumber")
val MIGRATION_18_19 = object : Migration(18, 19) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("DROP TABLE IF EXISTS `indicators`")
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS `indicators` (`type` TEXT NOT NULL, `value` TEXT NOT NULL, " +
                "`family` TEXT NOT NULL, `category` TEXT NOT NULL, `campaignKey` TEXT NOT NULL, " +
                "`severity` TEXT NOT NULL, `description` TEXT NOT NULL, `source` TEXT NOT NULL, " +
                "`reference` TEXT NOT NULL, `fetchedAt` INTEGER NOT NULL, PRIMARY KEY(`type`, `value`))"
        )
    }
}

/**
 * v20: the telemetry store (spec §4, §5.1). Adds the content/fact/observation tables, event
 * watermarks and correlation-signal members; `ScanResult.state` / `telemetryState` (existing scans
 * read back COMPLETE / NONE); `forensic_timeline.recordId` / `sourceEventKey` / `level` /
 * `persistent` and their indices. All DDL is additive (API 26 SQLite: ADD COLUMN only), so
 * `telemetry_record.id` and `forensic_timeline.id` keep AUTOINCREMENT.
 *
 * Then backfills `level` on legacy finding rows from `ScanResult.findings`, matched by
 * (`scanResultId`, `ruleId`), through [MigrationFindingsReader]: an oversized or corrupt findings
 * row leaves those rows' `level` null and never aborts the upgrade.
 */
val MIGRATION_19_20 = object : Migration(19, 20) {
    override fun migrate(db: SupportSQLiteDatabase) {
        SCHEMA_20_DDL.forEach(db::execSQL)
        backfillFindingLevels(db)
    }
}

/** v21: per-scan findings and lasting alerts ([FindingsMigration], spec §5.4). */
val MIGRATION_20_21: Migration = FindingsMigration()

private val SCHEMA_20_DDL = listOf(
    "ALTER TABLE ScanResult ADD COLUMN `state` TEXT NOT NULL DEFAULT 'COMPLETE'",
    "ALTER TABLE ScanResult ADD COLUMN `telemetryState` TEXT NOT NULL DEFAULT 'NONE'",
    "ALTER TABLE forensic_timeline ADD COLUMN `recordId` INTEGER",
    "ALTER TABLE forensic_timeline ADD COLUMN `sourceEventKey` BLOB",
    "ALTER TABLE forensic_timeline ADD COLUMN `level` TEXT",
    "ALTER TABLE forensic_timeline ADD COLUMN `persistent` INTEGER NOT NULL DEFAULT 0",
    "CREATE INDEX IF NOT EXISTS `index_forensic_timeline_recordId` ON `forensic_timeline` (`recordId`)",
    "CREATE INDEX IF NOT EXISTS `index_forensic_timeline_sourceEventKey` ON `forensic_timeline` (`sourceEventKey`)",
    "CREATE INDEX IF NOT EXISTS `index_forensic_timeline_scanResultId_startTimestamp` " +
        "ON `forensic_timeline` (`scanResultId`, `startTimestamp`)",
    "CREATE INDEX IF NOT EXISTS `index_forensic_timeline_packageName_startTimestamp` " +
        "ON `forensic_timeline` (`packageName`, `startTimestamp`)",
    "CREATE TABLE IF NOT EXISTS `record_body` (`hash` BLOB NOT NULL, `encoding` INTEGER NOT NULL, " +
        "`dictVersion` INTEGER NOT NULL, `body` BLOB NOT NULL, `rawBytes` INTEGER NOT NULL, PRIMARY KEY(`hash`))",
    "CREATE TABLE IF NOT EXISTS `telemetry_record` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
        "`service` TEXT NOT NULL, `factKey` BLOB NOT NULL, `sourceKey` BLOB, `subjectKey` TEXT, " +
        "`eventTime` INTEGER, `timePrecision` TEXT NOT NULL, `category` TEXT, `packageName` TEXT, " +
        "`bodyHash` BLOB NOT NULL, `firstSource` TEXT NOT NULL, `firstCapturedAt` INTEGER NOT NULL, " +
        "`firstStrippedKeys` INTEGER NOT NULL)",
    "CREATE UNIQUE INDEX IF NOT EXISTS `index_telemetry_record_service_factKey` " +
        "ON `telemetry_record` (`service`, `factKey`)",
    "CREATE INDEX IF NOT EXISTS `index_telemetry_record_service_subjectKey` " +
        "ON `telemetry_record` (`service`, `subjectKey`)",
    "CREATE INDEX IF NOT EXISTS `index_telemetry_record_packageName_eventTime` " +
        "ON `telemetry_record` (`packageName`, `eventTime`)",
    "CREATE INDEX IF NOT EXISTS `index_telemetry_record_eventTime` ON `telemetry_record` (`eventTime`)",
    "CREATE INDEX IF NOT EXISTS `index_telemetry_record_sourceKey` ON `telemetry_record` (`sourceKey`)",
    "CREATE INDEX IF NOT EXISTS `index_telemetry_record_bodyHash` ON `telemetry_record` (`bodyHash`)",
    "CREATE TABLE IF NOT EXISTS `scan_record` (`scanId` INTEGER NOT NULL, `service` TEXT NOT NULL, " +
        "`ordinal` INTEGER NOT NULL, `recordId` INTEGER NOT NULL, `eventTime` INTEGER, `source` TEXT NOT NULL, " +
        "`capturedAt` INTEGER NOT NULL, `strippedKeys` INTEGER NOT NULL, PRIMARY KEY(`scanId`, `service`, `ordinal`))",
    "CREATE UNIQUE INDEX IF NOT EXISTS `index_scan_record_scanId_recordId` ON `scan_record` (`scanId`, `recordId`)",
    "CREATE INDEX IF NOT EXISTS `index_scan_record_recordId` ON `scan_record` (`recordId`)",
    "CREATE INDEX IF NOT EXISTS `index_scan_record_scanId_eventTime` ON `scan_record` (`scanId`, `eventTime`)",
    "CREATE TABLE IF NOT EXISTS `event_watermark` (`service` TEXT NOT NULL, `position` INTEGER NOT NULL, " +
        "`scanId` INTEGER NOT NULL, PRIMARY KEY(`service`))",
    "CREATE TABLE IF NOT EXISTS `signal_member` (`signalRowId` INTEGER NOT NULL, `kind` INTEGER NOT NULL, " +
        "`refId` INTEGER NOT NULL, PRIMARY KEY(`signalRowId`, `kind`, `refId`))",
    "CREATE INDEX IF NOT EXISTS `index_signal_member_kind_refId` ON `signal_member` (`kind`, `refId`)",
)

internal fun backfillFindingLevels(db: SupportSQLiteDatabase) {
    val scanIds = db.query(
        "SELECT DISTINCT f.scanResultId FROM forensic_timeline f JOIN ScanResult s ON s.id = f.scanResultId " +
            "WHERE f.ruleId != '' AND f.level IS NULL"
    ).use { c -> buildList { while (c.moveToNext()) add(c.getLong(0)) } }
    for (scanId in scanIds) {
        for ((ruleId, level) in triggeredLevels(MigrationFindingsReader.read(db, scanId))) {
            db.execSQL(
                "UPDATE forensic_timeline SET level = ? WHERE scanResultId = ? AND ruleId = ? AND level IS NULL",
                arrayOf<Any>(level, scanId, ruleId)
            )
        }
    }
}

/** ruleId -> level of the first triggered finding per rule (`triggered` defaults to true when absent). */
private fun triggeredLevels(findings: List<JsonObject>): Map<String, String> {
    val out = LinkedHashMap<String, String>()
    for (f in findings) {
        val triggered = (f["triggered"] as? JsonPrimitive)?.booleanOrNull ?: true
        val ruleId = (f["ruleId"] as? JsonPrimitive)?.contentOrNull
        val level = (f["level"] as? JsonPrimitive)?.contentOrNull
        if (triggered && !ruleId.isNullOrEmpty() && !level.isNullOrEmpty()) out.putIfAbsent(ruleId, level)
    }
    return out
}

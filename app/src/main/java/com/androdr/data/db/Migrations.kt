package com.androdr.data.db

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

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

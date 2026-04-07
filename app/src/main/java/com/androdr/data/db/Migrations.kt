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

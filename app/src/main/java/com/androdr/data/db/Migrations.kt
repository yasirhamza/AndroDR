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
        database.execSQL("CREATE INDEX IF NOT EXISTS index_forensic_timeline_timestamp ON forensic_timeline(timestamp)")
        database.execSQL("CREATE INDEX IF NOT EXISTS index_forensic_timeline_severity ON forensic_timeline(severity)")
        database.execSQL("CREATE INDEX IF NOT EXISTS index_forensic_timeline_packageName ON forensic_timeline(packageName)")
        database.execSQL("CREATE INDEX IF NOT EXISTS index_forensic_timeline_source ON forensic_timeline(source)")
    }
}

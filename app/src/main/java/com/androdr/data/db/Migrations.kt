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

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

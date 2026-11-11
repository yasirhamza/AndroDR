package com.androdr.data.db

import android.content.Context
import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** Schema 23 adds the two privacy detail tables and privacy_scan.hasDetails (0 for every older scan). */
@RunWith(RobolectricTestRunner::class)
class Migration22To23Test {
    private val name = "migration-22-23"
    @get:Rule val helper: MigrationTestHelper = RoomTestDb.migrationHelper()

    @After fun tearDown() {
        ApplicationProvider.getApplicationContext<Context>().deleteDatabase(name)
    }

    private fun count(db: SupportSQLiteDatabase, sql: String): Int =
        db.query(sql).use { it.moveToFirst(); it.getInt(0) }

    @Test fun `migration adds the detail tables, marks older scans as without details and keeps their rows`() {
        val seed = helper.createDatabase(name, 22)
        try {
            seed.execSQL(
                "INSERT INTO privacy_scan (id, startedAt, finishedAt, appsTotal, appsInspected, appsPartial, " +
                    "appsFailed, registrySize, registrySha256, dnsWindowStart, dnsCoverageDays, usageCoverageFrom, " +
                    "networkStatus) VALUES (1, 10, 20, 1, 1, 0, 0, 428, 'abc', 0, 3, NULL, 'COMPLETE')"
            )
            seed.execSQL(
                "INSERT INTO privacy_app_result (scanId, packageName, versionCode, appLabel, isSystemApp, outcome, " +
                    "reason) VALUES (1, 'com.x', 7, 'X', 0, 'INSPECTED', NULL)"
            )
            seed.execSQL(
                "INSERT INTO privacy_tracker_evidence (scanId, packageName, trackerId, trackerName, website, " +
                    "categories, inCode, lookups, lookupDays, background, firstSeen, lastSeen, newSinceLastScan) " +
                    "VALUES (1, 'com.x', 12, 'Flurry', 'https://flurry.com', 'Analytics', 1, 4, 2, NULL, 5, 9, 0)"
            )
        } finally { seed.close() }

        val db = helper.runMigrationsAndValidate(name, 23, true, MIGRATION_22_23)
        assertEquals(0, count(db, "SELECT hasDetails FROM privacy_scan WHERE id = 1"))
        assertEquals(1, count(db, "SELECT COUNT(*) FROM privacy_app_result"))
        assertEquals(4, count(db, "SELECT lookups FROM privacy_tracker_evidence WHERE trackerId = 12"))
        assertEquals(0, count(db, "SELECT COUNT(*) FROM privacy_code_detail"))
        assertEquals(0, count(db, "SELECT COUNT(*) FROM privacy_domain_detail"))
    }
}

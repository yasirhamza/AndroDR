package com.androdr.data.db

import android.content.Context
import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** Schema 22 adds the four privacy tables and the DnsEvent (appName, domain, timestamp) index. */
@RunWith(RobolectricTestRunner::class)
class Migration21To22Test {
    private val name = "migration-21-22"
    @get:Rule val helper: MigrationTestHelper = RoomTestDb.migrationHelper()

    @After fun tearDown() {
        ApplicationProvider.getApplicationContext<Context>().deleteDatabase(name)
    }

    private fun names(db: SupportSQLiteDatabase, type: String): List<String> =
        db.query("SELECT name FROM sqlite_master WHERE type = '$type'").use { c ->
            buildList { while (c.moveToNext()) add(c.getString(0)) }
        }

    @Test fun `migration adds privacy tables and the DnsEvent index and keeps seeded rows`() {
        val seed = helper.createDatabase(name, 21)
        try {
            seed.execSQL(
                "INSERT INTO ScanResult (id, timestamp, bugReportFindings, riskySideloadCount, " +
                    "knownMalwareCount, scannerErrors, source, state, telemetryState) " +
                    "VALUES (1, 100, '[]', 0, 0, '[]', 'LIVE_SCAN', 'COMPLETE', 'STORED')"
            )
            seed.execSQL(
                "INSERT INTO DnsEvent (id, timestamp, domain, appUid, appName, isBlocked, reason) " +
                    "VALUES (1, 200, 'a.example', 10, 'com.x', 0, NULL)"
            )
        } finally { seed.close() }

        val db = helper.runMigrationsAndValidate(name, 22, true, MIGRATION_21_22)
        val tables = names(db, "table").filter { it.startsWith("privacy_") }.sorted()
        assertEquals(
            listOf("privacy_app_result", "privacy_package_set", "privacy_scan", "privacy_tracker_evidence"),
            tables
        )
        assertTrue(names(db, "index").contains("index_DnsEvent_appName_domain_timestamp"))
        db.query("SELECT COUNT(*) FROM ScanResult").use { it.moveToFirst(); assertEquals(1, it.getInt(0)) }
        db.query("SELECT COUNT(*) FROM DnsEvent").use { it.moveToFirst(); assertEquals(1, it.getInt(0)) }
    }
}

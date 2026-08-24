package com.androdr.data.db

import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Validates MIGRATION_17_18 (#356): the additive `ScanResult.source` column is
 * created, `runMigrationsAndValidate` cross-checks the migration against the
 * exported 18.json schema, and a scan persisted before the column existed reads
 * back as [TelemetrySource.LIVE_SCAN] — which is what it was. Without the
 * backfill default, opening the app after the update would crash on a NOT NULL
 * violation or drop the history.
 *
 * Requires an emulator / device (Room MigrationTestHelper uses real SQLite).
 */
@RunWith(AndroidJUnit4::class)
class Migration17To18Test {

    private val testDbName = "migration-test-17-18.db"

    @get:Rule
    val helper = MigrationTestHelper(
        InstrumentationRegistry.getInstrumentation(),
        AppDatabase::class.java.canonicalName!!,
        FrameworkSQLiteOpenHelperFactory()
    )

    @Test
    fun migrate17To18_addsSource_andBackfillsOldScansAsLiveScan() {
        helper.createDatabase(testDbName, 17).use { db ->
            db.execSQL(
                """
                INSERT INTO ScanResult
                    (id, timestamp, findings, bugReportFindings, riskySideloadCount,
                     knownMalwareCount, scannerErrors)
                VALUES (1000, 1000, '[]', '[]', 0, 0, '[]')
                """.trimIndent()
            )
        }

        helper.runMigrationsAndValidate(testDbName, 18, true, MIGRATION_17_18).use { db ->
            db.query("SELECT id, source FROM ScanResult").use { c ->
                assertEquals(1, c.count)
                assertTrue(c.moveToFirst())
                assertEquals(1000L, c.getLong(0))
                assertEquals(TelemetrySource.LIVE_SCAN.name, c.getString(1))
            }
        }
    }
}

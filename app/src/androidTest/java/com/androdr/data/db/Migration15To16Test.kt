package com.androdr.data.db

import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Validates plan 3 phase A: the `severity` column on `forensic_timeline`
 * is dropped via MIGRATION_15_16, existing rows are preserved with all
 * remaining columns intact, and the column no longer exists afterwards.
 *
 * Requires an emulator / device to run (Room MigrationTestHelper uses a
 * real SQLite instance).
 */
@RunWith(AndroidJUnit4::class)
class Migration15To16Test {

    private val testDbName = "migration-test-15-16.db"

    @get:Rule
    val helper = MigrationTestHelper(
        InstrumentationRegistry.getInstrumentation(),
        AppDatabase::class.java.canonicalName!!,
        FrameworkSQLiteOpenHelperFactory()
    )

    @Test
    fun migrate15To16_dropsSeverityColumn_andPreservesRows() {
        helper.createDatabase(testDbName, 15).use { db ->
            db.execSQL(
                """
                INSERT INTO forensic_timeline (
                    startTimestamp, kind, timestampPrecision, source, category,
                    description, details, severity, packageName, appName,
                    processUid, iocIndicator, iocType, iocSource, campaignName,
                    apkHash, correlationId, ruleId, scanResultId, attackTechniqueId,
                    telemetrySource, createdAt
                ) VALUES (
                    1000, 'event', 'exact', 'usage_stats', 'app_foreground',
                    'test row', '', 'high', 'com.example.test', 'Test',
                    -1, '', '', '', '', '', '', '', -1, '',
                    'LIVE_SCAN', 2000
                )
                """.trimIndent()
            )
        }

        helper.runMigrationsAndValidate(
            testDbName, 16, true, MIGRATION_15_16
        ).use { db ->
            val cursor = db.query(
                "SELECT startTimestamp, telemetrySource, packageName FROM forensic_timeline"
            )
            assertEquals(1, cursor.count)
            cursor.moveToFirst()
            assertEquals(1000L, cursor.getLong(0))
            assertEquals("LIVE_SCAN", cursor.getString(1))
            assertEquals("com.example.test", cursor.getString(2))
            cursor.close()

            val pragma = db.query("PRAGMA table_info(forensic_timeline)")
            val columns = mutableListOf<String>()
            while (pragma.moveToNext()) {
                columns.add(pragma.getString(pragma.getColumnIndexOrThrow("name")))
            }
            pragma.close()
            assertFalse(
                "severity column should be dropped; columns: $columns",
                columns.contains("severity")
            )
        }
    }
}

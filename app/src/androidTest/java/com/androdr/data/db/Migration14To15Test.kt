package com.androdr.data.db

import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Validates plan 2 phase C: `isFromBugreport` / `isFromRuntime` boolean
 * columns on `forensic_timeline` are folded into a single
 * `telemetrySource` TEXT column via MIGRATION_14_15.
 */
@RunWith(AndroidJUnit4::class)
class Migration14To15Test {

    private val testDbName = "migration-test-14-15.db"

    @get:Rule
    val helper = MigrationTestHelper(
        InstrumentationRegistry.getInstrumentation(),
        AppDatabase::class.java.canonicalName!!,
        FrameworkSQLiteOpenHelperFactory()
    )

    @Test
    fun migrate14To15_consolidatesBooleansIntoTelemetrySource() {
        helper.createDatabase(testDbName, 14).use { db ->
            db.execSQL(
                """
                INSERT INTO forensic_timeline (
                    startTimestamp, kind, timestampPrecision, source, category,
                    description, details, severity, packageName, appName,
                    processUid, iocIndicator, iocType, iocSource, campaignName,
                    apkHash, correlationId, ruleId, scanResultId, attackTechniqueId,
                    isFromBugreport, isFromRuntime, createdAt
                ) VALUES (
                    1000, 'event', 'exact', 'bugreport_parser', 'package_install',
                    'bugreport row', '', 'medium', 'com.example.test', 'Test',
                    -1, '', '', '', '', '', '', '', -1, '',
                    1, 0, 2000
                )
                """.trimIndent()
            )
            db.execSQL(
                """
                INSERT INTO forensic_timeline (
                    startTimestamp, kind, timestampPrecision, source, category,
                    description, details, severity, packageName, appName,
                    processUid, iocIndicator, iocType, iocSource, campaignName,
                    apkHash, correlationId, ruleId, scanResultId, attackTechniqueId,
                    isFromBugreport, isFromRuntime, createdAt
                ) VALUES (
                    3000, 'event', 'exact', 'usage_stats', 'app_foreground',
                    'runtime row', '', 'informational', 'com.example.runtime', 'Runtime',
                    -1, '', '', '', '', '', '', '', -1, '',
                    0, 1, 4000
                )
                """.trimIndent()
            )
        }

        val migrated = helper.runMigrationsAndValidate(
            testDbName, 15, true, MIGRATION_14_15
        )

        migrated.query(
            "SELECT startTimestamp, telemetrySource FROM forensic_timeline ORDER BY startTimestamp"
        ).use { c ->
            assertEquals(2, c.count)
            c.moveToFirst()
            assertEquals(1000L, c.getLong(0))
            assertEquals("BUGREPORT_IMPORT", c.getString(1))
            c.moveToNext()
            assertEquals(3000L, c.getLong(0))
            assertEquals("LIVE_SCAN", c.getString(1))
        }
    }
}

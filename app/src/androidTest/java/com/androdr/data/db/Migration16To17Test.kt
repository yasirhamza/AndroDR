package com.androdr.data.db

import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Validates MIGRATION_16_17 (#236): the additive `feed_health` table is created,
 * `runMigrationsAndValidate` cross-checks the migration against the exported
 * 17.json schema, and a pre-existing row in another table survives (the
 * migration is purely additive — no data loss).
 *
 * Requires an emulator / device (Room MigrationTestHelper uses real SQLite).
 */
@RunWith(AndroidJUnit4::class)
class Migration16To17Test {

    private val testDbName = "migration-test-16-17.db"

    @get:Rule
    val helper = MigrationTestHelper(
        InstrumentationRegistry.getInstrumentation(),
        AppDatabase::class.java.canonicalName!!,
        FrameworkSQLiteOpenHelperFactory()
    )

    @Test
    fun migrate16To17_createsFeedHealth_andPreservesExistingRows() {
        helper.createDatabase(testDbName, 16).use { db ->
            db.execSQL(
                """
                INSERT INTO indicators (type, value, name, campaign, severity, description, source, fetchedAt)
                VALUES ('domain', 'evil.example', 'X', 'C', 'HIGH', 'd', 'test', 1000)
                """.trimIndent()
            )
        }

        helper.runMigrationsAndValidate(testDbName, 17, true, MIGRATION_16_17).use { db ->
            // feed_health table now exists and is queryable.
            db.query("SELECT feedId, lastAttemptAt, lastSuccessAt, lastError, consecutiveFailures FROM feed_health")
                .use { c -> assertEquals(0, c.count) }

            // Pre-existing indicator row survived the additive migration.
            db.query("SELECT value FROM indicators").use { c ->
                assertEquals(1, c.count)
                assertTrue(c.moveToFirst())
                assertEquals("evil.example", c.getString(0))
            }
        }
    }
}

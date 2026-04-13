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

@RunWith(AndroidJUnit4::class)
class Migration11To12Test {

    @get:Rule
    val helper = MigrationTestHelper(
        InstrumentationRegistry.getInstrumentation(),
        AppDatabase::class.java.canonicalName!!,
        FrameworkSQLiteOpenHelperFactory()
    )

    @Test
    fun migrate11To12_renamesTimestampAndAddsNewColumns() {
        helper.createDatabase("sprint75-test", 11).use { db ->
            db.execSQL(
                "INSERT INTO forensic_timeline " +
                    "(timestamp, timestampPrecision, source, category, description, severity) " +
                    "VALUES (1000, 'exact', 'test', 'app_risk', 'pre-migration row', 'high')"
            )
        }

        val migrated = helper.runMigrationsAndValidate(
            "sprint75-test", 12, true, MIGRATION_11_12
        )

        migrated.query("SELECT startTimestamp, endTimestamp, kind FROM forensic_timeline").use { c ->
            assertTrue(c.moveToFirst())
            assertEquals(1000L, c.getLong(0))
            assertTrue(c.isNull(1))
            assertEquals("event", c.getString(2))
        }
    }
}

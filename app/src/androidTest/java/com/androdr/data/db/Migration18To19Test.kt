package com.androdr.data.db

import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Migration18To19Test {
    private val name = "migration-test-18-19.db"
    @get:Rule val helper = MigrationTestHelper(InstrumentationRegistry.getInstrumentation(),
        AppDatabase::class.java.canonicalName!!, FrameworkSQLiteOpenHelperFactory())

    @Test
    fun migrate18To19_recreatesIndicatorsEmpty_keepsOtherTables() {
        helper.createDatabase(name, 18).use { db ->
            db.execSQL("""INSERT INTO indicators (type,value,name,campaign,severity,description,source,fetchedAt) VALUES
              ('domain','forti.external-muki.com','','Graphite (Paragon)','CRITICAL','','androdr_public_repo',1)""")
            db.execSQL("""INSERT INTO ScanResult (id, timestamp, findings, bugReportFindings, riskySideloadCount,
              knownMalwareCount, scannerErrors, source) VALUES (1, 1, '[]', '[]', 0, 0, '[]', 'LIVE_SCAN')""")
        }
        helper.runMigrationsAndValidate(name, 19, true, MIGRATION_18_19).use { db ->
            db.query("SELECT COUNT(*) FROM indicators").use { c -> c.moveToFirst(); assertEquals(0, c.getInt(0)) }
            db.query("SELECT COUNT(*) FROM ScanResult").use { c -> c.moveToFirst(); assertEquals(1, c.getInt(0)) }
        }
    }
}

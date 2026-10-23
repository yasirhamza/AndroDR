package com.androdr.data.db

import android.content.Context
import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** Schema 19 -> 20: telemetry store tables, scan state, timeline columns, `level` backfill (spec §4, F1). */
@RunWith(RobolectricTestRunner::class)
class Migration19To20Test {
    private val name = "migration-19-20"
    private lateinit var helper: MigrationTestHelper

    @Before fun setUp() { helper = RoomTestDb.migrationHelper() }

    @After fun tearDown() {
        ApplicationProvider.getApplicationContext<Context>().deleteDatabase(name)
    }

    private fun seedV19(block: SupportSQLiteDatabase.() -> Unit) {
        val db = helper.createDatabase(name, 19)
        try { db.block() } finally { db.close() }
    }

    private fun migrate(): SupportSQLiteDatabase = helper.runMigrationsAndValidate(name, 20, true, MIGRATION_19_20)

    private fun SupportSQLiteDatabase.scan(id: Long, findings: String) = execSQL(
        "INSERT INTO ScanResult (id, timestamp, findings, bugReportFindings, riskySideloadCount, " +
            "knownMalwareCount, scannerErrors, source) VALUES (?, ?, ?, '[]', 0, 0, '[]', 'LIVE_SCAN')",
        arrayOf<Any>(id, id, findings)
    )

    private fun SupportSQLiteDatabase.findingRow(scanId: Long, ruleId: String) = execSQL(
        "INSERT INTO forensic_timeline (startTimestamp, kind, timestampPrecision, source, category, " +
            "description, details, packageName, appName, processUid, iocIndicator, iocType, iocSource, " +
            "campaignName, apkHash, correlationId, ruleId, scanResultId, attackTechniqueId, telemetrySource, " +
            "createdAt) VALUES (1, 'event', 'exact', 'app_scanner', 'app_risk', 'd', '', '', '', -1, '', '', '', " +
            "'', '', '', ?, ?, '', 'LIVE_SCAN', 1)",
        arrayOf<Any>(ruleId, scanId)
    )

    private fun finding(ruleId: String, level: String, triggered: Boolean = true) =
        """{"ruleId":"$ruleId","title":"t","level":"$level","category":"APP_RISK","triggered":$triggered}"""

    private fun SupportSQLiteDatabase.levels(scanId: Long): Map<String, String?> =
        query("SELECT ruleId, level FROM forensic_timeline WHERE scanResultId = ?", arrayOf<Any>(scanId)).use { c ->
            buildMap { while (c.moveToNext()) put(c.getString(0), if (c.isNull(1)) null else c.getString(1)) }
        }

    private fun SupportSQLiteDatabase.strings(sql: String): List<String> = query(sql).use { c ->
        buildList { while (c.moveToNext()) add(c.getString(0)) }
    }

    @Test
    fun `upgrade creates store tables, new columns and composite indices`() {
        seedV19 { }
        val db = migrate()
        val tables = db.strings("SELECT name FROM sqlite_master WHERE type = 'table'")
        for (t in listOf("record_body", "telemetry_record", "scan_record", "event_watermark", "signal_member")) {
            assertTrue("missing table $t", t in tables)
        }
        val scanCols = db.strings("SELECT name FROM pragma_table_info('ScanResult')")
        assertTrue(scanCols.containsAll(listOf("state", "telemetryState")))
        val ftCols = db.strings("SELECT name FROM pragma_table_info('forensic_timeline')")
        assertTrue(ftCols.containsAll(listOf("recordId", "sourceEventKey", "level", "persistent")))
        val indices = db.strings("SELECT name FROM sqlite_master WHERE type = 'index'")
        for (i in listOf(
            "index_forensic_timeline_recordId", "index_forensic_timeline_sourceEventKey",
            "index_forensic_timeline_scanResultId_startTimestamp",
            "index_forensic_timeline_packageName_startTimestamp",
            "index_telemetry_record_service_factKey", "index_telemetry_record_service_subjectKey",
            "index_telemetry_record_packageName_eventTime", "index_telemetry_record_eventTime",
            "index_telemetry_record_sourceKey", "index_telemetry_record_bodyHash",
            "index_scan_record_scanId_recordId", "index_scan_record_recordId",
            "index_scan_record_scanId_eventTime", "index_signal_member_kind_refId",
        )) assertTrue("missing index $i", i in indices)
        db.close()
    }

    @Test
    fun `scans saved before the upgrade read back COMPLETE with telemetry NONE`() {
        seedV19 { scan(1L, "[]"); scan(2L, "[]") }
        val db = migrate()
        db.query("SELECT state, telemetryState FROM ScanResult").use { c ->
            var n = 0
            while (c.moveToNext()) {
                assertEquals("COMPLETE", c.getString(0))
                assertEquals("NONE", c.getString(1))
                n++
            }
            assertEquals(2, n)
        }
        db.close()
    }

    @Test
    fun `legacy finding rows get level from ScanResult findings by scan and rule`() {
        seedV19 {
            scan(1L, "[${finding("androdr-001", "high")},${finding("androdr-002", "low")}]")
            scan(2L, "[${finding("androdr-001", "critical")},${finding("androdr-009", "medium", triggered = false)}]")
            findingRow(1L, "androdr-001"); findingRow(1L, "androdr-002")
            findingRow(2L, "androdr-001"); findingRow(2L, "androdr-003"); findingRow(2L, "androdr-009")
        }
        val db = migrate()
        assertEquals(mapOf("androdr-001" to "high", "androdr-002" to "low"), db.levels(1L))
        assertEquals(mapOf("androdr-001" to "critical", "androdr-003" to null, "androdr-009" to null), db.levels(2L))
        db.query("SELECT COUNT(*) FROM forensic_timeline WHERE persistent != 0").use { c ->
            c.moveToFirst()
            assertEquals(0, c.getInt(0))
        }
        db.close()
    }

    @Test
    fun `a 3 MB findings row and a corrupt row leave level null and the upgrade completes`() {
        val pad = "x".repeat(3 * 1024 * 1024)
        val huge = """[{"ruleId":"androdr-001","title":"$pad","level":"high","category":"APP_RISK"}]"""
        seedV19 {
            scan(1L, huge); findingRow(1L, "androdr-001")
            scan(2L, "[{\"ruleId\":\"androdr-001\",\"level\":"); findingRow(2L, "androdr-001")
            scan(3L, "[${finding("androdr-001", "medium")}]"); findingRow(3L, "androdr-001")
        }
        val db = migrate()
        assertNull(db.levels(1L)["androdr-001"])
        assertNull(db.levels(2L)["androdr-001"])
        assertEquals("medium", db.levels(3L)["androdr-001"])
        db.close()
    }

    @Test
    fun `fact and timeline ids stay AUTOINCREMENT after the upgrade`() {
        seedV19 { }
        val db = migrate()
        for (t in listOf("telemetry_record", "forensic_timeline")) {
            val sql = db.strings("SELECT sql FROM sqlite_master WHERE name = '$t'").single()
            assertTrue("$t lost AUTOINCREMENT: $sql", sql.uppercase().contains("AUTOINCREMENT"))
        }
        db.close()
    }
}

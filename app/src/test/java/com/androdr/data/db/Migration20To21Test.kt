package com.androdr.data.db

import android.content.Context
import androidx.room.Room
import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.test.core.app.ApplicationProvider
import com.androdr.data.repo.AlertIdentity
import com.androdr.data.repo.FindingsRepository
import com.androdr.data.store.EventDisplay
import com.androdr.data.store.TelemetryDictionaries
import com.androdr.data.store.TelemetryReader
import com.androdr.data.store.TelemetryRecordCodec
import com.androdr.data.store.rawFile
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * F1 (spec §5.4 Migration 20 → 21, §9): per-scan findings leave the `ScanResult.findings` JSON for
 * `scan_finding`, alerts are created, the summary columns are backfilled, and a database carrying
 * Phase A–C store data (facts, observations, signals, finding rows) upgrades with that data intact.
 */
@RunWith(RobolectricTestRunner::class)
class Migration20To21Test {
    private val name = "migration-20-21"
    // A rule, so the helper is finished() and closes every database it opened, even on a failure.
    @get:Rule val helper: MigrationTestHelper = RoomTestDb.migrationHelper()

    @After fun tearDown() {
        ApplicationProvider.getApplicationContext<Context>().deleteDatabase(name)
    }

    private fun seed(block: SupportSQLiteDatabase.() -> Unit) {
        val db = helper.createDatabase(name, 20)
        try { db.block() } finally { db.close() }
    }

    private fun migrate(): SupportSQLiteDatabase =
        helper.runMigrationsAndValidate(name, 21, true, FindingsMigration { NOW })

    private fun SupportSQLiteDatabase.scan(id: Long, timestamp: Long, findings: String, state: String = "COMPLETE") =
        execSQL(
            "INSERT INTO ScanResult (id, timestamp, findings, bugReportFindings, riskySideloadCount, " +
                "knownMalwareCount, scannerErrors, source, state, telemetryState) " +
                "VALUES (?, ?, ?, '[]', 0, 0, '[]', 'LIVE_SCAN', ?, 'STORED')",
            arrayOf<Any>(id, timestamp, findings, state)
        )

    /** A fact (event when [eventTime] is set) observed by [scanId] at (service, ordinal). */
    private fun SupportSQLiteDatabase.fact(
        id: Long, service: String, eventTime: Long?, scanId: Long? = null, ordinal: Int = 0,
    ) {
        execSQL("INSERT OR IGNORE INTO record_body (hash, encoding, dictVersion, body, rawBytes) " +
            "VALUES (X'0$id', 0, 0, X'7B7D', 2)")
        execSQL(
            "INSERT INTO telemetry_record (id, service, factKey, sourceKey, subjectKey, eventTime, timePrecision, " +
                "category, packageName, bodyHash, firstSource, firstCapturedAt, firstStrippedKeys) " +
                "VALUES (?, ?, X'0$id', NULL, NULL, ?, 'EXACT', NULL, NULL, X'0$id', 'LIVE_SCAN', 1, 0)",
            arrayOf(id, service, eventTime)
        )
        if (scanId != null) {
            execSQL(
                "INSERT INTO scan_record (scanId, service, ordinal, recordId, eventTime, source, capturedAt, " +
                    "strippedKeys) VALUES (?, ?, ?, ?, ?, 'LIVE_SCAN', 1, 0)",
                arrayOf(scanId, service, ordinal, id, eventTime)
            )
        }
    }

    private fun SupportSQLiteDatabase.findingRow(scanId: Long, ruleId: String, recordId: Long? = null) = execSQL(
        "INSERT INTO forensic_timeline (startTimestamp, kind, timestampPrecision, source, category, description, " +
            "details, packageName, appName, processUid, iocIndicator, iocType, iocSource, campaignName, apkHash, " +
            "correlationId, ruleId, scanResultId, attackTechniqueId, telemetrySource, createdAt, recordId, level, " +
            "persistent) VALUES (1, 'event', 'exact', 'app_scanner', 'app_risk', 'd', '', '', '', -1, '', '', '', " +
            "'', '', '', ?, ?, '', 'LIVE_SCAN', 1, ?, NULL, 0)",
        arrayOf(ruleId, scanId, recordId)
    )

    private fun dns(service: Boolean, ordinal: Int = 0, time: Long = 1_700L, recordId: Long? = null) =
        """{"ruleId":"androdr-003","title":"Malicious domain","level":"high","category":"APP_RISK",""" +
            (if (service) """"service":"dns_monitor","ordinal":$ordinal,""" else "") +
            (if (recordId != null) """"recordId":$recordId,""" else "") +
            """"evidence":{"type":"ioc_match","matchedIndicator":"evil.example","iocType":"domain",""" +
            """"source":"feed","family":"Pegasus"},"matchContext":{"domain":"evil.example","timestamp":"$time"}}"""

    private fun finding(ruleId: String, level: String, triggered: Boolean = true, extra: String = "") =
        """{"ruleId":"$ruleId","title":"t","level":"$level","category":"APP_RISK","triggered":$triggered$extra}"""

    private fun SupportSQLiteDatabase.rows(sql: String): List<List<String?>> = query(sql).use { c ->
        buildList {
            while (c.moveToNext()) add((0 until c.columnCount).map { if (c.isNull(it)) null else c.getString(it) })
        }
    }

    private fun SupportSQLiteDatabase.summary(id: Long) =
        rows("SELECT triggeredCount, maxLevel FROM ScanResult WHERE id = $id")[0]

    private fun SupportSQLiteDatabase.long(sql: String): Long = query(sql).use { c -> c.moveToFirst(); c.getLong(0) }

    private fun SupportSQLiteDatabase.alertKeyOf(scanId: Long, ruleId: String): ByteArray? =
        query("SELECT alertKey FROM scan_finding WHERE scanId = $scanId AND ruleId = '$ruleId'").use { c ->
            c.moveToFirst(); if (c.isNull(0)) null else c.getBlob(0)
        }

    private val ioc = AlertIdentity.Discriminator("ioc_match", "evil.example")

    @Suppress("LongMethod") // one seeded schema-20 database checked end to end (spec §9 F1)
    @Test
    fun `every scan survives, summary columns are backfilled, kinds and alerts follow the record`() {
        val bigFindings = (0 until 1_200).joinToString(",", "[", "]") {
            finding("androdr-0${10 + it % 5}", listOf("low", "medium", "high")[it % 3])
        }
        seed {
            // 10 days old: a schema-20 DNS finding resolved through its observation, a live app-ops
            // finding (snapshot fact), a correlation finding, an unknown rule, two untriggered findings.
            fact(1L, "dns_monitor", eventTime = 1_700L, scanId = A, ordinal = 0)
            fact(2L, "appops_audit", eventTime = null, scanId = A, ordinal = 0)
            scan(A, NOW - 10 * DAY, "[" + listOf(
                dns(service = true),
                finding("androdr-063", "medium", extra = ""","service":"appops_audit","ordinal":0"""),
                // Category CORRELATION decides, even when the finding names an always-event service.
                """{"ruleId":"androdr-corr-001","title":"c","level":"high","category":"CORRELATION",""" +
                    """"service":"dns_monitor","matchContext":{"member_count":"3","timestamp":"5"}}""",
                finding("androdr-999", "critical"),
                finding("androdr-040", "low", triggered = false, extra = ""","service":"device_auditor","ordinal":0"""),
                """{"ruleId":"androdr-003","title":"t","level":"high","category":"APP_RISK","triggered":false}""",
            ).joinToString(",") + "]")
            findingRow(A, "androdr-003", recordId = 1L)
            // 40 days old: a pre-store DNS finding (no service, no ordinal).
            scan(B, NOW - 40 * DAY, "[" + dns(service = false, time = 1_234L) + "]")
            // 5 days old: a Phase C late-IOC re-check finding, resolved by its recordId.
            fact(3L, "dns_monitor", eventTime = 1_900L, scanId = A, ordinal = 1)
            scan(C, NOW - 5 * DAY, "[" + dns(service = true, ordinal = -1, recordId = 3L) + "]")
            scan(D, NOW - DAY, bigFindings)
            findingRow(D, "androdr-010")
            scan(E, NOW, "[{\"ruleId\":\"androdr-001\",\"level\":")
            scan(F, NOW, """[{"ruleId":"androdr-001","title":"${"x".repeat(3 * 1024 * 1024)}","level":"high"}]""")
            execSQL("INSERT INTO signal_member (signalRowId, kind, refId) VALUES (99, 1, 1)")
        }
        val db = migrate()

        assertEquals("all scans survive", listOf(A, B, C, D, E, F).sorted(),
            db.rows("SELECT id FROM ScanResult ORDER BY id").map { it[0]!!.toLong() })
        assertFalse("findings column is gone",
            db.rows("SELECT name FROM pragma_table_info('ScanResult')").any { it[0] == "findings" })
        assertEquals(listOf("1200", "high"), db.summary(D))
        assertEquals(1_200L, db.long("SELECT COUNT(*) FROM scan_finding WHERE scanId = $D"))
        assertEquals(listOf("0", null), db.summary(E))
        assertEquals(listOf("0", null), db.summary(F))
        assertEquals(listOf("4", "critical"), db.summary(A))

        val kinds = db.rows("SELECT ruleId, kind, recordId FROM scan_finding WHERE scanId = $A ORDER BY id")
        assertEquals(listOf(
            listOf("androdr-003", "ALERT", "1"),
            listOf("androdr-063", "STATE", "2"),
            listOf("androdr-corr-001", "STATE", null),
            listOf("androdr-999", "STATE", null),
            listOf("androdr-040", "STATE", null),
        ), kinds)
        assertNull("a correlation finding opens no alert", db.alertKeyOf(A, "androdr-corr-001"))
        assertNull("a live app-ops (snapshot) finding opens no alert", db.alertKeyOf(A, "androdr-063"))

        assertArrayEquals(AlertIdentity.recordKey("androdr-003", 1L, ioc), db.alertKeyOf(A, "androdr-003"))
        assertArrayEquals(AlertIdentity.noFactKey("androdr-003", ioc, 1_234L, B, -1), db.alertKeyOf(B, "androdr-003"))
        assertArrayEquals("the re-check finding keys on its own fact",
            AlertIdentity.recordKey("androdr-003", 3L, ioc), db.alertKeyOf(C, "androdr-003"))
        assertEquals("3", db.rows("SELECT recordId FROM scan_finding WHERE scanId = $C")[0][0])

        val alerts = db.rows("SELECT openedScanId, status, closedReason, recordId, closedWithCredential FROM alert " +
            "ORDER BY openedScanId")
        assertEquals(listOf(
            listOf("$A", "OPEN", null, "1", "0"),
            listOf("$B", "CLOSED", FindingsMigration.MIGRATED_CLOSED_REASON, null, "0"),
            listOf("$C", "OPEN", null, "3", "0"),
        ), alerts.sortedBy { it[0]!!.toLong() })
        // D3: a migrated alert groups by its evidence's matched value (spec §5.4), like a new one.
        assertEquals("evil.example", db.rows("SELECT matchedValue FROM alert WHERE openedScanId = $A")[0][0])
        assertEquals("every keyed finding is attached", 0L,
            db.long("SELECT COUNT(*) FROM scan_finding WHERE alertKey IS NOT NULL AND alertId IS NULL"))

        // Migrated findings and the alerts' evidence keep matchContext.
        for (sql in listOf("SELECT findingJson FROM scan_finding WHERE scanId = $A AND ruleId = 'androdr-003'",
            "SELECT evidenceJson FROM alert WHERE openedScanId = $A")) {
            val obj = Json.parseToJsonElement(db.rows(sql)[0][0]!!) as JsonObject
            assertEquals(sql, "evil.example", (obj["matchContext"] as JsonObject)["domain"].toString().trim('"'))
        }

        // Phase A–C data is untouched; the level backfill ran.
        assertEquals(3L, db.long("SELECT COUNT(*) FROM telemetry_record"))
        assertEquals(3L, db.long("SELECT COUNT(*) FROM scan_record"))
        assertEquals(1L, db.long("SELECT COUNT(*) FROM signal_member"))
        assertEquals(listOf("high", "low"),
            db.rows("SELECT level FROM forensic_timeline WHERE persistent = 0 ORDER BY scanResultId").map { it[0] })
        // Review Minor 2: the corrupt and the 3 MB scans' findings are lost for good; one row says so.
        val lost = "Findings of 2 earlier scan(s) could not be carried over"
        assertEquals(listOf(listOf(FindingsMigration.UNREADABLE_CATEGORY, lost)),
            db.rows("SELECT category, description FROM forensic_timeline WHERE persistent = 1"))
        db.close()
    }

    /**
     * The `service` / `ordinal` JSON keys the migration reads are the keys [Converters] writes for
     * [Finding.service] / [Finding.ordinal]. A renamed field would not fail the migration: it would
     * quietly fall back to [FrozenRuleServices.SERVICE_BY_RULE] and lose the finding's record. The
     * rule here is in no frozen map, so only the JSON round-trip can resolve the fact.
     */
    @Test
    fun `a finding's service and ordinal round-trip through Converters JSON into the migration`() {
        val written = Finding(ruleId = "androdr-999", title = "t", level = "high", category = FindingCategory.APP_RISK,
            service = "appops_audit", ordinal = 1)
        assertNull(FrozenRuleServices.SERVICE_BY_RULE[written.ruleId])
        val json = Converters.fromFindingList(listOf(written))
        val obj = (Json.parseToJsonElement(json) as JsonArray).single() as JsonObject
        assertEquals("\"appops_audit\"", obj["service"].toString())
        assertEquals("1", obj["ordinal"].toString())
        assertEquals(written, Converters.toFindingList(json).single())
        seed {
            fact(5L, "appops_audit", eventTime = null, scanId = A, ordinal = 0)
            fact(6L, "appops_audit", eventTime = null, scanId = A, ordinal = 1)
            scan(A, NOW, json)
        }
        val db = migrate()
        assertEquals(listOf(listOf("appops_audit", "1", "6")),
            db.rows("SELECT service, ordinal, recordId FROM scan_finding WHERE scanId = $A"))
        val stored = Converters.decodeFinding(db.rows("SELECT findingJson FROM scan_finding")[0][0]!!, "test")!!
        assertEquals("appops_audit" to 1, stored.service to stored.ordinal)
        db.close()
    }

    @Test
    fun `an untriggered event-service finding is not stored, a snapshot one is`() {
        seed {
            scan(A, NOW, "[" + listOf(
                finding("androdr-003", "high", triggered = false, extra = ""","service":"dns_monitor""""),
                finding("androdr-040", "low", triggered = false, extra = ""","service":"device_auditor""""),
            ).joinToString(",") + "]")
        }
        val db = migrate()
        assertEquals(listOf("androdr-040"), db.rows("SELECT ruleId FROM scan_finding").map { it[0] })
        db.close()
    }

    @Test
    fun `migrated findings read back through FindingsRepository with matchContext and kind-free JSON`() = runBlocking {
        seed {
            fact(1L, "dns_monitor", eventTime = 1_700L, scanId = A, ordinal = 0)
            scan(A, NOW - DAY, "[" + dns(service = true) + "]")
        }
        migrate().close()
        val context = ApplicationProvider.getApplicationContext<Context>()
        val room = Room.databaseBuilder(context, AppDatabase::class.java, name).allowMainThreadQueries().build()
        try {
            val codec = TelemetryRecordCodec(TelemetryDictionaries { rawFile("$it.txt").readBytes() })
            val reader = TelemetryReader(room, codec, EventDisplay.parse(rawFile("event_display.yml").readText()))
            val f = FindingsRepository(room, reader) { true }.findingsOf(A).single()
            assertEquals("androdr-003", f.ruleId)
            assertEquals(1L, f.recordId)
            assertEquals("evil.example", f.matchContext["domain"])
            assertEquals(1, FindingsRepository(room, reader) { true }.currentOnce().openAlertCount)
            assertTrue(room.scanResultDao().getLatestTwo().single().maxLevel == "high")
        } finally {
            room.close()
        }
    }

    /** Ruling R39: an alert spanning scans follows its latest activity, not its opener's age. */
    @Test
    fun `an alert opened over 30 days ago with a finding within 30 days stays OPEN`() {
        seed {
            scan(A, NOW - 40 * DAY, "[" + dns(service = false, time = 1_234L) + "]")
            scan(B, NOW - 10 * DAY, "[" + dns(service = false, time = 1_234L) + "]")
        }
        val db = migrate()
        assertEquals(listOf(listOf("$A", "OPEN", "${NOW - 10 * DAY}")),
            db.rows("SELECT openedScanId, status, lastActivityAt FROM alert"))
        assertEquals(2L, db.long("SELECT COUNT(*) FROM scan_finding WHERE alertId IS NOT NULL"))
        db.close()
    }

    /** Review Minor 1: a scan the sweep will remove opens no alert and leaves no unattached key. */
    @Test
    fun `an IN_PROGRESS scan's findings carry no alert key`() {
        seed { scan(A, NOW, "[" + dns(service = false) + "]", state = "IN_PROGRESS") }
        val db = migrate()
        assertEquals(1L, db.long("SELECT COUNT(*) FROM scan_finding"))
        assertEquals(0L, db.long("SELECT COUNT(*) FROM scan_finding WHERE alertKey IS NOT NULL"))
        assertEquals(0L, db.long("SELECT COUNT(*) FROM alert"))
        db.close()
    }

    @Test
    fun `alert ids are AUTOINCREMENT after the upgrade`() {
        seed { }
        val db = migrate()
        val sql = db.rows("SELECT sql FROM sqlite_master WHERE name = 'alert'").single()[0]!!
        assertTrue(sql, sql.uppercase().contains("AUTOINCREMENT"))
        db.close()
    }

    private companion object {
        const val DAY = 24L * 60 * 60 * 1000
        const val NOW = 1_800_000_000_000L
        const val A = 101L
        const val B = 102L
        const val C = 103L
        const val D = 104L
        const val E = 105L
        const val F = 106L
    }
}

package com.androdr.data.repo

import com.androdr.data.db.LegacyEventRowCleanup
import com.androdr.data.db.PinnedFact
import com.androdr.data.db.SignalMemberBackfill
import com.androdr.data.db.VisibleFact
import com.androdr.data.db.getAllForExport
import com.androdr.data.db.toForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TelemetryState
import com.androdr.data.store.AtomReader
import com.androdr.data.store.StoreFixture.Companion.CAPTURED
import com.androdr.data.store.StoreFixture.Companion.app
import com.androdr.data.store.StoreFixture.Companion.dns
import com.androdr.reporting.ReportFiles
import com.androdr.scanner.StartupSweep
import com.androdr.scanner.WriteResult
import com.androdr.scanner.WriterFixture
import com.androdr.scanner.WriterFixture.Companion.APP_RULE
import com.androdr.scanner.WriterFixture.Companion.DNS_RULE
import com.androdr.scanner.WriterFixture.Companion.EVIL_APP
import com.androdr.scanner.WriterFixture.Companion.EVIL_DOMAIN
import com.androdr.scanner.WriterFixture.Companion.IMPORT_CAPTURED
import com.androdr.scanner.WriterFixture.Companion.SEC_RULE
import com.androdr.scanner.WriterFixture.Companion.securityLine
import com.androdr.sigma.Evidence
import com.androdr.sigma.Fact
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import com.androdr.sigma.Row
import com.androdr.sigma.StoreRecord
import com.androdr.sigma.TimelineAtom
import com.androdr.ui.security.ConfirmResult
import io.mockk.coEvery
import io.mockk.spyk
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.nio.file.Files

/**
 * L1 (spec §5.4 Lifecycle, §9): state findings follow the latest live scan, alerts last until a
 * person closes them, an overlapping import attaches to the same alert, correlation findings are
 * state findings of their scan, alert identity is stable across an IOC re-sync, and an alert's
 * evidence outlives its scan; plus S3 re-run with `scan_finding` pins.
 */
@RunWith(RobolectricTestRunner::class)
class FindingLifecycleTest {
    private val w = WriterFixture()
    private val reports = Files.createTempDirectory("lifecycle-reports").toFile()

    @After fun tearDown() {
        w.close()
        reports.deleteRecursively()
    }

    private val findings get() = w.f.findings
    private val live = TelemetrySource.LIVE_SCAN
    private val il = TelemetrySource.INTRUSION_LOG_IMPORT

    private suspend fun liveScan(
        id: Long, apps: List<StoreRecord> = emptyList(), dnsRecords: List<StoreRecord> = emptyList(),
        hooks: SessionHooks = SessionHooks.NONE,
    ): WriteResult {
        val s = w.writer.begin(w.scan(id), liveEvents = true, hooks)
        if (apps.isNotEmpty()) s.append("app_scanner", live, CAPTURED, apps)
        if (dnsRecords.isNotEmpty()) s.append("dns_monitor", live, CAPTURED, dnsRecords)
        return s.finish()
    }

    private suspend fun intrusionLog(id: Long, vararg lines: StoreRecord): WriteResult {
        val s = w.writer.begin(w.scan(id, il), liveEvents = false)
        s.append("security_log", il, IMPORT_CAPTURED, lines.toList())
        return s.finish()
    }

    private fun alertIds(): List<Long> = w.f.db.openHelper.readableDatabase
        .query("SELECT id FROM alert ORDER BY id").use { c -> buildList { while (c.moveToNext()) add(c.getLong(0)) } }

    private fun str(sql: String): String? = w.f.db.openHelper.readableDatabase.query(sql)
        .use { c -> if (c.moveToFirst() && !c.isNull(0)) c.getString(0) else null }

    private fun sweep() = StartupSweep(w.lock, w.repo, w.f.store, w.f.dirty, ReportFiles(reports),
        SignalMemberBackfill(w.f.db, w.f.db.signalMemberBackfillDao(), w.f.db.signalMemberDao(), w.lock,
            w.f.dataStore),
        LegacyEventRowCleanup(w.f.db,
            TimelineRowDeleter(w.f.db.forensicTimelineEventDao(), w.f.store, w.f.db.signalMemberDao()),
            w.f.db.signalMemberDao(), w.f.store, w.lock, w.f.dataStore))

    @Test
    fun `a state finding follows the latest live scan and survives an import`() = runBlocking {
        liveScan(1L, apps = listOf(app(EVIL_APP), app("com.ok")))
        assertEquals(listOf(APP_RULE), findings.currentOnce().stateFindings.map { it.ruleId })
        assertEquals(0, findings.currentOnce().openAlertCount)

        intrusionLog(2L, securityLine())
        val afterImport = findings.currentOnce()
        assertEquals("imports never displace live state", listOf(APP_RULE), afterImport.stateFindings.map { it.ruleId })
        assertEquals("matchContext rebuilt from the fact", EVIL_APP,
            afterImport.stateFindings.single().matchContext["package_name"])
        assertEquals("the import's event finding is an alert", 1, afterImport.openAlertCount)

        liveScan(3L, apps = listOf(app("com.ok")))
        assertEquals("cleared by the next live scan", emptyList<String>(),
            findings.currentOnce().stateFindings.map { it.ruleId })
        assertEquals(1, findings.currentOnce().count)
    }

    @Test
    fun `an alert persists until a person closes it, a closed alert stays closed, a new fact opens a new one`() =
        runBlocking {
            liveScan(1L, dnsRecords = listOf(dns(EVIL_DOMAIN, key = "dns:1")))
            liveScan(2L, apps = listOf(app("com.ok")))
            assertEquals("still open after a clean scan", 1, findings.currentOnce().openAlertCount)
            val id = alertIds().single()

            assertEquals(0, findings.close(listOf(id), "x", ConfirmResult.Cancelled))
            assertEquals(0, findings.close(listOf(id), "x", ConfirmResult.NoSecureLock))
            assertEquals("fails closed", 1, findings.currentOnce().openAlertCount)
            assertEquals(1, findings.close(listOf(id), "checked", ConfirmResult.Confirmed))
            assertEquals(0, findings.currentOnce().openAlertCount)
            assertEquals("CLOSED|checked|1", str("SELECT status || '|' || closedReason || '|' || " +
                "closedWithCredential FROM alert WHERE id = $id"))

            // A re-fire on the same fact (the late-IOC re-check) neither re-opens nor re-surfaces it.
            val factId = w.count("SELECT recordId FROM alert WHERE id = $id")
            val s = w.writer.begin(w.scan(3L), liveEvents = true)
            s.evaluateStored("dns_monitor", sequenceOf(factId to dns(EVIL_DOMAIN, key = "dns:1")))
            s.finish()
            assertEquals("CLOSED", str("SELECT status FROM alert WHERE id = $id"))

            liveScan(4L, dnsRecords = listOf(dns(EVIL_DOMAIN, time = 2L, key = "dns:2")))
            assertEquals("a new fact opens a new alert", 2, alertIds().size)
            assertEquals(1, findings.currentOnce().openAlertCount)
        }

    @Test
    fun `import B attaches to A's alert and keeps its own scan_finding row`() = runBlocking {
        intrusionLog(10L, securityLine())
        intrusionLog(20L, securityLine())
        assertEquals(1, alertIds().size)
        assertEquals(2L, w.count("SELECT COUNT(*) FROM scan_finding WHERE ruleId = '$SEC_RULE'"))
        assertEquals(1L, w.count("SELECT COUNT(DISTINCT alertId) FROM scan_finding WHERE ruleId = '$SEC_RULE'"))
        assertEquals(1L, w.count("SELECT COUNT(DISTINCT recordId) FROM scan_finding"))
        assertEquals("opened by A", 10L, w.count("SELECT openedScanId FROM alert"))
        assertEquals("re-surfaced by B", 20L, w.count("SELECT lastActivityAt FROM alert"))
        assertEquals(1, w.findingsOf(10L).size)
        assertEquals(1, w.findingsOf(20L).size)
    }

    private val chain = Finding(ruleId = "androdr-corr-004", title = "Permissions accessed rapidly", level = "high",
        category = FindingCategory.CORRELATION, matchContext = mapOf("member_count" to "2"))

    @Test
    fun `correlation findings are state findings of their scan and open no alert`() = runBlocking {
        val hooks = object : SessionHooks {
            override suspend fun correlate(scan: ScanResult, atoms: AtomReader) =
                Correlation(emptyList(), listOf(chain))
        }
        liveScan(1L, hooks = hooks)
        liveScan(2L, hooks = hooks)
        assertEquals(listOf("STATE", "STATE"), (1L..2L).map {
            str("SELECT kind FROM scan_finding WHERE scanId = $it AND category = 'CORRELATION'")
        })
        assertEquals(0L, w.count("SELECT COUNT(*) FROM alert"))
        assertEquals(0L, w.count("SELECT COUNT(*) FROM scan_finding WHERE alertKey IS NOT NULL"))
        val current = findings.currentOnce()
        assertEquals("the same chain in the next scan is again a state finding of that scan",
            listOf(chain.ruleId), current.stateFindings.map { it.ruleId })
        assertEquals("2", current.stateFindings.single().matchContext["member_count"])
        assertEquals(listOf(chain), w.findingsOf(2L))
        assertEquals(1, w.f.db.scanResultDao().getLatestTwo().first().triggeredCount)
    }

    @Test
    fun `this scan's own timeline rows are Row atoms with real ids, and an event binds once`() = runBlocking {
        var withRows: List<TimelineAtom> = emptyList()
        var factsOnly: List<TimelineAtom> = emptyList()
        val hooks = object : SessionHooks {
            override suspend fun correlate(scan: ScanResult, atoms: AtomReader): Correlation {
                withRows = atoms.atomsForScan(scan.id, setOf("app_risk", "dns_query"))
                factsOnly = atoms.atomsForScan(scan.id, setOf("dns_query"))
                return Correlation.NONE
            }
        }
        liveScan(1L, dnsRecords = listOf(dns(EVIL_DOMAIN, key = "dns:1")), hooks = hooks)
        val row = w.f.db.forensicTimelineEventDao().getAllForExport().single()
        assertEquals(DNS_RULE, row.ruleId)
        assertTrue("the INSERT … SELECT row has a real id", row.id > 0)
        // When the row's category is bound, the row is the event's atom and its fact is not read again.
        assertEquals("the finding row is a Row atom with its real id; the event binds once",
            listOf(Row(row.id)), withRows.map { it.ref })
        assertEquals("otherwise the event binds once, as its fact", listOf(Fact(row.recordId!!)),
            factsOnly.map { it.ref })
    }

    /** Findings with [evidence] on one stored DNS record of [scanId], recorded straight through the repository. */
    private suspend fun recordOn(scanId: Long, vararg evidence: Evidence) {
        val chunk = w.f.persist(scanId, "dns_monitor", listOf(dns(EVIL_DOMAIN, key = "dns:9")))
        val found = evidence.map { e ->
            Finding(ruleId = DNS_RULE, title = "t", level = "high", category = FindingCategory.APP_RISK,
                evidence = e, service = "dns_monitor", ordinal = 0)
        }
        val scan = w.scan(scanId)
        findings.recordChunk(scanId, 0, found, chunk) { it.toForensicTimelineEvent(scan) }
    }

    private suspend fun finishBare(scanId: Long) =
        w.repo.finish(w.scan(scanId), FindingTotals(), SessionHooks.NONE, TelemetryState.STORED)

    @Test
    fun `two evidence results on one record yield two alerts`() = runBlocking {
        w.writer.begin(w.scan(1L), liveEvents = false)
        recordOn(1L, Evidence.IocMatch("a.example", "domain", "feed"), Evidence.IocMatch("b.example", "domain", "feed"))
        finishBare(1L)
        assertEquals(2, alertIds().size)
        assertEquals(1L, w.count("SELECT COUNT(DISTINCT recordId) FROM alert"))
    }

    @Test
    fun `the evidence discriminator is unchanged after an IOC re-sync`() = runBlocking {
        w.writer.begin(w.scan(1L), liveEvents = false)
        recordOn(1L, Evidence.IocMatch(EVIL_DOMAIN, "domain", "feed-a", family = "Pegasus", reference = "r1"))
        finishBare(1L)
        w.writer.begin(w.scan(2L), liveEvents = false)
        recordOn(2L, Evidence.IocMatch(EVIL_DOMAIN, "domain", "feed-b", family = "Graphite", reference = "r2"))
        finishBare(2L)
        assertEquals("one alert, both findings attached", 1, alertIds().size)
        assertEquals(2L, w.count("SELECT COUNT(*) FROM scan_finding WHERE alertId IS NOT NULL"))
        val evidence = findings.alerts(alertIds()).single().evidence!!.evidence as Evidence.IocMatch
        assertEquals("the opening finding is the evidence", "Pegasus", evidence.family)
    }

    @Test
    fun `an alert's matched fact survives its opening scan's deletion and retention and still decodes`() =
        runBlocking {
            liveScan(1L, dnsRecords = listOf(dns(EVIL_DOMAIN, key = "dns:5")), apps = listOf(app("com.ok")))
            val alert = findings.alerts(alertIds()).single()
            val factId = checkNotNull(alert.recordId)
            // A simulated 31-day live-event retention: the event's observations go (D4 adds the pass).
            w.f.db.openHelper.writableDatabase.execSQL("DELETE FROM scan_record WHERE recordId = $factId")
            w.f.store.gcUnobservedUnpinned()
            w.repo.markForDelete(1L)
            w.repo.completeDelete(1L)
            w.f.store.gcUnobservedUnpinned()

            assertEquals("only the alert's fact is left", 1L, w.count("SELECT COUNT(*) FROM telemetry_record"))
            assertEquals(1L,
                w.count("SELECT COUNT(*) FROM telemetry_record f WHERE f.id = $factId AND ${VisibleFact.SQL}"))
            // "Matched record" reads the fact by recordId through TelemetryReader.
            val record = w.f.reader.records(listOf(factId)).single()
            assertEquals(EVIL_DOMAIN, record.fields?.get("domain"))
            assertEquals(live, record.source)
            val evidence = findings.alerts(listOf(alert.id)).single().evidence
            assertNotNull("the alert's evidence JSON is present", evidence)
            assertEquals(EVIL_DOMAIN, evidence!!.matchContext["domain"])
            assertEquals(factId, evidence.recordId)
        }

    @Test
    fun `a killed mid-import leaves no alert, and nothing of it is visible`() = runBlocking {
        val s = w.writer.begin(w.scan(1L, il), liveEvents = false)
        s.append("security_log", il, IMPORT_CAPTURED, listOf(securityLine()))
        // Killed here: no finish.
        assertEquals(1L, w.count("SELECT COUNT(*) FROM scan_finding"))
        assertEquals(0L, w.count("SELECT COUNT(*) FROM alert"))
        assertEquals(emptyList<Finding>(), w.findingsOf(1L))
        assertEquals(0, findings.currentOnce().openAlertCount)
        sweep().run()
        assertEquals(0L, w.count("SELECT COUNT(*) FROM scan_finding"))
        assertEquals(0L, w.count("SELECT COUNT(*) FROM alert"))
        assertEquals(0L, w.count("SELECT COUNT(*) FROM telemetry_record"))
    }

    /** S3 re-run with scan_finding pins (spec §9). */
    @Test
    fun `a crash between delete batches of a COMPLETE scan leaves no visible orphan, the sweep finishes it`() =
        runBlocking {
            val apps = listOf(app(EVIL_APP)) + (0 until 600).map { app("com.app$it") }
            liveScan(1L, apps = apps, dnsRecords = listOf(dns(EVIL_DOMAIN, key = "dns:1")))
            assertEquals(602L, w.count("SELECT COUNT(*) FROM scan_record"))
            val store = spyk(w.f.store)
            var batches = 0
            coEvery { store.deleteBatch(any(), any()) } coAnswers {
                check(++batches != 2) { "killed between batches" }
                callOriginal()
            }
            val repo = ScanWriteRepository(w.f.db, store,
                TimelineRowDeleter(w.f.db.forensicTimelineEventDao(), store, w.f.db.signalMemberDao()), findings)
            repo.markForDelete(1L)
            assertTrue(runCatching { repo.completeDelete(1L) }.isFailure)
            assertEquals("the first batch committed", 2, batches)
            assertEquals("DELETING", str("SELECT state FROM ScanResult WHERE id = 1"))
            assertEquals(0L, w.count("SELECT COUNT(*) FROM scan_finding"))
            assertEquals("no visible unpinned orphan", 0L, w.count(
                "SELECT COUNT(*) FROM telemetry_record f WHERE ${VisibleFact.SQL} AND NOT ${PinnedFact.SQL}"))
            assertEquals("nothing of the DELETING scan is visible but the alert's evidence", 0L, w.count(
                "SELECT COUNT(*) FROM telemetry_record f WHERE ${VisibleFact.SQL} AND f.id NOT IN " +
                    "(SELECT recordId FROM alert)"))

            sweep().run()
            assertEquals(null, str("SELECT state FROM ScanResult WHERE id = 1"))
            assertEquals("only the alert's fact survives", 1L, w.count("SELECT COUNT(*) FROM telemetry_record"))
            assertEquals(1L, w.count("SELECT COUNT(*) FROM telemetry_record WHERE id = (SELECT recordId FROM alert)"))
        }
}

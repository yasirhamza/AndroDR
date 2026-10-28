package com.androdr.data.repo

import android.content.Context
import androidx.paging.PagingSource
import androidx.room.withTransaction
import androidx.test.core.app.ApplicationProvider
import com.androdr.data.db.LegacyEventRowCleanup
import com.androdr.data.db.SignalMemberBackfill
import com.androdr.data.db.getAllForExport
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanState
import com.androdr.data.model.SignalMember
import com.androdr.data.model.TelemetrySource
import com.androdr.data.store.StoreFixture.Companion.CAPTURED
import com.androdr.data.store.StoreFixture.Companion.dns
import com.androdr.ioc.Campaign
import com.androdr.reporting.ExportMode
import com.androdr.reporting.ReportExporter
import com.androdr.reporting.ReportFiles
import com.androdr.scanner.StartupSweep
import com.androdr.scanner.WriterFixture
import com.androdr.scanner.WriterFixture.Companion.DNS_RULE
import com.androdr.scanner.WriterFixture.Companion.EVIL_DOMAIN
import com.androdr.ui.security.ConfirmResult
import com.androdr.ui.timeline.ClusterMembers
import com.androdr.ui.timeline.TimelineEntries
import com.androdr.ui.timeline.TimelinePagingSource
import com.androdr.data.db.TimelineFilter
import com.androdr.util.AppVersion
import com.androdr.util.appVersion
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.withLock
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File
import java.nio.file.Files

/**
 * L2 (spec §5.4, §9): closing alerts needs the device credential (bulk close under one confirmation;
 * `NoSecureLock` honoured only after a re-check finds no secure lock screen), each close writes a
 * persistent `alert_closed` row; the open list groups by rule and matched value and re-surfaces by
 * latest activity. Deleting a scan or "Clear all" writes one capped persistent audit row in its
 * first transaction, never deletes an alert or what it references, is refused while a scan runs, and
 * is finished by the startup sweep when killed.
 */
@RunWith(RobolectricTestRunner::class)
class AlertCloseTest {
    private val w = WriterFixture()
    private val dir: File = Files.createTempDirectory("alert-close").toFile()
    private val reports: File = Files.createTempDirectory("alert-close-reports").toFile()
    private val findings get() = w.f.findings
    private val dao get() = w.f.db.forensicTimelineEventDao()

    @Before fun setUp() {
        mockkStatic("com.androdr.util.AppVersionKt")
        every { any<Context>().appVersion() } returns AppVersion("test", 1L)
    }

    @After fun tearDown() {
        unmockkAll()
        w.close()
        dir.deleteRecursively()
        reports.deleteRecursively()
    }

    // ── fixtures ────────────────────────────────────────────────────────────────

    private fun repository() = ScanRepository(w.f.db.scanResultDao(), w.f.db.dnsEventDao(), dao,
        mockk(relaxed = true), w.repo, w.lock, w.f.db)

    private fun sweep() = StartupSweep(w.lock, w.repo, w.f.store, w.f.dirty, ReportFiles(reports) { 0L },
        SignalMemberBackfill(w.f.db, w.f.db.signalMemberBackfillDao(), w.f.db.signalMemberDao(), w.lock,
            w.f.dataStore),
        LegacyEventRowCleanup(w.f.db,
            TimelineRowDeleter(dao, w.f.store, w.f.db.signalMemberDao()),
            w.f.db.signalMemberDao(), w.f.store, w.lock, w.f.dataStore))

    private fun exporter() = ReportExporter(ApplicationProvider.getApplicationContext(), w.f.reader,
        mockk {
            every { campaigns() } returns listOf(Campaign("pegasus", "Pegasus"))
            every { ruleScopes() } returns emptyMap()
            every { ruleCategoryById() } returns emptyMap()
        }, ReportFiles(dir), findings)

    private suspend fun report(scan: ScanResult): String {
        val file = File(dir, "report-${scan.id}.txt")
        exporter().writeTo(file, scan, ExportMode.FINDINGS_ONLY, includeLog = false)
        return file.readText()
    }

    /** A finished live scan with one DNS fact per time on [domain] (the test DNS rule fires on EVIL_DOMAIN). */
    private suspend fun dnsScan(id: Long, vararg times: Long, domain: String = EVIL_DOMAIN): ScanResult {
        val s = w.writer.begin(w.scan(id), liveEvents = false)
        s.append("dns_monitor", TelemetrySource.LIVE_SCAN, CAPTURED,
            times.map { dns(domain, time = it, key = "dns $id $it") })
        return s.finish().scan
    }

    private fun count(sql: String) = w.count(sql)
    private fun ids(sql: String): List<Long> = w.f.db.openHelper.readableDatabase.query(sql).use { c ->
        buildList { while (c.moveToNext()) add(c.getLong(0)) }
    }

    private fun interruptedRows() =
        count("SELECT COUNT(*) FROM forensic_timeline WHERE category = '${StartupSweep.CATEGORY}'")

    private fun openIds() = ids("SELECT id FROM alert WHERE status = 'OPEN' ORDER BY id")
    private fun closedRows() = runBlocking {
        dao.getAllForExport().filter { it.category == FindingsRepository.CLOSED_CATEGORY }
    }
    private fun auditRows() = runBlocking { dao.getAllForExport().filter { it.category == DeletionAudit.CATEGORY } }

    /** Inserts an alert directly (grouping tests need matched values the test rules cannot produce). */
    private fun alert(id: Long, rule: String, value: String, last: Long) {
        w.f.db.openHelper.writableDatabase.execSQL(
            "INSERT INTO alert (id, alertKey, ruleId, status, openedAt, openedScanId, lastActivityAt, " +
                "closedWithCredential, level, recordId, evidenceJson, matchedValue) VALUES " +
                "($id, X'${"%032x".format(id)}', '$rule', 'OPEN', $last, 1, $last, 0, 'high', NULL, '{}', '$value')"
        )
    }

    private suspend fun groups(size: Int = 50) = OpenAlertGroupPagingSource(w.f.db)
        .load(PagingSource.LoadParams.Refresh(null, size, false))
        .let { it as PagingSource.LoadResult.Page<AlertGroupCursor, AlertGroup> }

    // ── confirmation (L2) ───────────────────────────────────────────────────────

    @Test
    fun `close and bulk close do nothing without Confirmed`() = runBlocking {
        dnsScan(1L, 1L, 2L, 3L)
        val open = openIds()
        assertEquals(3, open.size)
        val group = groups().data.single().ref
        assertEquals(0, findings.close(open, "x", ConfirmResult.Cancelled))
        assertEquals(0, findings.closeGroups(listOf(group), "x", ConfirmResult.Cancelled))
        assertEquals(open, openIds())
        assertTrue("no closure row without a close", closedRows().isEmpty())
    }

    @Test
    fun `NoSecureLock while isDeviceSecure is true is refused`() = runBlocking {
        dnsScan(1L, 1L, 2L)
        w.f.deviceSecure = true
        val group = groups().data.single().ref
        assertEquals(0, findings.close(openIds(), null, ConfirmResult.NoSecureLock))
        assertEquals(0, findings.closeGroups(listOf(group), null, ConfirmResult.NoSecureLock))
        assertEquals(2, openIds().size)
        assertTrue(closedRows().isEmpty())
    }

    @Test
    fun `NoSecureLock on a device with no secure lock closes and records no credential`() = runBlocking {
        dnsScan(1L, 1L)
        w.f.deviceSecure = false
        assertEquals(1, findings.close(openIds(), "no lock here", ConfirmResult.NoSecureLock))
        assertEquals(0L, count("SELECT closedWithCredential FROM alert"))
        assertEquals("CLOSED", w.f.db.alertDao().alertsByIds(listOf(1L)).single().status.name)
        val row = closedRows().single()
        assertTrue(row.persistent)
        assertTrue(row.details, row.details.contains("Closed with device credential: no"))
    }

    @Test
    fun `Confirmed bulk close closes every selected group under one confirmation and writes one closure row`() =
        runBlocking {
            for (id in 1L..4L) alert(id, "r-flood", "flood.example", 100L + id)
            alert(5L, "r-quiet", "quiet.example", 50L)
            alert(6L, "r-other", "other.example", 40L)
            val g = groups().data
            assertEquals(3, g.size)
            val chosen = g.filter { it.ruleId != "r-other" }.map { it.ref }
            assertEquals(5, findings.closeGroups(chosen, "  reviewed ", ConfirmResult.Confirmed))
            assertEquals(listOf(6L), openIds())
            assertEquals(5L, count("SELECT COUNT(*) FROM alert WHERE status = 'CLOSED' AND closedWithCredential = 1"))
            val row = closedRows().single()
            assertTrue(row.persistent)
            assertEquals(-1L, row.scanResultId)
            assertEquals("Closed 5 alert(s)", row.description)
            assertTrue(row.details, row.details.contains("Closed with device credential: yes"))
            assertTrue(row.details, row.details.contains("r-flood · flood.example × 4"))
            assertTrue(row.details, row.details.contains("r-quiet · quiet.example × 1"))
            // A single close by id records its note too.
            assertEquals(1, findings.close(listOf(6L), "one", ConfirmResult.Confirmed))
            assertEquals(2, closedRows().size)
            assertEquals("one", w.f.db.alertDao().alertsByIds(listOf(6L)).single().closedReason)
        }

    @Test
    fun `a group close stops at the alerts the person saw`() = runBlocking {
        alert(1L, "r", "v", 10L)
        alert(2L, "r", "v", 11L)
        val seen = groups().data.single().ref
        alert(3L, "r", "v", 12L) // a new alert of the same group, opened after the person looked
        assertEquals(2, findings.closeGroups(listOf(seen), null, ConfirmResult.Confirmed))
        assertEquals(listOf(3L), openIds())
    }

    @Test
    fun `the open list groups by rule and matched value and re-surfaces by latest activity`() = runBlocking {
        for (i in 0 until 300) alert(100L + i, "r1", "flood.example", 1_000L + i)
        alert(1L, "r1", "quiet.example", 50L)
        alert(2L, "r2", "", 60L)
        val page = groups(10).data
        assertEquals("a flood of one indicator is one group", listOf("flood.example", "", "quiet.example"),
            page.map { it.matchedValue })
        assertEquals(listOf(300, 1, 1), page.map { it.count })
        assertEquals(399L, page.first().maxId)
        assertEquals("the newest alert is the group's sample", 399L, page.first().sample?.id)
        // Activity on the quiet alert re-surfaces its group first.
        w.f.db.openHelper.writableDatabase.execSQL("UPDATE alert SET lastActivityAt = 5000 WHERE id = 1")
        assertEquals("quiet.example", groups(10).data.first().matchedValue)
        // Keyset paging one group at a time: append, an inclusive refresh at any key, and prepend.
        val source = OpenAlertGroupPagingSource(w.f.db)
        val all = mutableListOf<AlertGroup>()
        var res = source.load(PagingSource.LoadParams.Refresh(null, 1, false)) as
            PagingSource.LoadResult.Page<AlertGroupCursor, AlertGroup>
        all += res.data
        while (res.nextKey != null) {
            res = source.load(PagingSource.LoadParams.Append(res.nextKey!!, 1, false)) as
                PagingSource.LoadResult.Page<AlertGroupCursor, AlertGroup>
            all += res.data
        }
        assertEquals(listOf("quiet.example", "flood.example", ""), all.map { it.matchedValue })
        val middle = AlertGroupCursor(all[1].lastActivityAt, all[1].ruleId, all[1].matchedValue)
        val refreshed = OpenAlertGroupPagingSource(w.f.db).load(PagingSource.LoadParams.Refresh(middle, 1, false))
            as PagingSource.LoadResult.Page<AlertGroupCursor, AlertGroup>
        assertEquals("refresh is inclusive", "flood.example", refreshed.data.single().matchedValue)
        val before = OpenAlertGroupPagingSource(w.f.db).load(PagingSource.LoadParams.Prepend(middle, 5, false))
            as PagingSource.LoadResult.Page<AlertGroupCursor, AlertGroup>
        assertEquals(listOf("quiet.example"), before.data.map { it.matchedValue })
    }

    @Test
    fun `the writer stores the group value an alert groups by`() = runBlocking {
        dnsScan(1L, 1L)
        // The test DNS rule carries no evidence value, so the group is the record's app (review I4).
        assertEquals(1L, count("SELECT COUNT(*) FROM scan_finding WHERE alertKey IS NOT NULL " +
            "AND matchedValue = 'com.example'"))
        assertEquals(1L, count("SELECT COUNT(*) FROM alert WHERE matchedValue = 'com.example'"))
    }

    /** A live DNS record from [pkg] on EVIL_DOMAIN (the test rule fires; its evidence has no value). */
    private fun dnsFrom(pkg: String, time: Long) = com.androdr.sigma.StoreRecord(
        mapOf("domain" to EVIL_DOMAIN, "app_uid" to 10_001, "source_package" to pkg, "is_blocked" to false,
            "reason" to null, "timestamp" to time), "dns $pkg $time")

    @Test
    fun `value-less alerts of one rule group per app, and closing one app's group leaves the other open`() =
        runBlocking {
            val s = w.writer.begin(w.scan(1L), liveEvents = false)
            s.append("dns_monitor", TelemetrySource.LIVE_SCAN, CAPTURED,
                (1L..50L).map { dnsFrom("com.flood", it) } + listOf(dnsFrom("com.quiet", 99L)))
            s.finish()
            val g = groups().data
            assertEquals("one app's flood cannot bury another app's alert", setOf("com.flood", "com.quiet"),
                g.map { it.matchedValue }.toSet())
            assertEquals(50, g.single { it.matchedValue == "com.flood" }.count)
            val flood = g.single { it.matchedValue == "com.flood" }.ref
            assertEquals(50, findings.closeGroups(listOf(flood), null, ConfirmResult.Confirmed))
            assertEquals("the other app's alert stays open", 1, openIds().size)
            assertEquals("com.quiet", w.f.db.alertDao().alertsByIds(openIds()).single().matchedValue)
        }

    @Test
    fun `current findings carry the most severe open alert level`() = runBlocking {
        alert(1L, "r", "a", 1L)
        w.f.db.openHelper.writableDatabase.execSQL("UPDATE alert SET level = 'critical' WHERE id = 1")
        alert(2L, "r", "b", 2L)
        assertEquals(com.androdr.data.model.RiskLevel.CRITICAL, findings.currentOnce().highestOpenAlertLevel)
        assertEquals(1, findings.close(listOf(1L), null, ConfirmResult.Confirmed))
        assertEquals(com.androdr.data.model.RiskLevel.HIGH, findings.currentOnce().highestOpenAlertLevel)
        assertEquals(1, findings.close(listOf(2L), null, ConfirmResult.Confirmed))
        assertNull(findings.currentOnce().highestOpenAlertLevel)
    }

    // ── deletion (L2) ───────────────────────────────────────────────────────────

    @Test
    fun `deleting a scan keeps its alert and writes an audit row listing its triggered findings`() = runBlocking {
        dnsScan(1L, 1L, 2L)
        assertEquals(DeleteResult.Done, repository().deleteScan(1L))
        assertEquals(0L, count("SELECT COUNT(*) FROM ScanResult"))
        assertEquals("alerts are never deleted", 2L, count("SELECT COUNT(*) FROM alert"))
        val audit = auditRows().single()
        assertTrue(audit.persistent)
        assertEquals(-1L, audit.scanResultId)
        assertTrue(audit.description, audit.description.startsWith("Scan of "))
        assertTrue(audit.details, audit.details.startsWith("2 triggered finding(s) deleted with this scan."))
        assertTrue(audit.details, audit.details.contains("Alerts and their evidence are kept"))
        assertTrue(audit.details, Regex("\\n$DNS_RULE · high · [^\\n]* × 2").containsMatchIn(audit.details))
    }

    @Test
    fun `the audit of a migrated scan reads each finding's package from findingJson`() = runBlocking {
        w.f.scan(1L, ScanState.COMPLETE)
        val json = """{"ruleId":"r-mig","title":"t","level":"high","category":"APP_RISK",""" +
            """"matchContext":{"package_name":"com.migrated"}}"""
        repeat(3) {
            w.f.db.openHelper.writableDatabase.execSQL(
                "INSERT INTO scan_finding (scanId, ruleId, triggered, level, category, kind, service, ordinal, " +
                    "findingJson) VALUES (1, 'r-mig', 1, 'high', 'APP_RISK', 'STATE', '', -1, '$json')"
            )
        }
        assertEquals(DeleteResult.Done, repository().deleteScan(1L))
        val details = auditRows().single().details
        assertTrue(details, details.contains("r-mig · high · com.migrated × 3"))
    }

    @Test
    fun `Clear all keeps alerts, closure and audit rows and removes live scan-less rows up to clearMaxRowId`() =
        runBlocking {
            dnsScan(1L, 1L)
            dnsScan(2L, 2L)
            assertEquals(1, findings.close(listOf(openIds().first()), "seen", ConfirmResult.Confirmed))
            val dnsRow = dao.insert(ForensicTimelineEvent(startTimestamp = 5L, source = "dns", category = "dns_query",
                description = "q"))
            val iocRow = dao.insert(ForensicTimelineEvent(startTimestamp = 6L, source = "dns", category = "ioc_match",
                description = "m"))
            val snapshot = w.lock.mutex.withLock {
                w.repo.markAllForAuditedDelete().also { w.repo.saveClearMark(it.clearMaxRowId) }
            }
            assertTrue(snapshot.clearMaxRowId >= iocRow)
            assertEquals(snapshot.clearMaxRowId, w.f.pendingClear.get())
            // A live row the VPN writes after the first transaction is not part of the clear.
            val later = dao.insert(ForensicTimelineEvent(startTimestamp = 7L, source = "dns", category = "dns_query",
                description = "later"))
            w.repo.completeDeleteAll(snapshot)
            assertEquals(0L, count("SELECT COUNT(*) FROM ScanResult"))
            assertEquals(0L, count("SELECT COUNT(*) FROM forensic_timeline WHERE id IN ($dnsRow, $iocRow)"))
            assertEquals(listOf(later), ids("SELECT id FROM forensic_timeline WHERE persistent = 0"))
            assertEquals("alerts are kept", 2L, count("SELECT COUNT(*) FROM alert"))
            assertEquals("the closure row is kept", 1, closedRows().size)
            assertEquals("one audit row for the clear", 1, auditRows().size)
            assertTrue(auditRows().single().details.startsWith("2 triggered finding(s) deleted by Clear all."))
            assertNull("the mark is dropped when the clear finishes", w.f.pendingClear.get())
            // The public path writes exactly one more audit row and still keeps everything persistent.
            assertEquals(DeleteResult.Done, repository().deleteAllScans())
            assertEquals(2, auditRows().size)
            assertEquals(1, closedRows().size)
            assertEquals(0L, count("SELECT COUNT(*) FROM forensic_timeline WHERE persistent = 0"))
        }

    @Test
    fun `the audit row of a 50,000-finding scan stays under 16 KB and the Timeline and report still load`() =
        runBlocking {
            w.f.scan(1L, ScanState.COMPLETE)
            val db = w.f.db.openHelper.writableDatabase
            w.f.recording = false
            w.f.db.withTransaction {
                val stmt = db.compileStatement(
                    "INSERT INTO scan_finding (scanId, ruleId, triggered, level, category, kind, service, ordinal, " +
                        "findingJson, row_startTimestamp, row_timestampPrecision, row_source, row_category, " +
                        "row_description, row_details, row_packageName, row_appName, row_apkHash, row_iocIndicator, " +
                        "row_iocType, row_iocSource, row_campaignName, row_correlationId, row_attackTechniqueId, " +
                        "row_telemetrySource) VALUES (1, ?, 1, 'high', 'APP_RISK', 'ALERT', 'dns_monitor', ?, '{}', " +
                        "1, 'exact', 'sigma', 'finding', 'd', '', ?, '', '', '', '', '', '', '', '', 'LIVE_SCAN')"
                )
                for (i in 0 until BIG) {
                    stmt.bindString(1, "androdr-rule-${i % 7}")
                    stmt.bindLong(2, i.toLong())
                    stmt.bindString(3, "com.example.a.rather.long.package.name.number$i")
                    stmt.executeInsert()
                    stmt.clearBindings()
                }
            }
            w.f.recording = true
            val other = dnsScan(2L, 1L)
            assertEquals(DeleteResult.Done, repository().deleteScan(1L))
            val audit = auditRows().single()
            val bytes = audit.details.toByteArray(Charsets.UTF_8).size + audit.description.length
            assertTrue("audit row is $bytes bytes", bytes < 16 * 1024)
            val entries = audit.details.lines().size - 2 // the header line and the "and K more" line
            assertTrue("$entries entries", entries in 1..DeletionAudit.MAX_ENTRIES)
            assertTrue(audit.details, audit.details.lines().last().startsWith("…and "))
            val listed = audit.details.lines().drop(1).dropLast(1).sumOf { it.substringAfterLast("× ").toLong() }
            assertEquals("…and ${BIG - listed} more finding(s)", audit.details.lines().last())
            // The Timeline's first page and the surviving scan's report still load.
            val page = TimelinePagingSource(w.f.db, TimelineFilter(), TimelineEntries(w.f.db, w.f.reader))
                .load(PagingSource.LoadParams.Refresh(null, 50, false))
            assertTrue(page is PagingSource.LoadResult.Page)
            assertTrue((page as PagingSource.LoadResult.Page).data.isNotEmpty())
            assertTrue(report(other).contains("ALERTS"))
        }

    @Test
    fun `an audit row of long package names is cut by its byte budget and stays under 16 KB`() = runBlocking {
        w.f.scan(1L, ScanState.COMPLETE)
        val longPkg = "com." + "x".repeat(200)
        for (i in 0 until 150) {
            w.f.db.openHelper.writableDatabase.execSQL(
                "INSERT INTO scan_finding (scanId, ruleId, triggered, level, category, kind, service, ordinal, " +
                    "findingJson, row_startTimestamp, row_timestampPrecision, row_source, row_category, " +
                    "row_description, row_details, row_packageName, row_appName, row_apkHash, row_iocIndicator, " +
                    "row_iocType, row_iocSource, row_campaignName, row_correlationId, row_attackTechniqueId, " +
                    "row_telemetrySource) VALUES (1, 'androdr-a-rule-with-a-long-identifier', 1, 'informational', " +
                    "'APP_RISK', 'ALERT', 'dns_monitor', $i, '{}', 1, 'exact', 'sigma', 'finding', 'd', '', " +
                    "'$longPkg$i', '', '', '', '', '', '', '', '', 'LIVE_SCAN')"
            )
        }
        assertEquals(DeleteResult.Done, repository().deleteScan(1L))
        val audit = auditRows().single()
        assertTrue("${audit.details.length} chars", audit.details.toByteArray(Charsets.UTF_8).size < 16 * 1024)
        assertTrue("fewer than the entry cap fit the budget",
            audit.details.lines().size - 2 < DeletionAudit.MAX_ENTRIES)
        assertTrue(audit.details.lines().last().startsWith("…and "))
    }

    @Test
    fun `Clear all saves clearMaxRowId before its second phase, so a kill there is finished by the sweep`() =
        runBlocking {
            dnsScan(1L, 1L)
            val live = dao.insert(ForensicTimelineEvent(startTimestamp = 3L, source = "dns", category = "dns_query",
                description = "pre-clear live"))
            val killed = io.mockk.spyk(w.repo)
            io.mockk.coEvery { killed.completeDeleteAll(any()) } throws IllegalStateException("killed")
            val repo = ScanRepository(w.f.db.scanResultDao(), w.f.db.dnsEventDao(), dao, mockk(relaxed = true),
                killed, w.lock, w.f.db)
            assertTrue(runCatching { repo.deleteAllScans() }.isFailure)
            assertNotNull("the mark is saved in the first step", w.f.pendingClear.get())
            assertFalse(w.lock.mutex.isLocked)
            sweep().run()
            assertEquals(0L, count("SELECT COUNT(*) FROM forensic_timeline WHERE id = $live"))
            assertNull(w.f.pendingClear.get())
        }

    @Test
    fun `deleteScan and Clear all return ScanRunning and change nothing while a writer runs or the lock is busy`() =
        runBlocking {
            dnsScan(1L, 1L)
            fun snapshot() = listOf("ScanResult", "forensic_timeline", "scan_finding", "alert", "telemetry_record")
                .map { count("SELECT COUNT(*) FROM $it") } +
                count("SELECT COUNT(*) FROM ScanResult WHERE state = 'COMPLETE'")
            val before = snapshot()
            val repo = repository().apply { deleteLockWaitMs = 150L }
            w.lock.withWriter {
                assertEquals(DeleteResult.ScanRunning, repo.deleteScan(1L))
                assertEquals(DeleteResult.ScanRunning, repo.deleteAllScans())
            }
            assertEquals(before, snapshot())
            val owner = Any()
            w.lock.mutex.lock(owner) // a retention or backfill batch: writerRunning stays false
            try {
                assertEquals(DeleteResult.ScanRunning, repo.deleteScan(1L))
                assertEquals(DeleteResult.ScanRunning, repo.deleteAllScans())
            } finally {
                w.lock.mutex.unlock(owner)
            }
            assertEquals(before, snapshot())
            assertTrue(auditRows().isEmpty())
            assertNull(w.f.pendingClear.get())
            assertEquals(DeleteResult.Done, repo.deleteScan(1L))
        }

    @Test
    fun `a scan that starts after Clear all's first transaction and completes before it ends survives`() =
        runBlocking {
            dnsScan(1L, 1L)
            val preClear = dao.insert(ForensicTimelineEvent(startTimestamp = 3L, source = "dns", category = "ioc_match",
                description = "pre-clear live"))
            val snapshot = w.lock.mutex.withLock {
                w.repo.markAllForAuditedDelete().also { w.repo.saveClearMark(it.clearMaxRowId) }
            }
            // Scan 2 takes the lock after the first transaction and finishes before the clear's second phase.
            val s = w.lock.withWriter { w.writer.begin(w.scan(2L), liveEvents = false) }
            s.append("dns_monitor", TelemetrySource.LIVE_SCAN, CAPTURED,
                listOf(dns(EVIL_DOMAIN, time = 9L, key = "k9")))
            s.finish()
            val ownRow = ids("SELECT id FROM forensic_timeline WHERE scanResultId = 2").single()
            // Its correlation signal bound one of its own rows and one pre-clear live row.
            val signal = dao.insert(ForensicTimelineEvent(startTimestamp = 9L, source = "sigma_correlation_engine",
                category = "correlation", description = "chain", kind = "signal", scanResultId = 2L))
            w.f.db.signalMemberDao().insertAll(listOf(SignalMember(signal, SignalMember.KIND_ROW, ownRow),
                SignalMember(signal, SignalMember.KIND_ROW, preClear)))
            w.repo.completeDeleteAll(snapshot)
            assertEquals(listOf(1L), snapshot.scanIds)
            assertEquals("COMPLETE", w.f.db.scanWriteDao().stateOf(2L)?.name)
            assertEquals(2L, count("SELECT COUNT(*) FROM forensic_timeline WHERE scanResultId = 2"))
            assertEquals(2L, count("SELECT COUNT(*) FROM signal_member WHERE signalRowId = $signal"))
            assertEquals(1L, count("SELECT COUNT(*) FROM scan_record WHERE scanId = 2"))
            val cluster = ClusterMembers(w.f.db.signalMemberDao(), dao, w.f.reader).load(signal, null)
            assertEquals(1, cluster.members.size)
            assertEquals("the pre-clear member loads as missing", 1, cluster.missing)
            assertNoDanglingRows()
        }

    @Test
    fun `deleting scan X whose row is a member of scan Y's signal leaves Y's remaining members`() = runBlocking {
        dnsScan(1L, 1L)
        dnsScan(2L, 2L)
        val xRow = ids("SELECT id FROM forensic_timeline WHERE scanResultId = 1").single()
        val yRow = ids("SELECT id FROM forensic_timeline WHERE scanResultId = 2").single()
        val signal = dao.insert(ForensicTimelineEvent(startTimestamp = 2L, source = "sigma_correlation_engine",
            category = "correlation", description = "chain", kind = "signal", scanResultId = 2L))
        w.f.db.signalMemberDao().insertAll(listOf(SignalMember(signal, SignalMember.KIND_ROW, xRow),
            SignalMember(signal, SignalMember.KIND_ROW, yRow)))
        assertEquals(DeleteResult.Done, repository().deleteScan(1L))
        assertEquals(0L, count("SELECT COUNT(*) FROM forensic_timeline WHERE id = $xRow"))
        val cluster = ClusterMembers(w.f.db.signalMemberDao(), dao, w.f.reader).load(signal, null)
        assertEquals(listOf(yRow),
            cluster.members.map { (it as com.androdr.ui.timeline.TimelineMember.RowMember).row.id })
        assertEquals(1, cluster.missing)
        assertNoDanglingRows()
    }

    @Test
    fun `a deleteScan killed after its first transaction leaves one audit row and the sweep finishes it`() =
        runBlocking {
            dnsScan(1L, 1L)
            assertTrue(w.lock.mutex.withLock { w.repo.markForAuditedDelete(1L) })
            // killed here
            assertEquals(1, sweep().run())
            assertEquals(0L, count("SELECT COUNT(*) FROM ScanResult"))
            val audit = auditRows().single()
            assertTrue(audit.details.isNotEmpty() && audit.details.contains(DNS_RULE))
            assertEquals(0L, interruptedRows())
            assertEquals(1L, count("SELECT COUNT(*) FROM alert"))
        }

    @Test
    fun `a Clear all killed after its first transaction leaves one audit row and the sweep finishes it`() =
        runBlocking {
            dnsScan(1L, 1L)
            dnsScan(2L, 2L)
            dao.insert(ForensicTimelineEvent(startTimestamp = 3L, source = "dns", category = "dns_query",
                description = "pre-clear live"))
            w.lock.mutex.withLock {
                w.repo.markAllForAuditedDelete().also { w.repo.saveClearMark(it.clearMaxRowId) }
            }
            // killed here
            assertEquals(2, sweep().run())
            assertEquals(0L, count("SELECT COUNT(*) FROM ScanResult"))
            assertEquals(0L, count("SELECT COUNT(*) FROM forensic_timeline WHERE persistent = 0"))
            val audit = auditRows().single()
            assertTrue(audit.details.startsWith("2 triggered finding(s) deleted by Clear all."))
            assertEquals(0L, interruptedRows())
            assertNull("the sweep removes the mark", w.f.pendingClear.get())
            assertEquals(2L, count("SELECT COUNT(*) FROM alert"))
        }

    @Test
    fun `after deleting an alert's opening scan and after Clear all its evidence and matched fact read back`() =
        runBlocking {
            dnsScan(1L, 1L)
            val alert = w.f.db.alertDao().alertsByIds(openIds()).single()
            assertEquals(DeleteResult.Done, repository().deleteScan(alert.openedScanId))
            assertEvidenceReadsBack(alert.id, dnsScan(2L, 50L, domain = "ok.example"))
            assertEquals(DeleteResult.Done, repository().deleteAllScans())
            assertEquals(0L, count("SELECT COUNT(*) FROM ScanResult"))
            assertEvidenceReadsBack(alert.id, dnsScan(3L, 60L, domain = "ok.example"))
        }

    private suspend fun assertEvidenceReadsBack(alertId: Long, reportScan: ScanResult) {
        val a = w.f.db.alertDao().alertsByIds(listOf(alertId)).single()
        assertTrue("evidenceJson is present", a.evidenceJson.isNotEmpty())
        assertNotNull(AlertView.of(a).evidence)
        // "Matched record": the alert's fact decodes through the reader.
        val matched = w.f.reader.records(listOf(a.recordId!!)).single()
        assertEquals(EVIL_DOMAIN, matched.fields?.get("domain"))
        // Every pinned fact decodes.
        val pinned = ids("SELECT recordId FROM alert WHERE recordId IS NOT NULL UNION " +
            "SELECT recordId FROM forensic_timeline WHERE recordId IS NOT NULL UNION " +
            "SELECT refId FROM signal_member WHERE kind = '${SignalMember.KIND_FACT}'")
        val decoded = w.f.reader.records(pinned)
        assertEquals(pinned.toSet(), decoded.map { it.factId }.toSet())
        assertTrue(decoded.all { it.fields != null })
        // The report lists the alert with its matched record.
        val text = report(reportScan)
        assertTrue(text, text.contains("matched record (dns_monitor): ") && text.contains("domain=$EVIL_DOMAIN"))
    }

    /** No non-persistent row names a scan that does not exist; no signal_member row lacks its signal. */
    private fun assertNoDanglingRows() {
        assertEquals(0L, count("SELECT COUNT(*) FROM forensic_timeline r WHERE r.persistent = 0 AND " +
            "r.scanResultId != -1 AND NOT EXISTS (SELECT 1 FROM ScanResult s WHERE s.id = r.scanResultId)"))
        assertEquals(0L, count("SELECT COUNT(*) FROM signal_member m WHERE NOT EXISTS " +
            "(SELECT 1 FROM forensic_timeline s WHERE s.id = m.signalRowId)"))
    }

    // ── report ───────────────────────────────────────────────────────────────────

    @Test
    fun `the report lists open alerts with their opening scan and closed alerts with time, note and flag`() =
        runBlocking {
            val scan = dnsScan(7L, 1L, 2L, 3L)
            val (a, b, c) = openIds()
            assertEquals(1, findings.close(listOf(a), "checked it", ConfirmResult.Confirmed))
            w.f.deviceSecure = false
            assertEquals(1, findings.close(listOf(b), null, ConfirmResult.NoSecureLock))
            val text = report(scan)
            val alerts = text.substringAfter("  ALERTS").substringBefore("End of report")
            val open = alerts.substringAfter("Open alerts:").substringBefore("Closed alerts:")
            val closed = alerts.substringAfter("Closed alerts:")
            assertEquals("one open alert, with its opening scan and its source", 1,
                Regex("by scan 7 \\(live scan\\),").findAll(open).count())
            assertTrue(open, open.contains("($DNS_RULE) · 1 alert(s)"))
            assertTrue(closed, closed.contains("($DNS_RULE) · 2 alert(s)"))
            assertTrue(closed, closed.contains("1 of 2 closed with the device credential"))
            assertTrue(closed, closed.contains("note: checked it · closed with device credential: yes"))
            assertTrue(closed, closed.contains("note: (none) · closed with device credential: no"))
            assertFalse("alert $c is open, not closed", closed.contains("by scan"))
        }

    /**
     * Review I5: the report groups alerts as the Dashboard does, lists at most the display bound per
     * group with an exact "…and K more", names a deleted opening scan, and words a migrated automatic
     * closure as automatic, not as a person closing without a lock.
     */
    @Test
    fun `the report groups alerts, bounds each group's listing and counts every alert`() = runBlocking {
        val total = com.androdr.reporting.ALERT_SAMPLE_DISPLAY_LIMIT + 5
        for (i in 1L..total) alert(i, "r-group", "flood.example", 100L + i)
        alert(500L, "r-other", "other.example", 50L)
        w.f.db.openHelper.writableDatabase.execSQL("INSERT INTO alert (id, alertKey, ruleId, status, openedAt, " +
            "openedScanId, lastActivityAt, closedAt, closedReason, closedWithCredential, level, recordId, " +
            "evidenceJson, matchedValue) VALUES (600, X'00000000000000000000000000000600', 'r-old', 'CLOSED', 1, " +
            "1, 1, 2, '${com.androdr.data.db.FindingsMigration.MIGRATED_CLOSED_REASON}', 0, 'high', NULL, '{}', 'v')")
        val text = report(dnsScan(9L, 1L, domain = "ok.example"))
        val alerts = text.substringAfter("  ALERTS").substringBefore("End of report")
        val group = alerts.substringAfter("(r-group) · $total alert(s)").substringBefore("(r-other)")
        assertEquals(com.androdr.reporting.ALERT_SAMPLE_DISPLAY_LIMIT, Regex("- opened ").findAll(group).count())
        assertTrue(group, group.contains("…and 5 more alert(s) of this group"))
        assertTrue("scan 1 does not exist", group.contains("by scan 1 (scan deleted)"))
        assertTrue(alerts, alerts.contains("${total + 1} open alert(s) in total"))
        assertTrue(alerts, alerts.contains("closed automatically") && alerts.contains("(migrated, older than 30 days)"))
    }

    private companion object {
        const val BIG = 50_000
    }
}

package com.androdr.scanner

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.UsageEvent
import com.androdr.data.repo.ScanLock
import com.androdr.data.repo.ScanRepository
import com.androdr.data.store.HashKeys
import com.androdr.sigma.TaxonomyContract
import io.mockk.coEvery
import io.mockk.mockk
import io.mockk.spyk
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * The live scan through its writer session (telemetry store §5.2): live DNS facts keyed by their row
 * id, `ioc_match` rows carrying the same key, usage events stored as facts only (C3), live events
 * observed once, and a failed write that keeps nothing.
 */
@RunWith(RobolectricTestRunner::class)
class LiveScanWriterTest {
    private val engine = IntrusionLogZips.engine(
        IntrusionLogZips.rule("androdr-lv-dns", "dns_monitor", "domain", "evil.example", "high"),
        IntrusionLogZips.rule("androdr-lv-app", "app_scanner", "package_name", "com.evil", "critical"),
    )
    private val f = OrchestratorFixture(engine = engine)

    @After fun tearDown() = f.close()

    private fun repo() = ScanRepository(
        scanResultDao = f.db.scanResultDao(), dnsEventDao = f.db.dnsEventDao(),
        forensicTimelineEventDao = f.timelineDao, indicatorResolver = f.indicatorResolver,
        scanWrites = f.w.repo, scanLock = ScanLock(),
    )

    private fun dns(domain: String, reason: String? = null) =
        DnsEvent(timestamp = System.currentTimeMillis() - 60_000L, domain = domain, appUid = 1, appName = "com.a",
            isBlocked = false,
            reason = reason)

    @Test
    fun `DnsEventDao inserts return ids and matched VPN rows carry the live fact's key`() = runBlocking {
        val ids = repo().logDnsEventsBatch(listOf(dns("a.example"), dns("evil.example", reason = "IOC: X")))
        assertEquals(2, ids.size)
        val single = f.db.dnsEventDao().insert(dns("b.example"))
        assertTrue(single > ids.last())
        repo().logDnsEvent(dns("evil2.example", reason = "blocklist"))

        val rows = f.timelineDao.getAllForExport().filter { it.category == "ioc_match" }
        assertEquals(2, rows.size)
        val evil = rows.first { it.description.contains("evil.example") }
        assertArrayEquals(HashKeys.h128("dns:${ids[1]}"), evil.sourceEventKey)
        assertTrue(rows.all { it.sourceEventKey != null })
    }

    /** J1: a live scan stores each DNS row as a fact whose source key is the VPN row's key. */
    @Test
    fun `a live scan stores DNS facts keyed dns-id, joining the ioc_match row`() = runBlocking {
        repo().logDnsEventsBatch(listOf(dns("evil.example", reason = "IOC: X")))

        f.orchestrator.runFullScan()

        assertEquals("the ioc_match row joins its stored fact", 1L, f.count(
            "SELECT COUNT(*) FROM forensic_timeline r JOIN telemetry_record t ON t.sourceKey = r.sourceEventKey " +
                "WHERE r.category = 'ioc_match' AND t.service = 'dns_monitor'"))
    }

    /** Live events are observed once (§4.1): a DNS row fires once; a snapshot fact fires every scan. */
    @Test
    fun `a live DNS event already observed fires no second finding, a snapshot finding repeats`() = runBlocking {
        f.db.dnsEventDao().insert(dns("evil.example"))
        coEvery { f.appScanner.collectTelemetry() } returns listOf(OrchestratorFixture.app("com.evil"))

        val first = f.orchestrator.runFullScan()
        Thread.sleep(2)
        val second = f.orchestrator.runFullScan()

        assertEquals(setOf("androdr-lv-dns", "androdr-lv-app"), first.findings.map { it.ruleId }.toSet())
        assertEquals(listOf("androdr-lv-app"), second.findings.map { it.ruleId })
        assertTrue("dns_monitor is a live event service", "dns_monitor" in TaxonomyContract.eventServices)
    }

    /** C3: a re-read usage event is the same fact, observed once; no usage row is written. */
    @Test
    fun `re-read usage events are one fact each, observed once, with no rows`() = runBlocking {
        // Inside the 5-minute re-read, so the second scan reads both events again.
        val t = System.currentTimeMillis()
        val events = listOf(
            UsageEvent(t - 60_000L, "com.a", "A", "app_foreground", TelemetrySource.LIVE_SCAN, 9L),
            UsageEvent(t - 30_000L, "com.a", "A", "app_background", TelemetrySource.LIVE_SCAN, 9L),
        )
        coEvery { f.usageStatsScanner.collectEvents(any(), any()) } returns UsageCollection.Ok(events)

        val first = f.orchestrator.runFullScan()
        Thread.sleep(2)
        f.orchestrator.runFullScan()

        assertEquals(0L, f.count("SELECT COUNT(*) FROM forensic_timeline WHERE source = 'usage_stats'"))
        assertEquals(2L, f.count("SELECT COUNT(*) FROM telemetry_record WHERE service = 'usage_stats'"))
        assertEquals("observed by the first scan only", listOf(first.id, first.id),
            f.db.openHelper.readableDatabase.query("SELECT scanId FROM scan_record WHERE service = 'usage_stats'")
                .use { c -> generateSequence { if (c.moveToNext()) c.getLong(0) else null }.toList() })
    }

    /** A failed write aborts the session: nothing is kept, and the in-memory result says what failed. */
    @Test
    fun `a failed live write keeps nothing and reports the writer failure`() = runBlocking {
        coEvery { f.appScanner.collectTelemetry() } returns listOf(OrchestratorFixture.app("com.evil"))
        val store = spyk(f.w.f.store)
        f.w.store = store
        coEvery { store.persistChunk(any(), any(), any(), any(), any(), any(), any(), any(), any()) } throws
            IllegalStateException("write failed")

        val result = f.orchestrator.runFullScan()

        val failure = result.scannerErrors.single { it.scanner == ScanOrchestrator.SCAN_WRITER }
        assertEquals("IllegalStateException", failure.exception)
        assertTrue("the in-memory findings are still shown (never reads as clean)",
            result.findings.any { it.ruleId == "androdr-lv-app" && it.matchContext["package_name"] == "com.evil" })
        assertTrue(result.isPartialScan)
        assertEquals(0L, f.count("SELECT COUNT(*) FROM ScanResult"))
        assertEquals(0L, f.count("SELECT COUNT(*) FROM forensic_timeline"))
        assertTrue("the lock is released", !f.lock.mutex.isLocked && !f.lock.writerRunning.value)
    }

    /**
     * C1 (A7b fix round 1), kept through C2: the atoms are read inside `finish` after this scan's
     * rows were inserted, and the lookback admits only visible rows (this scan is still IN_PROGRESS),
     * so correlation never sees this scan's own rows twice. A recent install and admin grant (this
     * scan's detected changes)
     * and the two-step chain corr-001 give exactly one signal and one correlation finding.
     */
    @Test
    fun `live correlation counts this scan's own rows once`() = runBlocking {
        fun atom(name: String) = com.androdr.sigma.SigmaRuleParser.parse(
            com.androdr.data.store.rawFile("$name.yml").readText())!!
        val chain = com.androdr.sigma.SigmaRuleParser.parseCorrelation(
            com.androdr.data.store.rawFile("sigma_androdr_corr_001_install_then_admin.yml").readText())
        val engine = spyk(IntrusionLogZips.engine(atom("sigma_androdr_atom_package_install"),
            atom("sigma_androdr_atom_device_admin_grant")))
        io.mockk.every { engine.getCorrelationRules() } returns listOf(chain)
        val correlation = spyk(com.androdr.sigma.SigmaCorrelationEngine())
        OrchestratorFixture(engine = engine, correlationEngine = correlation).use { g ->
            val t = System.currentTimeMillis() - 60_000
            coEvery { g.installEventEmitter.emitNew(any(), any()) } answers {
                listOf(com.androdr.data.model.ForensicTimelineEvent(startTimestamp = t, source = "app_scanner",
                    category = "package_install", description = "Package installed: E", packageName = "com.evil",
                    scanResultId = firstArg()))
            }
            coEvery { g.deviceAdminGrantEmitter.emitNew(any()) } answers {
                listOf(com.androdr.data.model.ForensicTimelineEvent(startTimestamp = t + 1_000,
                    source = "device_admin_emitter", category = "device_admin_grant", description = "admin",
                    packageName = "com.evil", scanResultId = firstArg()))
            }
            val inputs = mutableListOf<List<com.androdr.sigma.TimelineAtom>>()
            io.mockk.every { correlation.evaluate(any(), any(), any(), any(), any()) } answers {
                inputs += secondArg<List<com.androdr.sigma.TimelineAtom>>()
                callOriginal()
            }

            val scan = g.orchestrator.runFullScan()

            val refs = inputs.single().map { it.ref }
            assertEquals("correlate's input refs are distinct: $refs", refs.size, refs.toSet().size)
            assertEquals("both detected changes are Row atoms", 2, refs.count { it is com.androdr.sigma.Row })
            assertEquals(1L, g.count("SELECT COUNT(*) FROM forensic_timeline WHERE kind = 'signal'"))
            assertEquals(1, scan.findings.count { it.category == com.androdr.sigma.FindingCategory.CORRELATION })
        }
    }

    /**
     * N1 (A7b fix round 2), kept through C3: a usage event re-read by this scan is the fact an earlier
     * scan observed (no second observation, no usage rows since C3), so it is correlated once, from
     * the lookback; a usage event older than the re-read window is correlated once too, and nothing
     * stamped after the scan start is (spec §5.2).
     */
    @Test
    fun `the lookback counts a re-read usage event once and leaves out rows after the scan start`() =
        runBlocking {
            val correlation = mockk<com.androdr.sigma.SigmaCorrelationEngine>(relaxed = true)
            OrchestratorFixture(correlationEngine = correlation).use { g ->
                io.mockk.every { g.engine.atomCategories() } returns
                    mapOf("a" to "app_foreground", "b" to "package_install")
                io.mockk.every { g.engine.getCorrelationRules() } returns listOf(
                    com.androdr.sigma.CorrelationRule(id = "corr-n1", title = "t",
                        type = com.androdr.sigma.CorrelationType.EVENT_COUNT, referencedRuleIds = listOf("a"),
                        timespanMs = 3_600_000L, groupBy = emptyList(), minEvents = 2, severity = "high",
                        displayLabel = "l"))
                val now = System.currentTimeMillis()
                val usageTime = now - 60_000
                val olderTime = now - 1_800_000
                fun usage(ts: Long) = UsageEvent(ts, "com.a", "A", "app_foreground", TelemetrySource.LIVE_SCAN, 1L)
                val atoms = mutableListOf<List<com.androdr.sigma.TimelineAtom>>()
                io.mockk.every { correlation.evaluate(any(), any(), any(), any(), any()) } answers {
                    atoms += secondArg<List<com.androdr.sigma.TimelineAtom>>()
                    com.androdr.sigma.CorrelationResult.NONE
                }
                // Scan 1 reads both events; scan 2 re-reads only the recent one (inside its window).
                coEvery { g.usageStatsScanner.collectEvents(any(), any()) } returns
                    UsageCollection.Ok(listOf(usage(olderTime), usage(usageTime)))
                g.orchestrator.runFullScan()
                atoms.clear()
                Thread.sleep(2)
                g.w.f.scan(8L, com.androdr.data.model.ScanState.COMPLETE)
                g.timelineDao.insertAll(listOf(
                    // Stamped after this scan starts (a producer outside the writer lock).
                    com.androdr.data.model.ForensicTimelineEvent(startTimestamp = now + 600_000,
                        source = "app_scanner", category = "package_install", description = "future",
                        packageName = "com.f", scanResultId = 8L),
                ))
                coEvery { g.usageStatsScanner.collectEvents(any(), any()) } returns
                    UsageCollection.Ok(listOf(usage(usageTime)))

                g.orchestrator.runFullScan()

                val second = atoms.single()
                assertEquals("the re-read usage event is correlated once", 1,
                    second.count { it.category == "app_foreground" && it.timestamp == usageTime })
                assertTrue("no row after the scan start", second.none { it.timestamp == now + 600_000 })
                assertEquals("a usage event before the re-read window is correlated once", 1,
                    second.count { it.category == "app_foreground" && it.timestamp == olderTime })
            }
        }
}

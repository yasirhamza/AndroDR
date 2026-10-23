package com.androdr.scanner

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.UsageEvent
import com.androdr.data.repo.ScanLock
import com.androdr.data.repo.ScanRepository
import com.androdr.data.store.HashKeys
import com.androdr.sigma.TaxonomyContract
import io.mockk.coEvery
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
 * id, `ioc_match` rows carrying the same key, today's usage rows (replaced every scan, each pinning
 * its fact), live events observed once, and a failed write that keeps nothing.
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
        DnsEvent(timestamp = 1_787_400_000_000L, domain = domain, appUid = 1, appName = "com.a", isBlocked = false,
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
        coEvery { f.dnsEventDao.getRecentSnapshot() } coAnswers { f.db.dnsEventDao().getRecentSnapshot() }

        f.orchestrator.runFullScan()

        assertEquals("the ioc_match row joins its stored fact", 1L, f.count(
            "SELECT COUNT(*) FROM forensic_timeline r JOIN telemetry_record t ON t.sourceKey = r.sourceEventKey " +
                "WHERE r.category = 'ioc_match' AND t.service = 'dns_monitor'"))
    }

    /** Live events are observed once (§4.1): a re-read DNS row fires once; a snapshot fact fires every scan. */
    @Test
    fun `a live DNS event already observed fires no second finding, a snapshot finding repeats`() = runBlocking {
        coEvery { f.dnsEventDao.getRecentSnapshot() } returns listOf(dns("evil.example").copy(id = 41))
        coEvery { f.appScanner.collectTelemetry() } returns listOf(OrchestratorFixture.app("com.evil"))

        val first = f.orchestrator.runFullScan()
        Thread.sleep(2)
        val second = f.orchestrator.runFullScan()

        assertEquals(setOf("androdr-lv-dns", "androdr-lv-app"), first.findings.map { it.ruleId }.toSet())
        assertEquals(listOf("androdr-lv-app"), second.findings.map { it.ruleId })
        assertTrue("dns_monitor is a live event service", "dns_monitor" in TaxonomyContract.eventServices)
    }

    @Test
    fun `usage rows are replaced every scan and pin their facts`() = runBlocking {
        val events = listOf(
            UsageEvent(1_000L, "com.a", "A", "app_foreground", TelemetrySource.LIVE_SCAN, 9L),
            UsageEvent(2_000L, "com.a", "A", "app_background", TelemetrySource.LIVE_SCAN, 9L),
        )
        coEvery { f.usageStatsScanner.collectEvents() } returns events

        f.orchestrator.runFullScan()
        Thread.sleep(2)
        val second = f.orchestrator.runFullScan()

        val usage = f.timelineDao.getAllForExport().filter { it.source == "usage_stats" }
        assertEquals("replaced, not stacked; re-read events keep their rows", 2, usage.size)
        assertEquals(listOf("App opened: A", "App closed: A"), usage.map { it.description })
        assertTrue(usage.all { it.scanResultId == second.id })
        assertTrue("each row pins its fact", usage.all { r ->
            r.recordId != null && f.count("SELECT COUNT(*) FROM telemetry_record WHERE id = ${r.recordId}") == 1L
        })
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

    @Test
    fun `watermark inputs are the highest DNS id and the latest usage time collected`() {
        val t = LiveTelemetry(emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), emptyList(),
            usage = listOf(UsageEvent(7L, "p", "p", "app_foreground", TelemetrySource.LIVE_SCAN, 1L),
                UsageEvent(5L, "p", "p", "app_foreground", TelemetrySource.LIVE_SCAN, 1L)),
            dns = listOf(dns("a").copy(id = 4), dns("b").copy(id = 9)))
        assertEquals(9L, t.dnsMaxId)
        assertEquals(7L, t.usageMaxTime)
        assertEquals(null, LiveTelemetry(emptyList(), emptyList(), emptyList(), emptyList(), emptyList(),
            emptyList(), emptyList(), emptyList(), emptyList()).dnsMaxId)
    }

    /**
     * C1 (fix round 1): the lookback is read before the session writes, so correlation never sees
     * this scan's own rows twice. A recent install and admin grant (this scan's detected changes)
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
            val inputs = mutableListOf<List<com.androdr.data.model.ForensicTimelineEvent>>()
            io.mockk.every { correlation.evaluate(any(), any(), any(), any()) } answers {
                inputs += secondArg<List<com.androdr.data.model.ForensicTimelineEvent>>()
                callOriginal()
            }

            val scan = g.orchestrator.runFullScan()

            val ids = inputs.single().map { it.id }
            assertEquals("correlate's input ids are distinct: $ids", ids.size, ids.toSet().size)
            assertEquals(1L, g.count("SELECT COUNT(*) FROM forensic_timeline WHERE kind = 'signal'"))
            assertEquals(1, scan.findings.count { it.category == com.androdr.sigma.FindingCategory.CORRELATION })
        }
    }
}

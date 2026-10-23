package com.androdr.scanner

import com.androdr.data.db.getAllForExport
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.Indicator
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.UsageEvent
import com.androdr.sigma.StoreRecord
import io.mockk.coEvery
import io.mockk.every
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * W1 (spec §5.2 Watermarks, Late-IOC re-check): a live scan collects each event once — live DNS by
 * row id, usage stats by event time with a 5-minute re-read — and advances each watermark on every
 * committed scan whose collection did not fail. Stored live DNS facts of the trailing 24 h are
 * re-checked against IOCs that arrived after them, firing once per fact.
 */
@RunWith(RobolectricTestRunner::class)
class EventWatermarkTest {
    private val engine = IntrusionLogZips.engine(
        IntrusionLogZips.rule(IOC_RULE, "dns_monitor", "domain|ioc_lookup", "domain_ioc_db", "high"),
    )
    private val f = OrchestratorFixture(engine = engine)

    /** Domains the IOC lookup knows right now; tests add to it between scans. */
    private val iocDomains = HashSet<String>()

    init {
        every { f.indicatorResolver.isKnownBadDomainWithBundle(any()) } answers {
            val d = firstArg<String>()
            if (d in iocDomains) Indicator(type = "domain", value = d, source = "test", fetchedAt = 1L) else null
        }
    }

    @After fun tearDown() = f.close()

    // ── Watermark advance rules (pure) ──────────────────────────────────────────

    private fun usage(ts: Long) = UsageEvent(ts, "com.a", "A", "app_foreground", TelemetrySource.LIVE_SCAN, 7L)

    @Test
    fun `NoAccess, Failed and the save fallback each leave the usage watermark unchanged`() {
        val ok = UsageCollection.Ok(listOf(usage(500L)))
        assertNull(Watermarks.nextTime(400L, UsageCollection.NoAccess, SCAN_START, NOW, saveFallback = false))
        assertNull(Watermarks.nextTime(400L, UsageCollection.Failed(IllegalStateException()), SCAN_START, NOW, false))
        assertNull(Watermarks.nextTime(400L, ok, SCAN_START, NOW, saveFallback = true))
        assertEquals(500L, Watermarks.nextTime(400L, ok, SCAN_START, NOW, saveFallback = false))
    }

    @Test
    fun `Ok with no events advances the first watermark to the scan start`() {
        assertEquals(SCAN_START, Watermarks.nextTime(null, UsageCollection.Ok(emptyList()), SCAN_START, NOW, false))
    }

    @Test
    fun `a future-dated event caps the watermark at the scan start`() {
        val future = UsageCollection.Ok(listOf(usage(SCAN_START + 3_600_000L)))
        assertEquals(SCAN_START, Watermarks.nextTime(null, future, SCAN_START, NOW, false))
    }

    @Test
    fun `a previous watermark ahead of now is reset, one behind is kept`() {
        val older = UsageCollection.Ok(listOf(usage(SCAN_START - 600_000L)))
        assertEquals(SCAN_START - 600_000L, Watermarks.nextTime(NOW + 3_600_000L, older, SCAN_START, NOW, false))
        assertEquals(SCAN_START - 60_000L, Watermarks.nextTime(SCAN_START - 60_000L, older, SCAN_START, NOW, false))
    }

    @Test
    fun `the DNS watermark advances to the collected id unless the collection failed or fell back`() {
        assertEquals(9L, Watermarks.nextDnsId(4L, 9L, failed = false, saveFallback = false))
        assertEquals(4L, Watermarks.nextDnsId(4L, null, failed = false, saveFallback = false))
        assertNull(Watermarks.nextDnsId(4L, 9L, failed = true, saveFallback = false))
        assertNull(Watermarks.nextDnsId(4L, 9L, failed = false, saveFallback = true))
        assertNull(Watermarks.nextDnsId(null, null, failed = false, saveFallback = false))
    }

    @Test
    fun `usage is re-read from five minutes before the watermark, or the last 24 h without a usable one`() {
        // NOW is a whole minute; the start is floored to the minute (whole dedup buckets).
        assertEquals(NOW - 6 * 60_000L, Watermarks.usageSince(NOW - 1_000L, NOW))
        assertEquals(NOW - Watermarks.USAGE_REREAD_MS, Watermarks.usageSince(NOW, NOW))
        assertEquals(NOW - Watermarks.LIVE_LOOKBACK_MS, Watermarks.usageSince(null, NOW))
        assertEquals(NOW - Watermarks.LIVE_LOOKBACK_MS, Watermarks.usageSince(NOW + 1L, NOW))
    }

    // ── Collection over consecutive scans ───────────────────────────────────────

    /** The device's usage log; the mock serves the events inside the requested window. */
    private val usageLog = mutableListOf<UsageEvent>()
    private val usageCalls = mutableListOf<Pair<Long, Long>>()

    private fun serveUsageLog() {
        coEvery { f.usageStatsScanner.collectEvents(any(), any()) } answers {
            val since = firstArg<Long>()
            val until = secondArg<Long>()
            usageCalls += since to until
            UsageCollection.Ok(usageLog.filter { it.timestamp in since..until })
        }
    }

    private fun watermark(service: String) = runBlocking { f.db.eventWatermarkDao().get(service)!! }

    private suspend fun scan() = f.orchestrator.runFullScan().also { Thread.sleep(2) }

    @Test
    fun `usage over consecutive scans observes each event once and misses none`() = runBlocking {
        serveUsageLog()
        val start = System.currentTimeMillis()
        usageLog += usage(start - 7_200_000L)
        usageLog += usage(start - 60_000L)
        scan()
        val first = watermark(USAGE).position
        assertEquals("the watermark is the latest event collected", start - 60_000L, first)

        // Recorded after scan 1 but stamped before its watermark (inside the re-read), plus a new one.
        usageLog += usage(first - 120_000L)
        usageLog += usage(System.currentTimeMillis() - 1L)
        Thread.sleep(2)
        scan()
        assertEquals("scan 2 re-reads from five minutes before the watermark (floored to the minute)",
            Math.floorDiv(first - Watermarks.USAGE_REREAD_MS, 60_000L) * 60_000L, usageCalls[1].first)
        scan()

        assertEquals("every event is observed", 4L,
            f.count("SELECT COUNT(*) FROM scan_record WHERE service = '$USAGE'"))
        assertEquals("each event exactly once", 4L,
            f.count("SELECT COUNT(DISTINCT recordId) FROM scan_record WHERE service = '$USAGE'"))
    }

    @Test
    fun `usage access revoked keeps the watermark, access with no events advances it to the scan start`() =
        runBlocking {
            coEvery { f.usageStatsScanner.collectEvents(any(), any()) } returns UsageCollection.Ok(emptyList())
            val before = System.currentTimeMillis()
            val first = scan()
            val wm = watermark(USAGE)
            assertTrue("advanced to the scan start", wm.position in before..first.timestamp)
            assertEquals(first.id, wm.scanId)

            coEvery { f.usageStatsScanner.collectEvents(any(), any()) } returns UsageCollection.NoAccess
            val second = scan()
            assertEquals("no access: unchanged", wm, watermark(USAGE))
            assertTrue("no access is not a scanner failure", second.scannerErrors.none { it.scanner == USAGE_SCANNER })

            coEvery { f.usageStatsScanner.collectEvents(any(), any()) } returns
                UsageCollection.Failed(IllegalStateException("query failed"))
            val third = scan()
            assertEquals("failed: unchanged", wm, watermark(USAGE))
            assertEquals("query failed", third.scannerErrors.single { it.scanner == USAGE_SCANNER }.message)
        }

    /**
     * C3: usage events are store-only facts, so a live scan writes no usage row and deletes none —
     * a legacy usage row (a pre-store scan's only record) survives, inside or outside the re-read
     * window, and also when it is stamped after the window end (a clock that moved back; C1 I2).
     */
    @Test
    fun `a live scan writes no usage row and deletes none, inside or outside its window`() = runBlocking {
        serveUsageLog()
        val start = System.currentTimeMillis()
        usageLog += usage(start - 7_200_000L)
        usageLog += usage(start - 60_000L)
        f.w.f.scan(5L, com.androdr.data.model.ScanState.COMPLETE)
        val legacy = listOf(start - 60_000L, start - 7_200_000L, start + 3_600_000L).map {
            com.androdr.data.model.ForensicTimelineEvent(startTimestamp = it, source = USAGE,
                category = "app_foreground", description = "App opened: A", packageName = "com.a",
                scanResultId = 5L)
        }
        f.timelineDao.insertAll(legacy)

        scan()
        scan()

        val rows = f.timelineDao.getAllForExport().filter { it.source == USAGE }
        assertEquals("only the legacy rows, untouched", legacy.map { it.startTimestamp }.sorted(),
            rows.map { it.startTimestamp }.sorted())
        assertTrue(rows.all { it.scanResultId == 5L })
        assertEquals("both events stored once", 2L,
            f.count("SELECT COUNT(DISTINCT recordId) FROM scan_record WHERE service = '$USAGE'"))
    }

    /**
     * Review m4: a usage collection that is full ([UsageStatsScanner.MAX_EVENTS_PER_SCAN]) without
     * reading past the previous watermark cannot advance it; the scan says so instead of silently
     * re-reading the same window forever. A full collection that does advance records nothing.
     */
    @Test
    fun `a full usage collection inside the re-read window is recorded, one that advances is not`() =
        runBlocking {
            val start = System.currentTimeMillis()
            val previous = start - 60_000L
            f.db.eventWatermarkDao().put(com.androdr.data.model.EventWatermark(USAGE, previous, 1L))
            val inside = List(UsageStatsScanner.MAX_EVENTS_PER_SCAN) { usage(previous - 1 - it % 60_000) }
            coEvery { f.usageStatsScanner.collectEvents(any(), any()) } returns UsageCollection.Ok(inside)

            val stalled = scan()

            assertEquals(LiveScanCollector.USAGE_WINDOW_STALLED,
                stalled.scannerErrors.single { it.scanner == USAGE_SCANNER }.exception)

            val advancing = inside.dropLast(1) + usage(previous + 1)
            coEvery { f.usageStatsScanner.collectEvents(any(), any()) } returns UsageCollection.Ok(advancing)
            assertTrue(scan().scannerErrors.none { it.scanner == USAGE_SCANNER })
        }

    // ── Live DNS by id ──────────────────────────────────────────────────────────

    private fun dns(domain: String, ts: Long = System.currentTimeMillis() - 60_000L) =
        DnsEvent(timestamp = ts, domain = domain, appUid = 1, appName = "com.a", isBlocked = false, reason = null)

    private suspend fun insertDns(vararg events: DnsEvent): List<Long> = f.db.dnsEventDao().insertAll(events.toList())

    @Test
    fun `DNS is collected by id, so a late-flushed row with an older timestamp is collected`() = runBlocking {
        val now = System.currentTimeMillis()
        insertDns(dns("stale.example", now - 25 * 3_600_000L))
        insertDns(dns("a.example", now - 60_000L))
        scan()
        assertEquals("the first scan starts at the last 24 h", 1L,
            f.count("SELECT COUNT(*) FROM scan_record WHERE service = '$DNS'"))

        val late = insertDns(dns("late-flush.example", now - 600_000L)).single()
        val second = scan()

        assertEquals(1L, f.count("SELECT COUNT(*) FROM scan_record WHERE service = '$DNS' AND scanId = ${second.id}"))
        assertEquals(late, watermark(DNS).position)
        assertEquals(second.id, watermark(DNS).scanId)
    }

    @Test
    fun `a capability-skipped dns rule still advances the watermark on each of 10 scans`() = runBlocking {
        val skipEngine = IntrusionLogZips.engine(
            IntrusionLogZips.rule("androdr-wm-skip", "dns_monitor", "domain|ioc_lookup", "unregistered_db"),
        )
        OrchestratorFixture(engine = skipEngine).use { g ->
            var distinct = 0L
            repeat(10) { i ->
                val ids = g.db.dnsEventDao().insertAll(List(1 + i % 2) { k -> dns("d$i-$k.example") })
                distinct += ids.size
                val scan = g.orchestrator.runFullScan()
                Thread.sleep(2)
                assertTrue("rule $i skipped", scan.scannerErrors.any { it.ruleId == "androdr-wm-skip" })
                val wm = runBlocking { g.db.eventWatermarkDao().get(DNS)!! }
                assertEquals("scan $i advanced the watermark", ids.last(), wm.position)
                assertEquals(scan.id, wm.scanId)
            }
            assertEquals(distinct, g.count("SELECT COUNT(*) FROM scan_record WHERE service = '$DNS'"))
            assertEquals(distinct, g.count("SELECT COUNT(DISTINCT recordId) FROM scan_record WHERE service = '$DNS'"))
        }
    }

    @Test
    fun `a DNS read failing mid-scan keeps the DNS watermark and is recorded`() = runBlocking {
        insertDns(dns("a.example"))
        scan()
        val before = watermark(DNS)
        insertDns(dns("b.example"))
        coEvery { f.dnsEventDao.eventsAfterId(any(), any(), any()) } throws IllegalStateException("cursor died")

        val second = scan()

        assertEquals(before, watermark(DNS))
        assertTrue(second.scannerErrors.any { it.scanner == "dnsSnapshot" && it.message!!.contains("cursor died") })
    }

    @Test
    fun `the disk-full fallback advances no watermark`() = runBlocking {
        val store = io.mockk.spyk(f.w.f.store)
        f.w.store = store
        coEvery { store.persistChunk(any(), any(), any(), any(), any(), any(), any(), any(), any()) } throws
            android.database.sqlite.SQLiteFullException("disk full")
        coEvery { f.usageStatsScanner.collectEvents(any(), any()) } returns UsageCollection.Ok(emptyList())
        insertDns(dns("a.example"))

        val scan = scan()

        assertEquals("the scan finished evaluate-only", com.androdr.data.model.TelemetryState.FAILED,
            scan.telemetryState)
        assertNull(f.db.eventWatermarkDao().get(DNS))
        assertNull(f.db.eventWatermarkDao().get(USAGE))
    }

    /** Review m3: a DNS watermark past the newest row is treated as absent (the last 24 h is read). */
    @Test
    fun `a DNS watermark past the newest row falls back to the last 24 h without duplicates`() = runBlocking {
        insertDns(dns("a.example"))
        scan()
        val newest = checkNotNull(f.db.dnsEventDao().maxId())
        f.db.eventWatermarkDao().put(com.androdr.data.model.EventWatermark(DNS, newest + 100, 1L))
        val late = insertDns(dns("b.example")).single()

        scan()

        assertEquals(2L, f.count("SELECT COUNT(*) FROM scan_record WHERE service = '$DNS'"))
        assertEquals(2L, f.count("SELECT COUNT(DISTINCT recordId) FROM scan_record WHERE service = '$DNS'"))
        assertEquals(late, watermark(DNS).position)
    }

    /** Review m2: the watermarks are written inside the finishing transaction, so a failed finish advances none. */
    @Test
    fun `a finish that rolls back advances no watermark`() = runBlocking {
        val hooks = object : com.androdr.data.repo.SessionHooks {
            override fun watermarks(saveFallback: Boolean) = mapOf(DNS to 5L)
            override fun summarize(scan: com.androdr.data.model.ScanResult,
                totals: com.androdr.data.repo.FindingTotals): com.androdr.data.model.ScanResult =
                error("summary failed after the watermark write")
        }
        val session = f.writer.begin(f.w.scan(1L), liveEvents = true, hooks = hooks)

        val failure = runCatching { session.finish() }.exceptionOrNull()

        assertEquals("summary failed after the watermark write", failure?.message)
        assertNull(f.db.eventWatermarkDao().get(DNS))
    }

    // ── Late-IOC re-check ───────────────────────────────────────────────────────

    @Test
    fun `a domain that becomes an IOC after scan 1 fires once, on scan 2, from the stored fact`() = runBlocking {
        insertDns(dns(LATE))
        val first = scan()
        assertTrue(first.findings.none { it.ruleId == IOC_RULE })
        val factId = f.count("SELECT recordId FROM scan_record WHERE scanId = ${first.id} AND service = '$DNS'")
        val observations = f.count("SELECT COUNT(*) FROM scan_record")

        iocDomains += LATE
        val second = scan()
        val hit = second.findings.single { it.ruleId == IOC_RULE }
        assertEquals("the re-check finding is the scan-1 fact", factId, hit.recordId)
        assertEquals(-1, hit.ordinal)
        assertEquals("no observation is written", observations, f.count("SELECT COUNT(*) FROM scan_record"))
        assertEquals(factId, f.timelineDao.getAllForExport().single { it.ruleId == IOC_RULE }.recordId)

        val third = scan()
        assertTrue("fires once inside the 24 h window", third.findings.none { it.ruleId == IOC_RULE })
    }

    /**
     * C1 fix round 1 (I1): the re-check covers the trailing 24 h only. A stored live fact whose
     * event time is past the window is never re-checked; one just inside it is.
     */
    @Test
    fun `the re-check covers stored DNS facts of the trailing 24 h only`() = runBlocking {
        insertDns(dns(LATE), dns(OLD))
        val first = scan()
        val now = System.currentTimeMillis()
        // OLD's fact now reads as 25 h old; LATE's as 23 h old (inside the window).
        fun setEventTime(domain: String, time: Long) = f.db.openHelper.writableDatabase.execSQL(
            "UPDATE telemetry_record SET eventTime = $time WHERE service = '$DNS' AND id IN (SELECT recordId " +
                "FROM scan_record WHERE scanId = ${first.id} AND ordinal = ${if (domain == LATE) 0 else 1})")
        setEventTime(OLD, now - 25 * 3_600_000L)
        setEventTime(LATE, now - 23 * 3_600_000L)
        iocDomains += setOf(LATE, OLD)

        val second = scan()

        val hits = second.findings.filter { it.ruleId == IOC_RULE }
        assertEquals("only the in-window fact fires", listOf(LATE), hits.map { it.matchContext["domain"] })
    }

    @Test
    fun `the re-check never evaluates the current scan's own facts`() = runBlocking {
        iocDomains += LATE
        insertDns(dns(LATE))
        val scan = scan()
        val hit = scan.findings.single { it.ruleId == IOC_RULE }
        assertEquals("fired by append, not by the re-check", 0, hit.ordinal)
    }

    @Test
    fun `the re-check ignores imported DNS facts with recent event times`() = runBlocking {
        val import = f.writer.begin(f.w.scan(1L, TelemetrySource.INTRUSION_LOG_IMPORT), liveEvents = false)
        import.append(DNS, TelemetrySource.INTRUSION_LOG_IMPORT, 5L, listOf(StoreRecord(mapOf(
            "timestamp" to System.currentTimeMillis() - 60_000L, "domain" to LATE, "source_package" to "com.a",
        ))))
        import.finish()
        assertEquals(1L, f.count("SELECT COUNT(*) FROM scan_record WHERE service = '$DNS'"))

        iocDomains += LATE
        val scan = scan()
        assertTrue(scan.findings.none { it.ruleId == IOC_RULE })
    }

    // ── Serialisation ───────────────────────────────────────────────────────────

    /**
     * The import is started while the live scan is held inside its session; it may only reach the
     * analyzer after the scan returned. A broken lock lets it in during the 2 s window, out of order.
     */
    @Test
    fun `a live scan and an import are serialised`() = runBlocking {
        val gate = CompletableDeferred<Unit>()
        val order = java.util.Collections.synchronizedList(mutableListOf<String>())
        coEvery { f.usageStatsScanner.collectEvents(any(), any()) } coAnswers {
            gate.await()
            UsageCollection.Ok(emptyList())
        }
        coEvery { f.intrusionLogAnalyzer.analyze(any(), any()) } coAnswers {
            order += "import"
            error("stop the import here")
        }
        val scan = async(Dispatchers.Default) { f.orchestrator.runFullScan().also { order += "scan" } }
        withTimeout(5_000) { while (!f.lock.writerRunning.value) delay(5) }
        val import = async(Dispatchers.Default) {
            runCatching { f.orchestrator.analyzeIntrusionLog(android.net.Uri.EMPTY) }
        }
        withTimeoutOrNull(2_000) { while (order.isEmpty()) delay(10) }

        gate.complete(Unit)
        scan.await()
        import.await()
        assertEquals("the import reaches the analyzer only after the scan", listOf("scan", "import"), order.toList())
    }

    private companion object {
        const val IOC_RULE = "androdr-wm-ioc"
        const val LATE = "late.example"
        const val OLD = "old.example"
        const val DNS = "dns_monitor"
        const val USAGE = "usage_stats"
        const val USAGE_SCANNER = "usageStatsScanner"
        const val NOW = 1_800_000_000_000L
        const val SCAN_START = NOW - 1_000L
    }
}

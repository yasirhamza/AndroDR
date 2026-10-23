package com.androdr.scanner

import com.androdr.data.db.Converters
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TelemetryState
import com.androdr.data.model.ScanResult
import com.androdr.data.repo.FindingTotals
import com.androdr.data.repo.ScanNotInProgressException
import com.androdr.data.repo.SessionHooks
import com.androdr.data.store.StoreFixture.Companion.CAPTURED
import com.androdr.data.store.StoreFixture.Companion.app
import com.androdr.data.store.StoreFixture.Companion.dns
import com.androdr.scanner.WriterFixture.Companion.APP_RULE
import com.androdr.scanner.WriterFixture.Companion.DNS_RULE
import com.androdr.scanner.WriterFixture.Companion.EVIL_APP
import com.androdr.scanner.WriterFixture.Companion.EVIL_DOMAIN
import com.androdr.scanner.WriterFixture.Companion.IMPORT_CAPTURED
import com.androdr.scanner.WriterFixture.Companion.SEC_RULE
import com.androdr.scanner.WriterFixture.Companion.securityLine
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import com.androdr.sigma.StoreRecord
import io.mockk.coEvery
import io.mockk.every
import io.mockk.spyk
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.random.Random

/** The session writer (spec §5.2): E1 writer half, ST1, S3, S2 duplicates, interim top-K, F2 recordId. */
@RunWith(RobolectricTestRunner::class)
class ChunkedScanWriterTest {
    private val w = WriterFixture()

    @After fun tearDown() = w.close()

    private val live = TelemetrySource.LIVE_SCAN
    private val il = TelemetrySource.INTRUSION_LOG_IMPORT

    private fun state(id: Long): String? = w.f.db.openHelper.readableDatabase
        .query("SELECT state FROM ScanResult WHERE id = $id").use { c -> if (c.moveToFirst()) c.getString(0) else null }

    private fun factIdAt(scanId: Long, service: String, ordinal: Int): Long = w.count(
        "SELECT recordId FROM scan_record WHERE scanId = $scanId AND service = '$service' AND ordinal = $ordinal"
    )

    // ── Basic finish, F2 (Phase A half) ─────────────────────────────────────────

    @Test
    fun `finish completes the scan and its finding rows carry level and a resolvable recordId`() = runBlocking {
        val s = w.writer.begin(w.scan(1L), liveEvents = false)
        s.append("dns_monitor", live, CAPTURED, listOf(dns("a.example"), dns("b.example")))
        // Second chunk: firstOrdinal 2, so chunk-relative indexing is exercised.
        s.append("dns_monitor", live, CAPTURED, listOf(dns("c.example"), dns(EVIL_DOMAIN)))
        assertEquals("hidden while open", 0L, w.visibleFacts())
        val r = s.finish()

        assertEquals(TelemetryState.STORED, r.telemetryState)
        assertEquals(4, r.newFacts)
        assertEquals("COMPLETE", state(1L))
        val finding = r.scan.findings.single()
        assertEquals(DNS_RULE, finding.ruleId)
        assertEquals(3, finding.ordinal)
        assertNull("recordId is set only by evaluateStored", finding.recordId)
        assertEquals(listOf(finding), w.f.db.scanResultDao().getLatestTwo().single().findings)

        val row = w.f.db.forensicTimelineEventDao().getAllForExport().single()
        assertEquals("high", row.level)
        assertEquals(factIdAt(1L, "dns_monitor", 3), row.recordId)
        assertEquals(1L, row.scanResultId)
        assertEquals(1L, w.count("SELECT COUNT(*) FROM telemetry_record WHERE id = ${row.recordId}"))
        assertEquals(4L, w.visibleFacts())
    }

    // ── E1 (writer half) ────────────────────────────────────────────────────────

    @Test
    fun `E1 - each chunk is evaluated and persisted as the same list`() = runBlocking {
        val engine = spyk(w.engine)
        val store = spyk(w.f.store)
        val writer = ChunkedScanWriter(engine, store, w.repo, w.preflight, w.health)
        val evaluated = mutableListOf<List<StoreRecord>>()
        val persisted = mutableListOf<List<StoreRecord>>()
        every { engine.evaluateRecords(any(), capture(evaluated), any()) } answers { callOriginal() }
        coEvery {
            store.persistChunk(any(), any(), any(), any(), capture(persisted), any(), any(), any(), any())
        } coAnswers { callOriginal() }
        val s = writer.begin(w.scan(1L), liveEvents = false)
        s.appendAll("app_scanner", live, CAPTURED, (0 until 12_000).asSequence().map { app("com.app$it") })
        s.finish()
        assertEquals(listOf(5_000, 5_000, 2_000), persisted.map { it.size })
        assertEquals(persisted.size, evaluated.size)
        persisted.indices.forEach { assertSame(evaluated[it], persisted[it]) }
    }

    // ── ST1 ─────────────────────────────────────────────────────────────────────

    @Test
    fun `ST1 - chunk k commits before record (k+1)x5000+1 is pulled`() = runBlocking {
        val s = w.writer.begin(w.scan(1L), liveEvents = false)
        val checked = mutableListOf<Int>()
        val records = sequence {
            for (i in 0 until 15_001) {
                if (i > 0 && i % ChunkedScanWriter.CHUNK_SIZE == 0) {
                    // Record number i+1 = (k+1)·5000+1 is about to be pulled: chunks 0..k are committed.
                    assertEquals(i.toLong(), w.count("SELECT COUNT(*) FROM scan_record WHERE scanId = 1"))
                    checked += i
                }
                yield(app("com.app$i"))
            }
        }
        s.appendAll("app_scanner", live, CAPTURED, records)
        assertEquals(listOf(5_000, 10_000, 15_000), checked)
        assertEquals(15_001L, w.count("SELECT COUNT(*) FROM scan_record WHERE scanId = 1"))
    }

    // ── S3 / Review Focus 5 ─────────────────────────────────────────────────────

    @Test
    fun `S3 - a throw on chunk 3 leaves nothing visible, and abort removes it`() = runBlocking {
        val store = spyk(w.f.store)
        coEvery {
            store.persistChunk(any(), any(), any(), any(), any(), any(), any(), any(), any())
        } coAnswers {
            // Chunk 3 is the one whose record carries time 1002.
            if (arg<List<StoreRecord>>(4).single().fields["timestamp"] == 1_002L) error("boom on chunk 3")
            callOriginal()
        }
        val writer = ChunkedScanWriter(w.engine, store, w.repo, w.preflight, w.health)
        val s = writer.begin(w.scan(1L, il), liveEvents = false)
        val failure = runCatching {
            for (k in 0 until 4) s.append("security_log", il, IMPORT_CAPTURED, listOf(securityLine(1_000L + k)))
        }
        assertTrue(failure.isFailure)
        // A killed writer (no abort yet): its two committed chunks are invisible.
        assertEquals(2L, w.count("SELECT COUNT(*) FROM telemetry_record"))
        assertEquals(0L, w.visibleFacts())
        assertEquals(0L, w.visibleRows())
        assertEquals(0L, w.count("SELECT COUNT(*) FROM ScanResult WHERE state = 'COMPLETE'"))
        assertEquals("IN_PROGRESS", state(1L))

        s.abort()
        assertEquals(null, state(1L))
        assertEquals(0L, w.count("SELECT COUNT(*) FROM telemetry_record"))
        assertEquals(0L, w.count("SELECT COUNT(*) FROM scan_record"))
        assertEquals(0L, w.count("SELECT COUNT(*) FROM forensic_timeline"))
    }

    @Test
    fun `S3 - a throw inside finish after the Timeline writes and the guarded complete rolls it all back`() =
        runBlocking {
        // summarize runs after the finding rows are inserted and the scan is set COMPLETE.
        val hooks = object : SessionHooks {
            override fun summarize(scan: ScanResult, totals: FindingTotals): ScanResult = error("boom")
        }
        val s = w.writer.begin(w.scan(1L), liveEvents = false, hooks)
        s.append("dns_monitor", live, CAPTURED, listOf(dns(EVIL_DOMAIN)))
        assertTrue(runCatching { s.finish() }.isFailure)
        assertEquals("IN_PROGRESS", state(1L))
        assertEquals("finding rows rolled back", 0L, w.count("SELECT COUNT(*) FROM forensic_timeline"))
        assertEquals(0L, w.visibleFacts())
        s.abort()
        assertEquals(null, state(1L))
    }

    @Test
    fun `guarded finish - a scan marked DELETING before finish never becomes COMPLETE`() = runBlocking {
        val s = w.writer.begin(w.scan(1L), liveEvents = false)
        s.append("dns_monitor", live, CAPTURED, listOf(dns(EVIL_DOMAIN)))
        w.f.setState(1L, ScanState.DELETING)
        val failure = runCatching { s.finish() }.exceptionOrNull()
        assertTrue("$failure", failure is ScanNotInProgressException)
        assertEquals("DELETING", state(1L))
        assertEquals(0L, w.count("SELECT COUNT(*) FROM forensic_timeline"))
        assertEquals(0L, w.visibleFacts())
    }

    @Test
    fun `abort writes no audit row`() = runBlocking {
        val s = w.writer.begin(w.scan(1L, il), liveEvents = false)
        s.append("security_log", il, IMPORT_CAPTURED, listOf(securityLine()))
        s.abort()
        assertEquals(0L, w.count("SELECT COUNT(*) FROM forensic_timeline"))
        assertEquals(0L,
            w.count("SELECT COUNT(*) FROM forensic_timeline WHERE persistent = 1 OR category = 'scan_deleted'"))
    }

    // ── S2 duplicates ───────────────────────────────────────────────────────────

    @Test
    fun `S2 - the same id-less line twice yields one observation and one finding`() = runBlocking {
        val s = w.writer.begin(w.scan(1L, il), liveEvents = false)
        s.append("security_log", il, IMPORT_CAPTURED, listOf(securityLine(), securityLine()))
        val r = s.finish()
        assertEquals(1L, w.count("SELECT COUNT(*) FROM scan_record WHERE scanId = 1"))
        assertEquals(1, r.duplicatesDropped)
        assertEquals(listOf(SEC_RULE), r.scan.findings.map { it.ruleId })
        assertEquals(1L, w.count("SELECT COUNT(*) FROM forensic_timeline WHERE ruleId = '$SEC_RULE'"))
    }

    @Test
    fun `a live event fact already observed by a COMPLETE live scan yields no second finding`() = runBlocking {
        val evil = dns(EVIL_DOMAIN, key = "dns:42")
        val first = w.writer.begin(w.scan(1L), liveEvents = true)
        first.append("dns_monitor", live, CAPTURED, listOf(evil))
        assertEquals(1, first.finish().scan.findings.size)
        val second = w.writer.begin(w.scan(2L), liveEvents = true)
        second.append("dns_monitor", live, CAPTURED, listOf(evil))
        assertEquals(emptyList<Finding>(), second.finish().scan.findings)
    }

    // ── Late-IOC re-check ───────────────────────────────────────────────────────

    @Test
    fun `evaluateStored sets recordId and ordinal -1, writes no observation, and never re-fires`() = runBlocking {
        val first = w.writer.begin(w.scan(1L), liveEvents = true)
        first.append("dns_monitor", live, CAPTURED, listOf(dns(EVIL_DOMAIN, key = "dns:7")))
        val stored = first.finish()
        // Simulate "the domain became an IOC after it was queried": drop the first scan's finding row.
        w.f.db.openHelper.writableDatabase.execSQL("DELETE FROM forensic_timeline")
        val factId = factIdAt(1L, "dns_monitor", 0)
        val observations = w.count("SELECT COUNT(*) FROM scan_record")
        assertEquals(1, stored.scan.findings.size)

        val recheck = w.writer.begin(w.scan(2L), liveEvents = true)
        recheck.evaluateStored("dns_monitor", sequenceOf(factId to dns(EVIL_DOMAIN, key = "dns:7")))
        val r = recheck.finish()
        val f = r.scan.findings.single()
        assertEquals(factId, f.recordId)
        assertEquals(-1, f.ordinal)
        assertEquals(observations, w.count("SELECT COUNT(*) FROM scan_record"))
        assertEquals(factId, w.f.db.forensicTimelineEventDao().getAllForExport().single().recordId)

        val again = w.writer.begin(w.scan(3L), liveEvents = true)
        again.evaluateStored("dns_monitor", sequenceOf(factId to dns(EVIL_DOMAIN, key = "dns:7")))
        assertEquals(emptyList<Finding>(), again.finish().scan.findings)
    }

    // ── Interim findings top-K ──────────────────────────────────────────────────

    private fun fixture(n: Int, seed: Int): List<Finding> {
        val rnd = Random(seed)
        val levels = listOf("critical", "high", "medium", "low", "informational", "")
        return List(n) { i ->
            Finding(ruleId = "r$i", title = "t$i", level = levels[rnd.nextInt(levels.size)],
                category = FindingCategory.APP_RISK, triggered = rnd.nextInt(10) != 0,
                // Few distinct times, so severity/time ties exercise the stable order.
                matchContext = if (rnd.nextBoolean()) mapOf("timestamp" to "${rnd.nextInt(5)}") else emptyMap())
        }
    }

    @Test
    fun `the findings top-K equals capTriggeredFindings on a 1500-finding fixture`() {
        for ((n, seed) in listOf(1_500 to 1, 1_500 to 2, 800 to 3, 1_112 to 4)) {
            val all = fixture(n, seed)
            val top = FindingsTopK.forSource(il)
            all.forEach { top.offer(it, null) }
            assertEquals("n=$n seed=$seed", ScanOrchestrator.capTriggeredFindings(all), top.result().map { it.finding })
            assertEquals(n.toLong(), top.totals().seen)
            assertEquals(all.count { it.triggered }.toLong(), top.totals().triggered)
        }
    }

    @Test
    fun `live and bug-report sessions keep every finding in arrival order, as today`() {
        for (source in listOf(live, TelemetrySource.BUGREPORT_IMPORT)) {
            val all = fixture(1_500, 9)
            val top = FindingsTopK.forSource(source)
            all.forEach { top.offer(it, null) }
            assertEquals("$source", all, top.result().map { it.finding })
        }
    }

    @Test
    fun `totals count every finding past the cap`() {
        val top = FindingsTopK(cap = 1)
        val malware = Finding(ruleId = "m", title = "m", level = "critical", category = FindingCategory.APP_RISK,
            impliesFlags = listOf("known_malware"))
        repeat(3) { top.offer(malware, null) }
        top.offer(malware.copy(ruleId = "x", triggered = false), null)
        assertEquals(FindingTotals(seen = 4, triggered = 3, knownMalware = 4, triggeredByRule = mapOf("m" to 3L)),
            top.totals())
        assertEquals(1, top.result().size)
    }

    @Test
    fun `a live session with 1500 findings keeps all of them`() = runBlocking {
        val s = w.writer.begin(w.scan(1L), liveEvents = false)
        s.appendAll("dns_monitor", live, CAPTURED,
            (0 until 1_500).asSequence().map { dns(EVIL_DOMAIN, time = 1_000L + it, key = "dns:$it") })
        val r = s.finish()
        assertEquals(1_500, r.scan.findings.size)
        assertEquals(1_500L, w.count("SELECT COUNT(*) FROM forensic_timeline WHERE scanResultId = 1"))
    }

    @Test
    fun `summarize sees the totals of findings dropped by the intrusion-log cap`() = runBlocking {
        var seen: FindingTotals? = null
        val hooks = object : SessionHooks {
            override fun summarize(scan: ScanResult, totals: FindingTotals): ScanResult = scan.also { seen = totals }
        }
        val s = w.writer.begin(w.scan(1L, il), liveEvents = false, hooks)
        s.appendAll("dns_monitor", il, IMPORT_CAPTURED,
            (0 until 1_200).asSequence().map { dns(EVIL_DOMAIN, time = 1_000L + it, key = "dns $it") })
        assertEquals(1_000, s.finish().scan.findings.size)
        assertEquals(1_200L, seen?.triggered)
        assertEquals(mapOf(DNS_RULE to 1_200L), seen?.triggeredByRule)
    }

    @Test
    fun `a session keeps 1000 of 1500 findings, in the JSON column and as Timeline rows`() = runBlocking {
        val s = w.writer.begin(w.scan(1L, il), liveEvents = false)
        s.appendAll("dns_monitor", il, IMPORT_CAPTURED,
            (0 until 1_500).asSequence().map { dns(EVIL_DOMAIN, time = 1_000L + it, key = "dns $it") })
        val r = s.finish()
        assertEquals(ScanOrchestrator.FINDINGS_PERSIST_CAP, r.scan.findings.size)
        assertEquals(1_000L, w.count("SELECT COUNT(*) FROM forensic_timeline WHERE scanResultId = 1"))
        assertEquals(1_000L, w.count("SELECT COUNT(*) FROM forensic_timeline WHERE recordId IS NOT NULL"))
    }

    // ── Finding JSON round-trip (carried gate) ──────────────────────────────────

    @Test
    fun `Finding service, ordinal and recordId survive the Converters round-trip`() {
        val findings = listOf(
            Finding(ruleId = "a", title = "a", level = "high", category = FindingCategory.APP_RISK,
                service = "dns_monitor", ordinal = 0, recordId = 0L),
            Finding(ruleId = "b", title = "b", level = "low", category = FindingCategory.DEVICE_POSTURE,
                service = "app_scanner", ordinal = 7, recordId = 42L),
            Finding(ruleId = "c", title = "c", level = "low", category = FindingCategory.APP_RISK),
        )
        assertEquals(findings, Converters.toFindingList(Converters.fromFindingList(findings)))
    }

    @Test
    fun `legacy Finding JSON decodes to empty service, ordinal -1 and null recordId`() {
        val legacy = """[{"ruleId":"x","title":"t","level":"high","category":"APP_RISK"}]"""
        val f = Converters.toFindingList(legacy).single()
        assertEquals("", f.service)
        assertEquals(-1, f.ordinal)
        assertNull(f.recordId)
    }

    @Test
    fun `persisted findings keep their ordinals through Room`() = runBlocking {
        val s = w.writer.begin(w.scan(1L), liveEvents = false)
        s.append("app_scanner", live, CAPTURED, listOf(app(EVIL_APP), app("com.ok")))
        s.finish()
        val f = w.f.db.scanResultDao().getLatestTwo().single().findings.single()
        assertEquals(APP_RULE, f.ruleId)
        assertEquals("app_scanner", f.service)
        assertEquals(0, f.ordinal)
    }

    @Test
    fun `an appended chunk over 5000 records is refused`() = runBlocking {
        val s = w.writer.begin(w.scan(1L), liveEvents = false)
        val big = List(ChunkedScanWriter.CHUNK_SIZE + 1) { app("com.app$it") }
        assertTrue(runCatching { s.append("app_scanner", live, CAPTURED, big) }.exceptionOrNull()
            is IllegalArgumentException)
    }
}

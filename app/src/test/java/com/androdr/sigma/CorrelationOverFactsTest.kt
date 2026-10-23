package com.androdr.sigma

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanState
import com.androdr.data.model.SignalMember
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TimelineEvent
import com.androdr.data.store.AtomReader
import com.androdr.data.store.HashKeys
import com.androdr.data.store.StoreFixture
import com.androdr.data.store.StoreFixture.Companion.dns
import com.androdr.data.store.rawFile
import com.androdr.scanner.BugReportHooks
import com.androdr.scanner.WriterFixture
import com.androdr.scanner.WriterHooks
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * K1 part 2 (spec §5.2 Correlation inputs, §6): correlation runs over atoms — timeline rows and
 * exact-precision facts keyed by [AtomRef] — and every event binds once.
 */
@RunWith(RobolectricTestRunner::class)
class CorrelationOverFactsTest {
    private val w = WriterFixture()
    private val f: StoreFixture get() = w.f
    private val atoms = AtomReader(w.f.db)

    @After fun tearDown() = w.close()

    private fun atom(name: String) = SigmaRuleParser.parse(rawFile("$name.yml").readText())!!

    private val perm = "androdr-atom-permission-use"

    /** A correlation engine set: the permission atom and one event-count rule needing [minEvents]. */
    private fun engine(minEvents: Int) = SigmaRuleEngine(io.mockk.mockk(relaxed = true)).apply {
        setRemoteRules(listOf(atom("sigma_androdr_atom_permission_use")))
        loadCorrelationRules(listOf(burst(minEvents)))
    }

    private fun burst(minEvents: Int) = CorrelationRule(
        id = "test-burst", title = "Burst", type = CorrelationType.EVENT_COUNT, referencedRuleIds = listOf(perm),
        timespanMs = 3_600_000L, groupBy = listOf("package_name"), minEvents = minEvents, severity = "high",
        displayLabel = "Burst",
    )

    private fun appOps(pkg: String, op: String, time: Long) = StoreRecord(mapOf(
        "package_name" to pkg, "operation" to op, "last_access_time" to "", "last_reject_time" to "",
        "access_count" to 1L, "is_system_app" to false, "source" to "bugreport_import", "event_time_ms" to time,
    ))

    private fun permRow(time: Long, pkg: String = "com.spy") = ForensicTimelineEvent(
        startTimestamp = time, source = "appops", category = "permission_use", description = "used",
        packageName = pkg, telemetrySource = TelemetrySource.BUGREPORT_IMPORT,
    )

    /** An import's hooks with [rows] as its extra rows and no lookback (an import's own atoms only). */
    private fun hooks(scan: ScanResult, engine: SigmaRuleEngine, rows: List<ForensicTimelineEvent> = emptyList()) =
        object : WriterHooks(scan, engine, SigmaCorrelationEngine()) {
            override fun extraRows(scan: ScanResult) = rows.map { it.copy(scanResultId = scan.id) }
        }

    private fun signals() = f.db.openHelper.readableDatabase
        .query("SELECT id FROM forensic_timeline WHERE kind = 'signal'")
        .use { c -> generateSequence { if (c.moveToNext()) c.getLong(0) else null }.toList() }

    private suspend fun members(signalId: Long) = f.db.signalMemberDao().forSignal(signalId, null, null, 100)

    @Test
    fun `an event-count rule over three fact atoms and one row atom fires once with members of both kinds`() =
        runBlocking {
            val scan = w.scan(1L, TelemetrySource.BUGREPORT_IMPORT)
            val s = w.writer.begin(scan, liveEvents = false, hooks(scan, engine(4), listOf(permRow(4_000))))
            s.append("appops_audit", TelemetrySource.BUGREPORT_IMPORT, 9L,
                listOf(appOps("com.spy", "android:camera", 1_000), appOps("com.spy", "android:record_audio", 2_000),
                    appOps("com.spy", "android:read_sms", 3_000)))
            val r = s.finish()

            val signal = signals().single()
            val m = members(signal)
            assertEquals("three facts and one row", listOf(SignalMember.KIND_ROW, SignalMember.KIND_FACT,
                SignalMember.KIND_FACT, SignalMember.KIND_FACT), m.map { it.kind })
            assertEquals(1, r.scan.findings.count { it.category == FindingCategory.CORRELATION })
            assertEquals("4", r.scan.findings.single { it.category == FindingCategory.CORRELATION }
                .matchContext["member_count"])
        }

    @Test
    fun `a row and a fact with the same numeric id bind separately`() {
        fun a(ref: AtomRef, t: Long) = TimelineAtom(ref, "permission_use", t, "com.spy", "", TelemetrySource.LIVE_SCAN)
        val list = listOf(a(Row(5), 1_000), a(Fact(5), 2_000), a(Fact(6), 3_000))
        val e = engine(3)
        val bindings = e.computeAtomBindings(list)
        assertEquals("both refs bound", setOf(Row(5), Fact(5), Fact(6)), bindings.keys)
        val result = SigmaCorrelationEngine().evaluate(e.getCorrelationRules(), list, bindings)
        assertEquals(listOf(Row(5), Fact(5), Fact(6)), result.signals.single().members)
    }

    @Test
    fun `a live DNS fact and its ioc_match row bind once`() = runBlocking {
        f.scan(1L, ScanState.COMPLETE)
        val key = "dns:41"
        val match = dns("evil.example", time = 5_000L, key = key).let {
            StoreRecord(it.fields + ("reason" to "IOC: evil.example"), key)
        }
        val factId = f.persist(1L, "dns_monitor", listOf(match)).factIdByChunkIndex.single()
        f.db.forensicTimelineEventDao().insert(ForensicTimelineEvent(startTimestamp = 5_000L, source = "dns_monitor",
            category = "ioc_match", description = "match", sourceEventKey = HashKeys.h128(key)))
        val cats = setOf("ioc_match")

        val lookback = atoms.atomsBetween(0L, 10_000L, cats)
        assertEquals("the row stands in for the fact", 1, lookback.size)
        assertTrue(lookback.single().ref is Row)
        assertTrue("the fact never binds", atoms.atomsForScan(1L, cats).none { it.ref == Fact(factId) })
    }

    @Test
    fun `an interim intrusion-log row carrying its recordId and its fact bind once`() = runBlocking {
        f.scan(2L)
        val id = f.persist(2L, "security_log", listOf(WriterFixture.securityLine(time = 7_000L)),
            source = TelemetrySource.INTRUSION_LOG_IMPORT).factIdByChunkIndex.single()
        f.db.forensicTimelineEventDao().insert(ForensicTimelineEvent(startTimestamp = 7_000L, source = "intrusion_log",
            category = "security_event", description = "sec", scanResultId = 2L, recordId = id,
            telemetrySource = TelemetrySource.INTRUSION_LOG_IMPORT))

        val got = atoms.atomsForScan(2L, setOf("security_event"))
        assertEquals(1, got.size)
        assertTrue("the row, not its fact", got.single().ref is Row)
    }

    @Test
    fun `a fact referenced only by a finding row (not an atom category) is still an atom`() = runBlocking {
        f.scan(3L)
        val id = f.persist(3L, "appops_audit", listOf(appOps("com.spy", "android:camera", 1_000)),
            source = TelemetrySource.BUGREPORT_IMPORT).factIdByChunkIndex.single()
        f.db.forensicTimelineEventDao().insert(ForensicTimelineEvent(startTimestamp = 1_000L,
            source = "bugreport_analysis",
            category = "app_risk", description = "Camera Access", scanResultId = 3L, recordId = id))

        assertEquals(listOf<AtomRef>(Fact(id)), atoms.atomsForScan(3L, setOf("permission_use")).map { it.ref })
    }

    @Test
    fun `day-precision facts never become atoms`() = runBlocking {
        f.scan(4L)
        fun battery(time: Long, precision: String?) = StoreRecord(buildMap {
            put("package_name", "com.x"); put("event_type", "package_install"); put("timestamp", time)
            if (precision != null) put("timestamp_precision", precision)
        })
        val ids = f.persist(4L, "battery_daily", listOf(battery(86_400_000L, "day"), battery(5_000L, null)),
            source = TelemetrySource.BUGREPORT_IMPORT).factIdByChunkIndex
        assertEquals("only the exact fact", listOf<AtomRef>(Fact(ids[1])),
            atoms.atomsForScan(4L, setOf("package_install")).map { it.ref })
    }

    @Test
    fun `the lookback excludes imports, future-dated facts, the finishing scan and DELETING scans`() = runBlocking {
        val usage = { t: Long, pkg: String -> StoreRecord(mapOf("package_name" to pkg, "app_name" to pkg,
            "event_type" to "app_foreground", "timestamp" to t)) }
        f.scan(10L, ScanState.COMPLETE) // live, in window
        val live = f.persist(10L, "usage_stats", listOf(usage(5_000L, "com.live"), usage(50_000L, "com.future")),
            live = true).factIdByChunkIndex
        f.scan(11L, ScanState.COMPLETE) // a bug-report import in the window
        f.persist(11L, "usage_stats", listOf(usage(6_000L, "com.import")), source = TelemetrySource.BUGREPORT_IMPORT)
        f.scan(12L, ScanState.DELETING) // a live scan being deleted
        f.persist(12L, "usage_stats", listOf(usage(7_000L, "com.deleting")), live = true)
        f.scan(13L, ScanState.IN_PROGRESS) // the finishing scan itself: its atoms come from atomsForScan only
        f.persist(13L, "usage_stats", listOf(usage(7_500L, "com.finishing")), live = true)
        val dao = f.db.forensicTimelineEventDao()
        fun row(scan: Long, pkg: String, src: TelemetrySource) = ForensicTimelineEvent(startTimestamp = 8_000L,
            source = "s", category = "app_foreground", description = pkg, packageName = pkg, scanResultId = scan,
            telemetrySource = src)
        dao.insertAll(listOf(row(10L, "row.live", TelemetrySource.LIVE_SCAN),
            row(11L, "row.import", TelemetrySource.BUGREPORT_IMPORT),
            row(12L, "row.deleting", TelemetrySource.LIVE_SCAN),
            row(13L, "row.finishing", TelemetrySource.LIVE_SCAN)))

        val got = atoms.atomsBetween(0L, 10_000L, setOf("app_foreground"))

        assertEquals(setOf("com.live", "row.live"), got.map { it.packageName }.toSet())
        assertTrue("the live fact is a Fact atom", got.any { it.ref == Fact(live[0]) })
        assertTrue("never a future-dated fact", got.none { it.ref == Fact(live[1]) })
    }

    @Test
    fun `an import's correlation never binds a live row or fact`() = runBlocking {
        // A live permission_use row and fact in a COMPLETE live scan at the same time as the import's event.
        f.scan(20L, ScanState.COMPLETE)
        f.persist(20L, "appops_audit", listOf(appOps("com.spy", "android:camera", 1_500)), live = true)
        f.db.forensicTimelineEventDao().insert(permRow(1_600).copy(scanResultId = 20L,
            telemetrySource = TelemetrySource.LIVE_SCAN))
        val scan = w.scan(21L, TelemetrySource.BUGREPORT_IMPORT)
        val s = w.writer.begin(scan, liveEvents = false, hooks(scan, engine(2)))
        s.append("appops_audit", TelemetrySource.BUGREPORT_IMPORT, 9L,
            listOf(appOps("com.spy", "android:read_sms", 1_000)))
        s.finish()

        assertEquals("one import atom alone cannot reach two", emptyList<Long>(), signals())
    }

    /**
     * Ruling R17: a bug-report module row (AppOps) and the fact it was parsed from would both be
     * permission_use atoms; the row carries the fact's recordId, so the event binds once.
     */
    @Test
    fun `a bug-report module row and its fact bind once`() = runBlocking {
        val scan = w.scan(30L, TelemetrySource.BUGREPORT_IMPORT)
        val module = listOf(TimelineEvent(timestamp = 1_000, source = "appops", category = "permission_use",
            description = "com.spy used CAMERA", severity = "INFO", packageName = "com.spy"))
        val h = BugReportHooks(scan, engine(2), SigmaCorrelationEngine(), emptyMap(), module, emptyList())
        val s = w.writer.begin(scan, liveEvents = false, h)
        s.append("appops_audit", TelemetrySource.BUGREPORT_IMPORT, 9L,
            listOf(appOps("com.spy", "android:camera", 1_000)))
        s.finish()

        val fact = f.db.openHelper.readableDatabase.query("SELECT id FROM telemetry_record")
            .use { c -> c.moveToFirst(); c.getLong(0) }
        val row = f.db.forensicTimelineEventDao().getAllForExport().single { it.source == "appops" }
        assertEquals("the module row carries its fact", fact, row.recordId)
        assertEquals("one event is one atom: a two-event burst does not fire", emptyList<Long>(), signals())
        assertEquals(listOf<AtomRef>(Row(row.id)), atoms.atomsForScan(30L, setOf("permission_use")).map { it.ref })
    }

    @Test
    fun `two bug-report events with module rows fire once with two row members`() = runBlocking {
        val scan = w.scan(31L, TelemetrySource.BUGREPORT_IMPORT)
        val module = listOf(1_000L, 2_000L).map {
            TimelineEvent(timestamp = it, source = "appops", category = "permission_use", description = "used",
                severity = "INFO", packageName = "com.spy")
        }
        val h = BugReportHooks(scan, engine(2), SigmaCorrelationEngine(), emptyMap(), module, emptyList())
        val s = w.writer.begin(scan, liveEvents = false, h)
        s.append("appops_audit", TelemetrySource.BUGREPORT_IMPORT, 9L,
            listOf(appOps("com.spy", "android:camera", 1_000), appOps("com.spy", "android:read_sms", 2_000)))
        s.finish()

        val m = members(signals().single())
        assertEquals(listOf(SignalMember.KIND_ROW, SignalMember.KIND_ROW), m.map { it.kind })
    }
}

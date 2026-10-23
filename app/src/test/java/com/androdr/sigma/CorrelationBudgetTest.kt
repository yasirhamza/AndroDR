package com.androdr.sigma

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetrySource
import com.androdr.data.store.rawFile
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
 * Gate C2 (spec §5.2, §9): correlation inside the finishing transaction is bounded by a
 * [CorrelationBudget] — a per-(rule, group) and a total deadline, checked, never thrown. The clock
 * is injected and advances one millisecond per read, so every cut-off is deterministic.
 */
@RunWith(RobolectricTestRunner::class)
class CorrelationBudgetTest {
    private val w = WriterFixture(recordSql = false)

    @After fun tearDown() = w.close()

    /** A clock that advances [step] ms every time it is read. */
    private class Ticker(private val step: Long = 1L) {
        private var now = 0L
        fun read(): Long {
            now += step
            return now
        }
    }

    private fun atom(name: String) = SigmaRuleParser.parse(rawFile("$name.yml").readText())!!
    private fun corr(name: String) = SigmaRuleParser.parseCorrelation(rawFile("$name.yml").readText())

    private val installThenAdmin = corr("sigma_androdr_corr_001_install_then_admin")
    private val burst = corr("sigma_androdr_corr_004_surveillance_burst")
    private val permThenC2 = corr("sigma_androdr_corr_003_permission_then_c2")

    private fun engine(rules: List<CorrelationRule>) = SigmaRuleEngine(io.mockk.mockk(relaxed = true)).apply {
        setRemoteRules(listOf(
            atom("sigma_androdr_atom_permission_use"), atom("sigma_androdr_atom_dns_lookup"),
            atom("sigma_androdr_atom_package_install"), atom("sigma_androdr_atom_device_admin_grant"),
        ))
        loadCorrelationRules(rules)
    }

    private fun hooks(scan: ScanResult, engine: SigmaRuleEngine, ticker: Ticker) =
        object : WriterHooks(scan, engine, SigmaCorrelationEngine(), { CorrelationBudget(ticker::read) }) {}

    private fun row(scan: Long, time: Long, category: String, pkg: String) = ForensicTimelineEvent(
        startTimestamp = time, source = "test", category = category, description = category, packageName = pkg,
        scanResultId = scan, telemetrySource = TelemetrySource.BUGREPORT_IMPORT,
    )

    private fun signalsOf(ruleId: String): Long =
        w.count("SELECT COUNT(*) FROM forensic_timeline WHERE kind = 'signal' AND ruleId = '$ruleId'")

    private fun incomplete(scan: ScanResult) =
        scan.scannerErrors.filter { it.exception == NotEvaluatedReason.CORRELATION_INCOMPLETE.sentinel }

    /**
     * 100k permission_use atoms for one package in 30 min: the ordered permission-then-C2 chain is
     * quadratic over them and stops at its per-group budget; the signals it found before the cut-off
     * are kept, the other rules' signals are kept, the rule and package are recorded, and no row
     * grows with the chain (members live only in signal_member).
     */
    @Test
    fun `an adversarial-density group stops at its per-group budget and keeps every signal found`() =
        runBlocking {
            val scan = w.scan(1L, TelemetrySource.BUGREPORT_IMPORT)
            val s = w.writer.begin(scan, liveEvents = false,
                hooks(scan, engine(listOf(installThenAdmin, burst, permThenC2)), Ticker()))
            val t0 = 1_700_000_000_000L
            val flood = buildList {
                (0L..2L).forEach { add(row(1L, t0 + it, "permission_use", "com.flood")) }
                add(row(1L, t0 + 3, "ioc_match", "com.flood"))
                val step = 30L * 60_000L / DENSE
                for (i in 0 until DENSE) add(row(1L, t0 + 4 + i * step, "permission_use", "com.flood"))
                add(row(1L, t0, "package_install", "com.ok"))
                add(row(1L, t0 + 1_000, "device_admin_grant", "com.ok"))
            }
            flood.chunked(5_000).forEach { w.f.db.forensicTimelineEventDao().insertAll(it) }

            val done = s.finish().scan

            assertEquals("finish returned and completed the scan", ScanState.COMPLETE, done.state)
            assertEquals("the other rule's signal is kept", 1L, signalsOf("androdr-corr-001"))
            assertTrue("the burst rule finished its group", signalsOf("androdr-corr-004") > 0)
            assertEquals("signals found in the group before its cut-off are kept", 3L, signalsOf("androdr-corr-003"))
            val cut = incomplete(done).single()
            assertEquals("androdr-corr-003", cut.ruleId)
            assertEquals(listOf("com.flood"), cut.packages)
            assertEquals("not a scanner failure", 0, done.realFailureCount)
            val maxRow = w.count("SELECT MAX(length(details) + length(correlationId) + length(description) + " +
                "length(packageName) + length(ruleId)) FROM forensic_timeline")
            assertTrue("no forensic_timeline row exceeds 64 KB: $maxRow", maxRow < 64 * 1024)
        }

    /** 50 dense packages: correlation stops at the total deadline; the rest are recorded, capped. */
    @Test
    fun `fifty dense packages stop at the total deadline and record the unstarted pairs`() = runBlocking {
        val scan = w.scan(2L, TelemetrySource.BUGREPORT_IMPORT)
        val s = w.writer.begin(scan, liveEvents = false, hooks(scan, engine(listOf(permThenC2, burst)), Ticker()))
        val t0 = 1_700_000_000_000L
        val rows = (0 until PACKAGES).flatMap { p ->
            // Three minutes apart: no burst of three in five minutes, so only the budget limits it.
            (0 until PER_PACKAGE).map { i -> row(2L, t0 + i * 180_000L, "permission_use", "com.p%02d".format(p)) }
        }
        rows.chunked(5_000).forEach { w.f.db.forensicTimelineEventDao().insertAll(it) }

        val done = s.finish().scan

        assertEquals(ScanState.COMPLETE, done.state)
        val entries = incomplete(done).associateBy { it.ruleId }
        val chain = entries.getValue("androdr-corr-003")
        assertEquals("at most 20 packages named", 20, chain.packages.size)
        assertEquals("every package is cut off or unstarted", PACKAGES - 20, chain.morePackages)
        assertTrue(chain.message!!, chain.message!!.endsWith("and ${PACKAGES - 20} more"))
        val unstarted = entries.getValue("androdr-corr-004")
        assertEquals("a rule that never ran lists its packages", 20, unstarted.packages.size)
        assertEquals(0, done.realFailureCount)
    }

    @Test
    fun `a total deadline passed during binding records every rule as not started`() {
        val engine = engine(listOf(installThenAdmin, permThenC2))
        val atoms = (0 until 1_000).map {
            TimelineAtom(Row(it.toLong()), "permission_use", it.toLong(), "com.x", "", TelemetrySource.LIVE_SCAN)
        }
        val budget = CorrelationBudget(Ticker(step = 10)::read, perGroupMs = 2_000, totalMs = 5)
        val bindings = engine.computeAtomBindings(atoms, budget::totalExpired)
        val result = SigmaCorrelationEngine().evaluate(engine.getCorrelationRules(), atoms, bindings, budget = budget)

        assertTrue(result.signals.isEmpty())
        assertEquals(listOf("androdr-corr-001", "androdr-corr-003"), result.incomplete.map { it.ruleId })
        assertTrue("rule-level entries name no package", result.incomplete.all { it.packages.isEmpty() })
        assertTrue(result.incomplete.all { it.message!!.contains("not started") })
    }

    private companion object {
        const val DENSE = 100_000
        const val PACKAGES = 50
        const val PER_PACKAGE = 300
    }
}

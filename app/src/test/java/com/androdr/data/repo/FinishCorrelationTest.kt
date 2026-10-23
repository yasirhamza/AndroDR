package com.androdr.data.repo

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.SignalMember
import com.androdr.data.store.AtomReader
import com.androdr.data.store.StoreFixture.Companion.CAPTURED
import com.androdr.data.store.StoreFixture.Companion.dns
import com.androdr.data.model.TelemetrySource
import com.androdr.scanner.WriterFixture
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import com.androdr.sigma.CorrelationSignal
import com.androdr.sigma.Row
import com.androdr.sigma.SignalIdentity
import com.androdr.sigma.TimelineAtom
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * The correlation pass inside the session's finishing transaction (ported from the retired
 * `saveScanWithCorrelation` tests): it reads its atoms after this scan's rows were inserted, so they
 * are `Row` atoms with their real ids (the Sprint 75 fix — signals were written with member ids
 * `0,0,0`); its signals are inserted after them with their members in `signal_member` only (spec
 * §5.4), and the findings the chains become are on the completed scan (#350).
 */
@RunWith(RobolectricTestRunner::class)
class FinishCorrelationTest {
    private val w = WriterFixture()

    @After fun tearDown() = w.close()

    private val chain = Finding(ruleId = "androdr-corr-004", title = "Multiple permissions accessed rapidly",
        level = "high", category = FindingCategory.CORRELATION, triggered = true)

    private inner class Hooks(private val signals: Boolean) : SessionHooks {
        var seen: List<TimelineAtom> = emptyList()
        override fun interimRows(scan: ScanResult) = listOf(
            ForensicTimelineEvent(startTimestamp = 1_000, source = "test", category = "permission_use",
                description = "evt", packageName = "com.test", scanResultId = scan.id),
            ForensicTimelineEvent(startTimestamp = 2_000, source = "test", category = "permission_use",
                description = "evt", packageName = "com.test", scanResultId = scan.id),
        )

        override suspend fun correlate(scan: ScanResult, atoms: AtomReader): Correlation {
            seen = atoms.atomsForScan(scan.id, setOf("app_risk", "permission_use")).sortedBy { it.ref }
            if (!signals) return Correlation.NONE
            val refs = seen.map { it.ref }
            val signal = ForensicTimelineEvent(startTimestamp = 1_000, endTimestamp = 2_000, kind = "signal",
                category = "correlation", source = "test", description = chain.title, ruleId = chain.ruleId,
                details = """{"member_count":${refs.size}}""",
                correlationId = SignalIdentity.correlationId(chain.ruleId, refs), scanResultId = 1L)
            return Correlation(listOf(CorrelationSignal(signal, refs)), listOf(chain))
        }
    }

    @Test
    fun `correlate sees this scan's rows as Row atoms with their real ids, finding rows first`() = runBlocking {
        val hooks = Hooks(signals = false)
        val s = w.writer.begin(w.scan(1L), liveEvents = false, hooks)
        s.append("dns_monitor", TelemetrySource.LIVE_SCAN, CAPTURED, listOf(dns(WriterFixture.EVIL_DOMAIN)))
        val r = s.finish()

        val rows = w.f.db.forensicTimelineEventDao().getAllForExport().sortedBy { it.id }
        assertEquals(rows.map { Row(it.id) }, hooks.seen.map { it.ref })
        assertEquals(listOf("app_scanner", "test", "test"), rows.map { it.source })
        assertTrue("real, distinct ids", hooks.seen.all { it.ref.id > 0 } && hooks.seen.toSet().size == 3)
        assertEquals("no signal, scan unchanged", listOf(WriterFixture.DNS_RULE), r.scan.findings.map { it.ruleId })
    }

    @Test
    fun `signals are inserted after the rows with their members in signal_member only`() = runBlocking {
        val hooks = Hooks(signals = true)
        val s = w.writer.begin(w.scan(1L), liveEvents = false, hooks)
        val r = s.finish()

        val rows = w.f.db.forensicTimelineEventDao().getAllForExport()
        val signal = rows.single { it.kind == "signal" }
        val memberIds = hooks.seen.map { it.ref.id }
        val stored = w.f.db.signalMemberDao().forSignal(signal.id, null, null, 10)
        assertEquals("the signal's members are the rows' real ids", memberIds,
            stored.filter { it.kind == SignalMember.KIND_ROW }.map { it.refId })
        assertTrue("no id list on the signal row", !signal.details.contains(memberIds.joinToString(",")))
        assertTrue("inserted after its members", signal.id > memberIds.max())
        assertEquals(listOf(chain), r.scan.findings)
        assertEquals(listOf(chain), w.f.db.scanResultDao().getLatestTwo().single().findings)
    }
}

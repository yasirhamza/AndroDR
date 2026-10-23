package com.androdr.data.repo

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.store.StoreFixture.Companion.CAPTURED
import com.androdr.data.store.StoreFixture.Companion.dns
import com.androdr.data.model.TelemetrySource
import com.androdr.scanner.WriterFixture
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * The correlation pass inside the session's finishing transaction (ported from the retired
 * `saveScanWithCorrelation` tests): it sees this scan's rows with their real ids (the Sprint 75 fix —
 * signals were written with `member_event_ids = "0,0,0"`), its signals are inserted after them, and
 * the findings the chains become are on the completed scan (#350).
 */
@RunWith(RobolectricTestRunner::class)
class FinishCorrelationTest {
    private val w = WriterFixture()

    @After fun tearDown() = w.close()

    private val chain = Finding(ruleId = "androdr-corr-004", title = "Multiple permissions accessed rapidly",
        level = "high", category = FindingCategory.CORRELATION, triggered = true)

    private inner class Hooks(private val signals: Boolean) : SessionHooks {
        var seen: List<ForensicTimelineEvent> = emptyList()
        override fun interimRows(scan: ScanResult) = listOf(
            ForensicTimelineEvent(startTimestamp = 1_000, source = "test", category = "permission_use",
                description = "evt", packageName = "com.test", scanResultId = scan.id),
            ForensicTimelineEvent(startTimestamp = 2_000, source = "test", category = "permission_use",
                description = "evt", packageName = "com.test", scanResultId = scan.id),
        )

        override suspend fun correlate(rows: List<ForensicTimelineEvent>): Correlation {
            seen = rows
            if (!signals) return Correlation.NONE
            val ids = rows.joinToString(",") { it.id.toString() }
            val signal = ForensicTimelineEvent(startTimestamp = 1_000, endTimestamp = 2_000, kind = "signal",
                category = "correlation", source = "test", description = chain.title, ruleId = chain.ruleId,
                details = """{"member_event_ids":"$ids"}""", scanResultId = 1L)
            return Correlation(listOf(signal), listOf(chain))
        }
    }

    @Test
    fun `correlate sees this scan's rows with their real ids, finding rows first`() = runBlocking {
        val hooks = Hooks(signals = false)
        val s = w.writer.begin(w.scan(1L), liveEvents = false, hooks)
        s.append("dns_monitor", TelemetrySource.LIVE_SCAN, CAPTURED, listOf(dns(WriterFixture.EVIL_DOMAIN)))
        val r = s.finish()

        assertEquals(listOf("app_scanner", "test", "test"), hooks.seen.map { it.source })
        assertTrue("real, distinct ids", hooks.seen.all { it.id > 0 } && hooks.seen.map { it.id }.toSet().size == 3)
        assertEquals("no signal, scan unchanged", listOf(WriterFixture.DNS_RULE), r.scan.findings.map { it.ruleId })
    }

    @Test
    fun `signals are inserted after the rows and their findings are on the completed scan`() = runBlocking {
        val hooks = Hooks(signals = true)
        val s = w.writer.begin(w.scan(1L), liveEvents = false, hooks)
        val r = s.finish()

        val rows = w.f.db.forensicTimelineEventDao().getAllForExport()
        val signal = rows.single { it.kind == "signal" }
        val memberIds = hooks.seen.map { it.id }
        assertTrue("the signal references the rows' real ids", signal.details.contains(memberIds.joinToString(",")))
        assertTrue("inserted after its members", signal.id > memberIds.max())
        assertEquals(listOf(chain), r.scan.findings)
        assertEquals(listOf(chain), w.f.db.scanResultDao().getLatestTwo().single().findings)
    }
}

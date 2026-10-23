package com.androdr.data.repo

import com.androdr.data.db.toForensicTimelineEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TelemetryState
import com.androdr.scanner.WriterFixture
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import com.androdr.sigma.SigmaRuleEvaluator
import com.androdr.sigma.StoreRecord
import com.androdr.sigma.TAXONOMY_CONTRACT_TABLE
import com.androdr.sigma.TaxonomyContract
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * F2 (spec §9): for every taxonomy service, a stored finding resolves its `recordId` to the fact
 * its own scan observed, its Timeline row carries the same `recordId`, its kind follows the record
 * (ALERT iff it is an event), and its dropped `matchContext` is rebuilt from that fact exactly as
 * the evaluator built it.
 */
@RunWith(RobolectricTestRunner::class)
class FindingRecordRefTest {
    private val w = WriterFixture()

    @After fun tearDown() = w.close()

    private fun record(service: String): StoreRecord {
        val fields = mutableMapOf<String, Any?>("package_name" to "com.x", "marker" to service, "count" to 3L)
        TaxonomyContract.eventTimeField(service)?.let { fields[it] = 1_700_000_000_000L }
        return StoreRecord(fields)
    }

    @Test
    fun `recordId resolves for every service`() = runBlocking {
        val services = TAXONOMY_CONTRACT_TABLE.keys.toList()
        assertTrue(services.size > 10)
        services.forEachIndexed { i, service ->
            val scanId = 100L + i
            w.writer.begin(w.scan(scanId, TelemetrySource.BUGREPORT_IMPORT), liveEvents = false)
            val rec = record(service)
            val chunk = w.f.persist(scanId, service, listOf(record("$service-other"), rec),
                source = TelemetrySource.BUGREPORT_IMPORT)
            val evaluated = Finding(ruleId = "r-$service", title = "t", level = "medium",
                category = FindingCategory.APP_RISK, service = service, ordinal = 1,
                matchContext = SigmaRuleEvaluator.matchContextOf(rec.fields))
            val scan = w.scan(scanId, TelemetrySource.BUGREPORT_IMPORT)
            w.f.findings.recordChunk(scanId, 0, listOf(evaluated), chunk) {
                it.toForensicTimelineEvent(scan, isBugreport = true)
            }
            w.repo.finish(scan, PendingFindings(), FindingTotals(), SessionHooks.NONE, TelemetryState.STORED)

            val observed = w.count("SELECT recordId FROM scan_record WHERE scanId = $scanId AND ordinal = 1")
            assertEquals(service, observed, w.count("SELECT recordId FROM scan_finding WHERE scanId = $scanId"))
            assertEquals(service, observed,
                w.count("SELECT recordId FROM forensic_timeline WHERE scanResultId = $scanId"))
            val kind = if (TaxonomyContract.eventTimeField(service) != null) "ALERT" else "STATE"
            val stored = w.f.db.openHelper.readableDatabase
                .query("SELECT kind FROM scan_finding WHERE scanId = $scanId").use { it.moveToFirst(); it.getString(0) }
            assertEquals(service, kind, stored)
            val back = w.findingsOf(scanId).single()
            assertEquals(service, observed, back.recordId)
            assertEquals(service, evaluated.matchContext, back.matchContext)
        }
    }

    /** Spec §5.4: untriggered (safe-state) findings are stored only for snapshot services. */
    @Test
    fun `an untriggered finding is stored for a snapshot service and not for an event service`() = runBlocking {
        val scan = w.scan(1L, TelemetrySource.BUGREPORT_IMPORT)
        w.writer.begin(scan, liveEvents = false)
        for ((i, service) in listOf("app_scanner", "dns_monitor").withIndex()) {
            val chunk = w.f.persist(1L, service, listOf(record(service)), source = TelemetrySource.BUGREPORT_IMPORT)
            val safe = Finding(ruleId = "safe-$i", title = "t", level = "low", category = FindingCategory.APP_RISK,
                triggered = false, service = service, ordinal = 0)
            w.f.findings.recordChunk(1L, 0, listOf(safe), chunk) { it.toForensicTimelineEvent(scan, true) }
        }
        w.repo.finish(scan, PendingFindings(), FindingTotals(), SessionHooks.NONE, TelemetryState.STORED)
        assertEquals(listOf("safe-0"), w.findingsOf(1L).map { it.ruleId })
        assertEquals("no Timeline row for an untriggered finding", 0L,
            w.count("SELECT COUNT(*) FROM forensic_timeline"))
    }

    @Test
    fun `findingJson drops matchContext only when the fact is stored`() = runBlocking {
        val s = w.writer.begin(w.scan(1L), liveEvents = false)
        s.append("dns_monitor", TelemetrySource.LIVE_SCAN, 1L,
            listOf(com.androdr.data.store.StoreFixture.dns(WriterFixture.EVIL_DOMAIN, key = "dns:1")))
        s.finish()
        val json = w.f.db.openHelper.readableDatabase.query("SELECT findingJson FROM scan_finding")
            .use { it.moveToFirst(); it.getString(0) }
        assertTrue(json, !json.contains("matchContext"))
        assertTrue(w.findingsOf(1L).single().matchContext["domain"] == WriterFixture.EVIL_DOMAIN)
    }
}

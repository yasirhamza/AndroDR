package com.androdr.scanner

import android.net.Uri
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.ByteArrayInputStream

/**
 * Gate D1: an imported DNS finding row carries the record's own time.
 *
 * Imported DNS records used to be evaluated without a `timestamp` field, so a
 * DNS finding from an intrusion-log import was persisted at 0 ("Unknown")
 * while connect and security findings carried their event time. Imported DNS
 * is now evaluated through [com.androdr.data.model.ImportedDnsEvent.toFieldMap],
 * which also carries `resolved_ips`.
 */
@RunWith(RobolectricTestRunner::class)
class DnsFindingTimestampTest {

    private val eventTime = 1_787_400_345_334L

    private val log = """{"dns_event":{"event_id":0,"event_time":$eventTime,"package_name":"com.evil.app",""" +
        """"hostname":"api.badexample.com","ip_addresses":["/34.160.125.113"],"ip_addresses_count":1}}"""

    private val engine = IntrusionLogZips.engine(
        IntrusionLogZips.rule("androdr-d1-domain", "dns_monitor", "domain", "api.badexample.com"),
        IntrusionLogZips.rule("androdr-d1-ip", "dns_monitor", "resolved_ips", "34.160.125.113"),
    )

    private fun analyze(): CollectingChunks {
        val chunks = CollectingChunks(engine)
        val entries = sequenceOf("2026-08-21.txt" to ByteArrayInputStream(log.toByteArray()))
        runBlocking {
            IntrusionLogAnalyzer(mockk(relaxed = true), mockk(relaxed = true))
                .analyzeEntries(entries, uidResolver = { -1 }, capturedAt = 1_787_400_400_000L, chunks = chunks)
        }
        return chunks
    }

    @Test
    fun `imported dns finding carries the record timestamp`() {
        val finding = analyze().findings.single { it.ruleId == "androdr-d1-domain" && it.triggered }
        assertEquals(eventTime.toString(), finding.matchContext["timestamp"])
    }

    @Test
    fun `imported dns is evaluated with its resolved ips`() {
        assertTrue(analyze().findings.any { it.ruleId == "androdr-d1-ip" && it.triggered })
    }

    @Test
    fun `persisted imported dns finding row has the record time`() = runBlocking {
        val zip = IntrusionLogZips.zip("2026-08-21.txt" to listOf(log))
        IntrusionLogZips.fixture(engine) { zip }.use { f ->
            f.orchestrator.analyzeIntrusionLog(mockk<Uri>(relaxed = true))
            val row = f.timelineDao.getAllForExport().single { it.ruleId == "androdr-d1-domain" }
            assertEquals(eventTime, row.startTimestamp)
        }
    }
}

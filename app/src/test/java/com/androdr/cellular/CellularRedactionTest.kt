package com.androdr.cellular

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.reporting.TimelineExporter
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression guard for a real defect: cellular findings were exported with the
 * full cell identity tuple. `(mcc, mnc, tac, ci)` is a globally unique tower
 * identifier and is directly geolocatable, so an export carrying it is a
 * location trail — and an export is meant to be shared, which is why this is
 * worse than the same data in a log.
 *
 * Pins BOTH directions: identity absent, radio condition present. A redactor
 * that strips everything would be safe and useless.
 */
class CellularRedactionTest {

    private val realistic =
        "rat=LTE tac=1437 ci=192816407 pci=167 earfcn=1600 bw=null plmn=427/01 " +
            "op=Ooredoo neighbours=13 rsrp=-84 prevTac=1436 churn5m=4"

    @Test
    fun `tower identity never survives redaction`() {
        val out = CellularRedaction.redact(realistic)
        listOf("tac=1437", "ci=192816407", "pci=167", "plmn=427/01", "op=Ooredoo", "prevTac=1436")
            .forEach { assertFalse("leaked: $it", out.contains(it)) }
    }

    @Test
    fun `radio condition survives redaction`() {
        val out = CellularRedaction.redact(realistic)
        listOf("rat=LTE", "neighbours=13", "rsrp=-84", "churn5m=4", "earfcn=1600")
            .forEach { assertTrue("dropped: $it", out.contains(it)) }
    }

    @Test
    fun `the circumstances of the read survive redaction`() {
        // They are facts about the device, not the tower, and a reader needs
        // them to tell an idle-radio "no neighbours" from a real one.
        val out = CellularRedaction.redact(
            "$realistic origin=PRIME records=14 screen=false fg=false data=NONE",
        )
        listOf("origin=PRIME", "records=14", "screen=false", "fg=false", "data=NONE")
            .forEach { assertTrue("dropped: $it", out.contains(it)) }
    }

    @Test
    fun `redaction is an allowlist, so unknown fields are dropped`() {
        // The point of the allowlist: a field added later must be consciously
        // cleared for export rather than leaking by default.
        val out = CellularRedaction.redact("rat=LTE imsi=123456789012345 newfield=x")
        assertTrue(out.contains("rat=LTE"))
        assertFalse("an unrecognised field leaked", out.contains("imsi="))
        assertFalse("an unrecognised field leaked", out.contains("newfield="))
    }

    @Test
    fun `redaction says what it withheld rather than staying silent`() {
        // Silence would read as "there was nothing more" in a forensic artifact.
        assertTrue(CellularRedaction.redact(realistic).contains("withheld"))
        assertTrue(CellularRedaction.redact("tac=1 ci=2").contains("withheld"))
    }

    @Test
    fun `blank details stay blank`() {
        assertTrue(CellularRedaction.redact("").isBlank())
    }

    // ---- exporter-level: the redactor being correct is not enough if the
    // exporters forget to call it ----

    private fun cellEvent() = ForensicTimelineEvent(
        startTimestamp = 1_700_000_000_000L,
        source = "cellular_monitor",
        category = "network_anomaly",
        description = "Tracking area churn",
        details = realistic,
        ruleId = "androdr-104",
    )

    private fun otherEvent() = ForensicTimelineEvent(
        startTimestamp = 1_700_000_000_000L,
        source = "dns_monitor",
        category = "network",
        description = "Lookup",
        details = "domain=example.com tac=notacell",
        ruleId = "androdr-003",
    )

    @Test
    fun `timeline CSV export redacts cellular rows`() {
        val csv = TimelineExporter.formatCsv(listOf(cellEvent()))
        assertFalse("TAC leaked into CSV export", csv.contains("tac=1437"))
        assertFalse("CI leaked into CSV export", csv.contains("ci=192816407"))
        assertTrue("condition missing from CSV export", csv.contains("churn5m=4"))
    }

    @Test
    fun `timeline plaintext export redacts cellular rows`() {
        val txt = TimelineExporter.formatPlaintext(listOf(cellEvent()), versionName = "test")
        assertFalse("TAC leaked into plaintext export", txt.contains("tac=1437"))
        assertFalse("CI leaked into plaintext export", txt.contains("ci=192816407"))
    }

    @Test
    fun `non-cellular rows are left alone`() {
        // Redaction is scoped by source; it must not mangle other telemetry.
        val csv = TimelineExporter.formatCsv(listOf(otherEvent()))
        assertTrue("a dns row was wrongly redacted", csv.contains("domain=example.com"))
    }
}

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
            "$realistic moved5m=640 fixAge=12 origin=PRIME records=14 screen=false fg=false data=NONE",
        )
        listOf("moved5m=640", "fixAge=12", "origin=PRIME", "records=14", "screen=false", "fg=false", "data=NONE")
            .forEach { assertTrue("dropped: $it", out.contains(it)) }
    }

    @Test
    fun `signal quality and the neighbour scalars survive redaction`() {
        // Measurements, not identity: a reader judging "the tower is suddenly
        // very close" needs the timing advance, not the tower's name.
        val out = CellularRedaction.redact(
            "$realistic rsrq=-11 sinr=10 cqi=9 ta=4 taUs=- dbm=-84 nMaxRsrp=-95 nEarfcns=2 pciInN=true",
        )
        listOf("rsrq=-11", "sinr=10", "cqi=9", "ta=4", "dbm=-84", "nMaxRsrp=-95", "nEarfcns=2", "pciInN=true")
            .forEach { assertTrue("dropped: $it", out.contains(it)) }
    }

    @Test
    fun `neighbour identities are dropped even if a future writer emits them`() {
        // Defence in depth: the monitor never puts neighbour PCIs or channels
        // in details, and the allowlist would drop them if it did.
        val out = CellularRedaction.redact("$realistic nPcis=12,167 nEarfcnList=1600,1850")
        assertFalse(out.contains("12,167"))
        assertFalse(out.contains("1600,1850"))
    }

    @Test
    fun `the registration state survives redaction`() {
        val out = CellularRedaction.redact("$realistic svc=IN_SERVICE roaming=false dnt=LTE")
        listOf("svc=IN_SERVICE", "roaming=false", "dnt=LTE").forEach { assertTrue("dropped: $it", out.contains(it)) }
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
    fun `a newline inside a value cannot carry a forged pair onto the next line`() {
        // The operator name is network-chosen. Were it to reach details
        // unfolded, a CSV reader would see the second line as its own row,
        // and a forged `rsrp=` would shadow the real one. The redactor
        // cannot tell a forged pair with a fresh key from a real one — that
        // is the writer's job (CellularDetailsTest) — but it never lets a
        // line break or a shadowed key through.
        val out = CellularRedaction.redact("rat=LTE op=Evil\nrsrp=-1 rsrp=-84")
        assertFalse("newline survived", out.contains('\n'))
        assertFalse("a shadowed key survived", out.contains("rsrp="))
        assertTrue(out.contains("rat=LTE"))
    }

    @Test
    fun `a key that appears twice is dropped both times`() {
        // A smuggled second `rsrp=` is indistinguishable from the real one,
        // so neither can be believed; the row says so by omission.
        val out = CellularRedaction.redact("rat=LTE rsrp=-1 op=x rsrp=-84")
        assertFalse("a duplicated key survived", out.contains("rsrp="))
        assertTrue(out.contains("rat=LTE"))
    }

    @Test
    fun `a token that is not a pair is dropped`() {
        val out = CellularRedaction.redact("rat=LTE garbage rsrp=-84=-1 svc==x")
        assertTrue(out.contains("rat=LTE"))
        assertFalse(out.contains("garbage"))
        assertFalse(out.contains("rsrp="))
        assertFalse(out.contains("svc="))
    }

    @Test
    fun `the note is plain ASCII like the rest of the report`() {
        assertTrue(CellularRedaction.REDACTION_NOTE.all { it.code < 128 })
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

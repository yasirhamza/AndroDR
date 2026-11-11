package com.androdr.privacy

import com.androdr.data.model.NetworkStatus
import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyTrackerEvidence
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The Timeline entries a privacy scan writes (spec 2026-11-10 §5.2, §5.5). */
class PrivacyTimelineRowsTest {

    private val at = 1_000L

    private fun app(
        pkg: String,
        label: String = pkg,
        system: Boolean = false,
        outcome: InspectOutcome = InspectOutcome.INSPECTED,
    ) =
        PrivacyAppResult(9, pkg, 1, label, system, outcome.name, null)

    private fun ev(pkg: String, id: Int, name: String = "T$id", inCode: Boolean = true, isNew: Boolean = false) =
        PrivacyTrackerEvidence(9, pkg, id, name, "", "Analytics", inCode, if (inCode) 0 else 3, 0, null, null, null,
            isNew)

    private fun build(
        results: List<PrivacyAppResult>,
        evidence: List<PrivacyTrackerEvidence>,
        counts: PrivacyTimelineRows.ScanCounts = PrivacyTimelineRows.ScanCounts(inspected = 3, partial = 0, failed = 0),
        network: NetworkStatus = NetworkStatus.COMPLETE,
        coverageDays: Int = 3,
    ) = PrivacyTimelineRows.build(at, counts, results, evidence, network, coverageDays)

    @Test fun `one scan entry plus one per user app with a tracker found in code`() {
        val rows = build(
            listOf(app("a", "Alpha"), app("b", "Beta"), app("c", "Gamma")),
            listOf(ev("a", 1), ev("a", 2), ev("b", 3)),
        )
        assertEquals(listOf(PrivacyTimelineRows.CATEGORY_SCAN, PrivacyTimelineRows.CATEGORY_APP,
            PrivacyTimelineRows.CATEGORY_APP), rows.map { it.category })
        assertEquals("Privacy scan: 3 apps inspected · trackers found in the code of 2", rows[0].description)
        assertEquals(listOf("Alpha: 2 trackers found in code", "Beta: 1 tracker found in code"),
            rows.drop(1).map { it.description })
        assertEquals(listOf("a", "b"), rows.drop(1).map { it.packageName })
    }

    @Test fun `no entry for a system app, though the scan entry counts it`() {
        val rows = build(listOf(app("s", system = true)), listOf(ev("s", 1)))
        assertEquals(1, rows.size)
        assertTrue(rows[0].description.endsWith("trackers found in the code of 1"))
    }

    @Test fun `no entry for an app with only network evidence`() {
        val rows = build(listOf(app("a")), listOf(ev("a", 1, inCode = false)))
        assertEquals(1, rows.size)
        assertTrue(rows[0].description.endsWith("trackers found in the code of 0"))
    }

    @Test fun `the first ten trackers are named, then and N more`() {
        val rows = build(listOf(app("a")), (1..13).map { ev("a", it, name = "T%02d".format(it)) })
        val details = rows[1].details
        assertTrue(details, details.contains("T01, T02, T03, T04, T05, T06, T07, T08, T09, T10 and 3 more"))
        assertFalse(details, details.contains("T11"))
    }

    @Test fun `new since the previous scan is counted`() {
        val rows = build(listOf(app("a")), listOf(ev("a", 1, isNew = true), ev("a", 2, isNew = true), ev("a", 3)))
        assertTrue(rows[1].details, rows[1].details.contains("2 new since the previous privacy scan"))
        val none = build(listOf(app("a")), listOf(ev("a", 1)))
        assertFalse(none[1].details.contains("new since"))
    }

    @Test fun `partly inspected is said`() {
        val rows = build(listOf(app("a", outcome = InspectOutcome.PARTIAL)), listOf(ev("a", 1)))
        assertTrue(rows[1].details, rows[1].details.contains("Partly inspected"))
    }

    @Test fun `the scan entry says what could not be inspected and how the network step went`() {
        val counts = PrivacyTimelineRows.ScanCounts(inspected = 5, partial = 2, failed = 1)
        val rows = build(emptyList(), emptyList(), counts,
            NetworkStatus.TRUNCATED)
        assertEquals("Privacy scan: 7 apps inspected · trackers found in the code of 0 · 1 could not be inspected · " +
            "2 partly inspected", rows[0].description)
        assertTrue(rows[0].details, rows[0].details.contains("incomplete"))
        val failed = build(emptyList(), emptyList(), network = NetworkStatus.FAILED)
        assertTrue(failed[0].details.contains("could not be read"))
    }

    @Test fun `with no lookups recorded the scan entry never claims complete network evidence`() {
        val rows = build(emptyList(), emptyList(), network = NetworkStatus.COMPLETE, coverageDays = 0)
        assertFalse(rows[0].details, rows[0].details.contains("complete"))
        assertTrue(rows[0].details, rows[0].details.contains("no lookups"))
    }

    @Test fun `one app inspected is said in the singular`() {
        val one = PrivacyTimelineRows.ScanCounts(inspected = 1, partial = 0, failed = 0)
        assertTrue(build(emptyList(), emptyList(), one)[0].description.startsWith("Privacy scan: 1 app inspected"))
    }

    @Test fun `a hostile label is sanitised and still found by its name`() {
        val rows = build(listOf(app("com.bank", "Bank\u202Eevil\n")), listOf(ev("com.bank", 1, name = "Tr\u200Back")))
        assertTrue(rows[1].description, rows[1].description.startsWith("Bankevil: 1 tracker"))
        assertEquals("Bankevil", rows[1].appName)
        assertTrue(rows[1].details, rows[1].details.contains("Track"))
        val text = rows.joinToString { it.description + it.details + it.appName }
        assertFalse(text.any { Character.getType(it) == Character.FORMAT.toInt() })
    }

    @Test fun `a label with nothing displayable falls back to the package name`() {
        val rows = build(listOf(app("com.bank", "\u202E")), listOf(ev("com.bank", 1)))
        assertTrue(rows[1].description.startsWith("com.bank: 1 tracker"))
    }

    @Test fun `every entry is marked as a privacy entry and tied to no security scan`() {
        val rows = build(listOf(app("a")), listOf(ev("a", 1)))
        for (r in rows) {
            assertEquals(TelemetrySource.PRIVACY_SCAN, r.telemetrySource)
            assertEquals(-1L, r.scanResultId)
            assertEquals(null, r.level)
            assertEquals("", r.ruleId)
            assertFalse(r.persistent)
            assertEquals(null, r.recordId)
            assertEquals("event", r.kind)
            assertEquals(at, r.startTimestamp)
            assertEquals(PrivacyTimelineRows.MODULE, r.source)
        }
    }
}

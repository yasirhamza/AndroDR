package com.androdr.reporting

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertTrue
import org.junit.Test

class TimelineExporterTest {

    private val events = listOf(
        ForensicTimelineEvent(
            id = 1, startTimestamp = 1711900800000, source = "app_scanner",
            category = "ioc_match", description = "IOC: com.evil.spy",
            severity = "CRITICAL", packageName = "com.evil.spy",
            iocIndicator = "com.evil.spy", iocType = "package_name",
            campaignName = "Pegasus", ruleId = "androdr-001",
            telemetrySource = TelemetrySource.LIVE_SCAN
        ),
        ForensicTimelineEvent(
            id = 2, startTimestamp = 1711900860000, source = "appops",
            category = "permission_use", description = "com.evil.spy used CAMERA",
            severity = "MEDIUM", packageName = "com.evil.spy",
            telemetrySource = TelemetrySource.BUGREPORT_IMPORT
        )
    )

    @Test
    fun `plaintext export contains header and events`() {
        val text = TimelineExporter.formatPlaintext(events)
        assertTrue(text.contains("AndroDR Forensic Timeline"))
        assertTrue(text.contains("IOC: com.evil.spy"))
        assertTrue(text.contains("CRITICAL"))
        assertTrue(text.contains("com.evil.spy used CAMERA"))
    }

    @Test
    fun `CSV export has header row and data rows`() {
        val csv = TimelineExporter.formatCsv(events)
        val lines = csv.lines().filter { it.isNotBlank() }
        assertTrue(lines[0].contains("timestamp"))
        assertTrue(lines[0].contains("module"))
        assertTrue(lines[0].contains("event"))
        assertTrue(lines[0].contains("ioc_source"))
        assertTrue(lines[0].contains("mitre_technique"))
        assertTrue(lines[0].contains("details"))
        // Sprint 75 follow-up — correlation + clustering fields must be
        // present so a CSV consumer can reconstruct what the Timeline UI
        // renders (cluster membership, rule linkage, kind, scan scoping).
        assertTrue(lines[0].contains("end_timestamp"))
        assertTrue(lines[0].contains("kind"))
        assertTrue(lines[0].contains("rule_id"))
        assertTrue(lines[0].contains("correlation_id"))
        assertTrue(lines[0].contains("scan_result_id"))
        assertTrue(lines.size >= 3)
    }

    @Test
    fun `CSV export emits correlation fields from signal rows`() {
        val signalEvent = ForensicTimelineEvent(
            id = 100L,
            startTimestamp = 1_700_000_000_000L,
            endTimestamp = 1_700_000_300_000L,
            kind = "signal",
            category = "correlation",
            source = "sigma_correlation_engine",
            description = "Install then device admin grant",
            severity = "high",
            packageName = "com.test",
            ruleId = "androdr-corr-001",
            correlationId = "androdr-corr-001:1,2",
            scanResultId = 42L,
            details = """{"correlation_type":"temporal_ordered","member_event_ids":"1,2"}"""
        )
        val csv = TimelineExporter.formatCsv(listOf(signalEvent))
        val dataRow = csv.lines().drop(1).first { it.isNotBlank() }
        assertTrue("kind column populated", dataRow.contains("signal"))
        assertTrue("rule_id column populated", dataRow.contains("androdr-corr-001"))
        assertTrue("correlation_id column populated", dataRow.contains("androdr-corr-001:1,2"))
        assertTrue("scan_result_id column populated", dataRow.contains(",42,"))
        // endTimestamp is epoch ms for signals
        assertTrue("end_timestamp populated", dataRow.contains("1700000300000"))
    }

    @Test
    fun `CSV export recovers package and pkg correlation id from description for legacy rows`() {
        // Simulates a pre-PR #76 bug-report permission_use row where
        // AppOpsModule never stamped packageName and the scan never
        // stamped a correlationId. The CSV export should parse the
        // package prefix out of the description and synthesize a
        // `pkg:` correlation id so legacy data isn't dead on export.
        val legacyRow = ForensicTimelineEvent(
            id = 999L,
            startTimestamp = 1_700_000_000_000L,
            kind = "event",
            category = "permission_use",
            source = "appops",
            description = "com.microsoft.appmanager used READ_CONTACTS at 2026-04-05 08:51:50.313",
            severity = "INFO",
            // Critical: packageName is empty (legacy row)
            packageName = "",
            correlationId = ""
        )
        val csv = TimelineExporter.formatCsv(listOf(legacyRow))
        val dataRow = csv.lines().drop(1).first { it.isNotBlank() }
        assertTrue(
            "package column should recover com.microsoft.appmanager from description",
            dataRow.contains("com.microsoft.appmanager")
        )
        assertTrue(
            "correlation_id should synthesize pkg:com.microsoft.appmanager",
            dataRow.contains("pkg:com.microsoft.appmanager")
        )
    }

    @Test
    fun `CSV export emits pkg correlation id stamped at write time`() {
        val pkgLinked = ForensicTimelineEvent(
            id = 200L,
            startTimestamp = 1_700_000_100_000L,
            kind = "event",
            category = "package_install",
            source = "app_scanner",
            description = "Package installed: Test App",
            severity = "info",
            packageName = "com.test.app",
            correlationId = "pkg:com.test.app"
        )
        val csv = TimelineExporter.formatCsv(listOf(pkgLinked))
        val dataRow = csv.lines().drop(1).first { it.isNotBlank() }
        assertTrue(dataRow.contains("pkg:com.test.app"))
        assertTrue(dataRow.contains("package_install"))
    }

    @Test
    fun `CSV export escapes commas in descriptions`() {
        val eventsWithComma = listOf(
            ForensicTimelineEvent(
                id = 3, startTimestamp = 1000L, source = "test",
                category = "test", description = "value with, comma",
                severity = "INFO"
            )
        )
        val csv = TimelineExporter.formatCsv(eventsWithComma)
        assertTrue(csv.contains("\"value with, comma\""))
    }

    @Test
    fun `empty events produce valid output`() {
        val text = TimelineExporter.formatPlaintext(emptyList())
        assertTrue(text.contains("No timeline events"))
        val csv = TimelineExporter.formatCsv(emptyList())
        assertTrue(csv.lines().first().contains("timestamp"))
    }

    @Test
    fun `display names resolve when appName is empty`() {
        val eventsNoName = listOf(
            ForensicTimelineEvent(
                id = 4, startTimestamp = 1711900800000, source = "appops",
                category = "permission_use", description = "com.whatsapp used CAMERA",
                severity = "INFO", packageName = "com.whatsapp"
            )
        )
        val names = mapOf("com.whatsapp" to "WhatsApp")
        val text = TimelineExporter.formatPlaintext(eventsNoName, names)
        assertTrue("Should resolve display name", text.contains("App: WhatsApp (com.whatsapp)"))
    }

    @Test
    fun `assessment driven by rule guidance`() {
        val guidance = mapOf("androdr-001" to "UNINSTALL IMMEDIATELY -- known malware")
        val text = TimelineExporter.formatPlaintext(events, ruleGuidance = guidance)
        assertTrue("Should have assessment", text.contains("ASSESSMENT:"))
        assertTrue("Rule guidance drives critical assessment",
            text.contains("CRITICAL ACTIVITY DETECTED"))
    }

    @Test
    fun `assessment without guidance caps at review`() {
        // Same events but no rule guidance -> no CRITICAL, just REVIEW
        val text = TimelineExporter.formatPlaintext(events)
        assertTrue(text.contains("ASSESSMENT:"))
        assertTrue("Without guidance, significant events -> REVIEW",
            text.contains("REVIEW RECOMMENDED"))
    }

    @Test
    fun `assessment shows no concerns for informational events`() {
        val infoEvents = listOf(
            ForensicTimelineEvent(
                id = 5, startTimestamp = 1711900800000, source = "appops",
                category = "permission_use", description = "test",
                severity = "INFORMATIONAL", packageName = "com.test"
            )
        )
        val text = TimelineExporter.formatPlaintext(infoEvents)
        assertTrue(text.contains("NO CONCERNS"))
    }

    @Test
    fun `output is ASCII only`() {
        val text = TimelineExporter.formatPlaintext(events)
        val nonAscii = text.filter { it.code > 127 }
        assertTrue("Non-ASCII characters found: $nonAscii", nonAscii.isEmpty())
    }
}

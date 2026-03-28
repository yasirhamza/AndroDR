package com.androdr.reporting

import com.androdr.data.model.ForensicTimelineEvent
import org.junit.Assert.assertTrue
import org.junit.Test

class TimelineExporterTest {

    private val events = listOf(
        ForensicTimelineEvent(
            id = 1, timestamp = 1711900800000, source = "app_scanner",
            category = "ioc_match", description = "IOC: com.evil.spy",
            severity = "CRITICAL", packageName = "com.evil.spy",
            iocIndicator = "com.evil.spy", iocType = "package_name",
            campaignName = "Pegasus", ruleId = "androdr-001",
            isFromRuntime = true
        ),
        ForensicTimelineEvent(
            id = 2, timestamp = 1711900860000, source = "appops",
            category = "permission_use", description = "com.evil.spy used CAMERA",
            severity = "MEDIUM", packageName = "com.evil.spy",
            isFromBugreport = true
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
        assertTrue(lines.size >= 3)
    }

    @Test
    fun `CSV export escapes commas in descriptions`() {
        val eventsWithComma = listOf(
            ForensicTimelineEvent(
                id = 3, timestamp = 1000L, source = "test",
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
}

package com.androdr.sigma

import android.content.Context
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.FileArtifactTelemetry
import com.androdr.data.model.ImportedDnsEvent
import com.androdr.data.model.SecurityLogEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TombstoneEvent
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

/**
 * E1, engine half: the typed `evaluate*` entry points and [SigmaRuleEngine.evaluateRecords]
 * evaluate the same maps, and every finding carries the ordinal of its record.
 */
class EvaluateRecordsTest {

    private lateinit var engine: SigmaRuleEngine

    /** A never-matching rule that reports safe state: one finding per evaluated record. */
    private fun perRecordRule(service: String) = SigmaRule(
        id = "test-$service", title = "per record", status = "production",
        description = "", product = "androdr", service = service, level = "low",
        category = RuleCategory.INCIDENT, tags = emptyList(),
        detection = SigmaDetection(
            selections = mapOf(
                "selection" to SigmaSelection(
                    fieldMatchers = listOf(
                        SigmaFieldMatcher("no_such_field", SigmaModifier.EQUALS, listOf("x"))
                    )
                )
            ),
            condition = "selection",
        ),
        falsepositives = emptyList(), remediation = emptyList(),
        display = SigmaDisplay(category = FindingCategory.DEVICE_POSTURE),
        reportSafeState = true,
    )

    @Before
    fun setUp() {
        engine = SigmaRuleEngine(mockk<Context>(relaxed = true))
        val rules = listOf(
            "file_scanner", "dns_monitor", "tombstone_parser", "security_log",
        ).map { perRecordRule(it) }
        for (field in listOf("bundledRules", "rules")) {
            SigmaRuleEngine::class.java.getDeclaredField(field).apply { isAccessible = true }
                .set(engine, rules)
        }
    }

    private fun file(path: String, accessible: Boolean = true) = FileArtifactTelemetry(
        filePath = path, fileExists = true, fileSize = 1L, fileModified = 2L,
        source = TelemetrySource.LIVE_SCAN, accessible = accessible,
    )

    private fun dns(domain: String) = DnsEvent(
        timestamp = 5L, domain = domain, appUid = 1, appName = "a", isBlocked = false, reason = null,
    )

    @Test
    fun `live builder maps equal toFieldMap element by element`() {
        val dnsEvents = listOf(dns("a.example"), dns("b.example"))
        assertEquals(
            dnsEvents.map { it.toFieldMap() },
            LiveRecordBuilders.dns(dnsEvents).map { it.fields },
        )
        val files = listOf(file("/a"), file("/b", accessible = false))
        assertEquals(files.map { it.toFieldMap() }, LiveRecordBuilders.files(files).map { it.fields })
    }

    @Test
    fun `bug report and intrusion log builders equal toFieldMap`() {
        val tomb = listOf(
            TombstoneEvent("p", null, 6, "m", 9L, TelemetrySource.BUGREPORT_IMPORT, 10L)
        )
        assertEquals(
            tomb.map { it.toFieldMap() },
            BugReportRecordBuilders.tombstones(tomb).map { it.fields },
        )
        val generic = listOf(mapOf<String, Any?>("k" to "v"))
        assertEquals(generic, BugReportRecordBuilders.generic(generic).map { it.fields })
        val imported = listOf(ImportedDnsEvent(dns("c.example"), listOf("1.2.3.4")))
        assertEquals(
            imported.map { it.toFieldMap() },
            IntrusionLogRecordBuilders.importedDns(imported).map { it.fields },
        )
        val sec = listOf(SecurityLogEvent(1L, 2, "t", listOf("d"), TelemetrySource.BUGREPORT_IMPORT, 3L))
        assertEquals(
            sec.map { it.toFieldMap() },
            IntrusionLogRecordBuilders.securityLog(sec).map { it.fields },
        )
    }

    @Test
    fun `typed entry point gives the findings evaluateRecords gives, with ordinals`() {
        val events = listOf(dns("a.example"), dns("b.example"), dns("c.example"))
        val typed = engine.evaluateDns(events)
        val direct = engine.evaluateRecords("dns_monitor", LiveRecordBuilders.dns(events), 0)
        assertEquals(direct, typed)
        assertEquals(listOf(0, 1, 2), typed.map { it.ordinal })
        assertEquals(listOf("dns_monitor"), typed.map { it.service }.distinct())
    }

    @Test
    fun `firstOrdinal offsets every finding`() {
        val events = listOf(dns("a.example"), dns("b.example"))
        val findings = engine.evaluateRecords("dns_monitor", LiveRecordBuilders.dns(events), 40)
        assertEquals(listOf(40, 41), findings.map { it.ordinal })
    }

    @Test
    fun `an inaccessible file at index 0 still consumes ordinal 0`() {
        val findings = engine.evaluateFiles(listOf(file("/hidden", accessible = false), file("/seen")))
        assertEquals(1, findings.size)
        assertEquals(1, findings.single().ordinal)
        assertEquals("file_scanner", findings.single().service)
    }

    @Test
    fun `evaluate include predicate skips a record but keeps its ordinal`() {
        val rule = perRecordRule("dns_monitor")
        val records = listOf(mapOf<String, Any?>("a" to 1), mapOf("a" to 2), mapOf("a" to 3))
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(rule), records, "dns_monitor", firstOrdinal = 10, include = { it != 1 },
        )
        assertEquals(listOf(10, 12), findings.map { it.ordinal })
    }
}

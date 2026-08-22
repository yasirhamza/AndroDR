package com.androdr.scanner.intrusionlog

import com.androdr.scanner.ArtifactSniffer
import com.androdr.scanner.ArtifactType
import com.androdr.scanner.IntrusionLogAnalyzer
import com.androdr.sigma.SigmaRule
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleEvaluator
import com.androdr.sigma.SigmaRuleParser
import com.androdr.sigma.toFieldMap
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

class IntrusionLogEndToEndTest {

    /**
     * Build an export ZIP in memory: two per-day files with an overlapping event,
     * plus a third entry one directory deep (covers androidqf's intrusion-logs/
     * layout) with its own unique dns_event — a regression guard for the
     * depth-inclusion rule in ArtifactSniffer/IntrusionLogAnalyzer.
     */
    private fun exportZip(): ByteArray {
        val day1 = listOf(
            """{"dns_event":{"event_id":0,"event_time":1787400345334,"package_name":"com.evil.app",""" +
                """"hostname":"api.flexispy.com","ip_addresses":["/34.160.125.113"],"ip_addresses_count":1}}""",
            """{"connect_event":{"event_id":1,"event_time":1787400345540,"package_name":"com.evil.app",""" +
                """"port":5555,"ip_address":"/192.168.1.7"}}""",
        )
        val day2 = listOf(
            """{"connect_event":{"event_id":1,"event_time":1787400345540,"package_name":"com.evil.app",""" +
                """"port":5555,"ip_address":"/192.168.1.7"}}""",
            """{"security_event":{"event_id":2,"event_time":1787400350000,"tag":210002,""" +
                """"data":["pm install /data/local/tmp/x.apk"]}}""",
        )
        val deepDay = listOf(
            """{"dns_event":{"event_id":10,"event_time":1787400340000,"package_name":"com.deep.app",""" +
                """"hostname":"deep.example.com","ip_addresses":["/9.9.9.9"],"ip_addresses_count":1}}""",
        )
        val bytes = ByteArrayOutputStream()
        ZipOutputStream(bytes).use { zip ->
            for ((name, lines) in listOf(
                "2026-08-21.txt" to day1,
                "2026-08-22.txt" to day2,
                "intrusion-logs/2026-08-20.txt" to deepDay,
            )) {
                zip.putNextEntry(ZipEntry(name))
                zip.write(lines.joinToString("\n").toByteArray())
                zip.closeEntry()
            }
        }
        return bytes.toByteArray()
    }

    private fun zipEntries(bytes: ByteArray) = sequence {
        val zip = ZipInputStream(ByteArrayInputStream(bytes))
        var entry = zip.nextEntry
        while (entry != null) {
            if (!entry.isDirectory) yield(entry.name to (zip as java.io.InputStream))
            zip.closeEntry()
            entry = zip.nextEntry
        }
    }

    @Test
    fun `sniffer classifies the export as an intrusion log`() {
        val names = zipEntries(exportZip()).map { it.first }.toList()
        assertEquals(ArtifactType.INTRUSION_LOG, ArtifactSniffer.classify(names.asSequence()))
    }

    @Test
    fun `full pipeline - parse, dedup, and fire rules on all three services`() {
        val dnsRule = buildDnsRule()
        val netRule = buildNetRule()
        val secRule = buildSecRule()
        // Engine mock delegates to the real evaluator with the inline rules —
        // this keeps the test JVM-only while exercising real matching.
        val engine = mockEngine(dnsRule, netRule, secRule)

        val result = IntrusionLogAnalyzer(mockk(relaxed = true), engine).analyzeEntries(
            zipEntries(exportZip()), uidResolver = { -1 }, capturedAt = 1_787_400_400_000L
        )

        // dnsEventCount is 2: the top-level flexispy event AND the one-dir-deep
        // "intrusion-logs/2026-08-20.txt" event — regression guard for the
        // depth-inclusion rule (`<= 1` slashes) in ArtifactSniffer /
        // IntrusionLogAnalyzer. A tightened rule (e.g. `< 1`) would drop the
        // deep entry and turn this red.
        assertEquals(2, result.stats.dnsEventCount)
        assertEquals(1, result.stats.connectEventCount)      // event_id 1 deduped across files
        assertEquals(1, result.stats.securityEventCount)
        assertEquals(1, result.stats.duplicatesCollapsed)
        assertTrue(result.dnsEvents.any { it.event.domain == "deep.example.com" })
        // The dns rule only matches flexispy.com, so the deep event does not
        // add a fourth triggered finding — triggered-findings counts are
        // unchanged from the two-file baseline.
        assertEquals(3, result.findings.count { it.triggered })
        assertTrue(result.findings.any { it.ruleId == "androdr-e2e-dns" && it.triggered })
        assertTrue(result.findings.any { it.ruleId == "androdr-e2e-net" && it.triggered })
        assertTrue(result.findings.any { it.ruleId == "androdr-e2e-sec" && it.triggered })
    }

    private fun buildDnsRule(): SigmaRule = SigmaRuleParser.parse(
        """
            title: Stalkerware C2 domain
            id: androdr-e2e-dns
            status: experimental
            description: Test
            category: incident
            logsource:
                product: androdr
                service: dns_monitor
            detection:
                selection:
                    domain|contains:
                        - flexispy.com
                condition: selection
            level: high
            tags:
                - attack.t1437
        """.trimIndent()
    )!!

    private fun buildNetRule(): SigmaRule = SigmaRuleParser.parse(
        """
            title: ADB over TCP connect
            id: androdr-e2e-net
            status: experimental
            description: Test
            category: incident
            logsource:
                product: androdr
                service: network_monitor
            detection:
                selection:
                    destination_port: 5555
                condition: selection
            level: medium
            tags:
                - attack.t1021
        """.trimIndent()
    )!!

    private fun buildSecRule(): SigmaRule = SigmaRuleParser.parse(
        """
            title: ADB shell command observed
            id: androdr-e2e-sec
            status: experimental
            description: Test
            category: incident
            logsource:
                product: androdr
                service: security_log
            detection:
                selection:
                    tag_name: adb_shell_cmd
                condition: selection
            level: low
            tags:
                - attack.t1059
        """.trimIndent()
    )!!

    private fun mockEngine(dnsRule: SigmaRule, netRule: SigmaRule, secRule: SigmaRule): SigmaRuleEngine {
        val engine = mockk<SigmaRuleEngine>(relaxed = true)
        every { engine.evaluateDns(any()) } answers {
            SigmaRuleEvaluator.evaluate(
                listOf(dnsRule),
                firstArg<List<com.androdr.data.model.DnsEvent>>().map { it.toFieldMap() },
                "dns_monitor", emptyMap(), emptyMap()
            )
        }
        every { engine.evaluateNetwork(any()) } answers {
            SigmaRuleEvaluator.evaluate(
                listOf(netRule),
                firstArg<List<com.androdr.data.model.NetworkTelemetry>>().map { it.toFieldMap() },
                "network_monitor", emptyMap(), emptyMap()
            )
        }
        every { engine.evaluateSecurityLog(any()) } answers {
            SigmaRuleEvaluator.evaluate(
                listOf(secRule),
                // SecurityLogEvent.toFieldMap() is internal to com.androdr.sigma,
                // but the unit-test source set is a friend module, so the real
                // extension is directly callable — no hand-copied mirror needed.
                firstArg<List<com.androdr.data.model.SecurityLogEvent>>().map { it.toFieldMap() },
                "security_log", emptyMap(), emptyMap()
            )
        }
        return engine
    }
}

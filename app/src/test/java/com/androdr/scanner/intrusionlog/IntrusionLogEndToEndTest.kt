package com.androdr.scanner.intrusionlog

import android.net.Uri
import com.androdr.scanner.ArtifactSniffer
import com.androdr.scanner.ArtifactType
import com.androdr.scanner.IntrusionLogZips
import com.androdr.sigma.SigmaRule
import com.androdr.sigma.SigmaRuleParser
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

@RunWith(RobolectricTestRunner::class)
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

    /** The real analyzer, writer session and store: the cross-file duplicate collapses in the store. */
    @Test
    fun `full pipeline - parse, dedup, and fire rules on all three services`() = runBlocking {
        val engine = IntrusionLogZips.engine(buildDnsRule(), buildNetRule(), buildSecRule())
        val zip = exportZip()
        IntrusionLogZips.fixture(engine) { zip }.use { f ->
            val result = f.orchestrator.analyzeIntrusionLog(mockk<Uri>(relaxed = true))

            // dnsEventCount is 2: the top-level flexispy event AND the one-dir-deep
            // "intrusion-logs/2026-08-20.txt" event — regression guard for the
            // depth-inclusion rule (`<= 1` slashes) in ArtifactSniffer /
            // IntrusionLogAnalyzer. A tightened rule (e.g. `< 1`) would drop the
            // deep entry and turn this red.
            assertEquals(2, result.stats.dnsEventCount)
            assertEquals(1, result.stats.connectEventCount)      // event_id 1 deduped across files
            assertEquals(1, result.stats.securityEventCount)
            assertEquals(1, result.stats.duplicatesCollapsed)
            assertEquals("one observation per distinct record", 4L, f.count("SELECT COUNT(*) FROM scan_record"))
            // C3: the deep event is a stored fact (the Timeline reads it from the store), not a row.
            val dnsFacts = f.db.openHelper.readableDatabase
                .query("SELECT id FROM telemetry_record WHERE service = 'dns_monitor'")
                .use { c -> generateSequence { if (c.moveToNext()) c.getLong(0) else null }.toList() }
            assertTrue(f.w.f.reader.records(dnsFacts).any { it.fields?.get("domain") == "deep.example.com" })
            // The dns rule only matches flexispy.com, so the deep event does not
            // add a fourth triggered finding; the duplicate connect adds no second one.
            assertEquals(3, result.findings.count { it.triggered })
            assertEquals(3, result.stats.triggeredFindingCount)
            assertTrue(result.findings.any { it.ruleId == "androdr-e2e-dns" && it.triggered })
            assertTrue(result.findings.any { it.ruleId == "androdr-e2e-net" && it.triggered })
            assertTrue(result.findings.any { it.ruleId == "androdr-e2e-sec" && it.triggered })
        }
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
            display:
                category: app_risk
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
            display:
                category: app_risk
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
            display:
                category: app_risk
        """.trimIndent()
    )!!
}

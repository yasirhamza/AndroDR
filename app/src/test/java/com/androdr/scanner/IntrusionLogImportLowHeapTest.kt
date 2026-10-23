package com.androdr.scanner

import android.net.Uri
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Low heap (telemetry store §9, spec §5.2): a 200,000-line intrusion log imports within a 256 MB heap,
 * because nothing holds the whole import — records stream through the session in chunks, and only
 * the bounded heaps and the findings top-K survive a chunk. Runs only in the `lowHeapTest` Gradle
 * task (`maxHeapSize = "256m"`); `testDebugUnitTest` excludes `*LowHeap*`.
 */
@RunWith(RobolectricTestRunner::class)
class IntrusionLogImportLowHeapTest {

    /** Streams the export to a temp file: the test itself must not hold the 200,000 lines either. */
    private fun export(lines: Int): File {
        val file = File.createTempFile("intrusion-low-heap", ".zip")
        ZipOutputStream(file.outputStream().buffered()).use { zip ->
            var n = 0
            var day = 0
            while (n < lines) {
                zip.putNextEntry(ZipEntry("2026-08-%02d.txt".format(1 + day++)))
                val writer = zip.bufferedWriter()
                repeat(minOf(PER_DAY, lines - n)) {
                    val t = 1_787_000_000_000L + n
                    writer.write(when (n % 3) {
                        0 -> """{"dns_event":{"event_id":$n,"event_time":$t,"package_name":"com.app${n % 97}",""" +
                            """"hostname":"h$n.example.com","ip_addresses":["/10.0.${n % 250}.1"]}}"""
                        1 -> """{"connect_event":{"event_id":$n,"event_time":$t,"package_name":"com.app${n % 97}",""" +
                            """"port":${443 + n % 7},"ip_address":"/10.1.${n % 250}.2"}}"""
                        else -> """{"security_event":{"event_id":$n,"event_time":$t,""" +
                            """"${if (n % 50 == 2) "hit_cmd" else "other"}":{"seq":$n}}}"""
                    })
                    writer.write("\n")
                    n++
                }
                writer.flush()
                zip.closeEntry()
            }
        }
        return file
    }

    @Test
    fun `a 200,000-line intrusion log imports under 256 MB`() = runBlocking {
        assertTrue("run through the lowHeapTest task (max heap ${Runtime.getRuntime().maxMemory() shr 20} MB)",
            Runtime.getRuntime().maxMemory() <= HEAP_CEILING)
        val file = export(LINES)
        val engine = IntrusionLogZips.engine(
            IntrusionLogZips.rule("androdr-lh-sec", "security_log", "tag_name", "hit_cmd", "high"))
        val context = OrchestratorFixture.serving { file.inputStream() }
        try {
            OrchestratorFixture(
                engine = engine, intrusionLogAnalyzer = IntrusionLogAnalyzer(context, mockk(relaxed = true)),
                recordSql = false,
            ).use { f ->
                val result = f.orchestrator.analyzeIntrusionLog(mockk<Uri>(relaxed = true))

                assertEquals(LINES.toLong(), f.count("SELECT COUNT(*) FROM scan_record"))
                assertEquals(LINES / 3 + 1, result.stats.dnsEventCount)
                assertEquals(0, result.stats.malformedLines)
                val hits = (0 until LINES).count { it % 3 == 2 && it % 50 == 2 }
                assertEquals(hits, result.stats.triggeredFindingCount)
                assertEquals("every finding is stored, none capped (D2)", hits.toLong(),
                    f.count("SELECT COUNT(*) FROM scan_finding WHERE triggered = 1"))
                assertEquals("events are store-only: the rows are the finding rows (C3)",
                    hits.toLong(), f.count("SELECT COUNT(*) FROM forensic_timeline"))
                assertEquals("nothing is held in memory for an import", 0, result.write!!.findings.size)
            }
        } finally {
            file.delete()
        }
    }

    private companion object {
        const val LINES = 200_000
        const val PER_DAY = 8_192
        /** 256 MB plus slack for how the JVM reports `-Xmx`. */
        const val HEAP_CEILING = 280L shl 20
    }
}

package com.androdr.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The ioc_match provider reads domain rows from the prefetch cache (the VPN path
 * must stay off Room, #71). A DNS evaluation without a prefetch first yields
 * findings that cannot name their family. DNS is evaluated when its chunk is appended to a writer
 * session (telemetry store §4.1), so every place that hands DNS records to a session — the live
 * scan's `appendAll(LiveRecordBuilders.DNS_MONITOR` and the intrusion-log analyzer's `chunks.dns(` —
 * must prefetch earlier in the same file. A new caller fails here until it is reviewed and added to
 * [KNOWN_CALLERS]; direct `evaluate*` calls are gated by WriterEvaluationGateTest.
 */
class DnsEvaluationPrefetchTest {
    private val root = listOf(File("app/src/main/java"), File("src/main/java")).first { it.isDirectory }

    @Test
    fun `every evaluateDns caller prefetches domain indicators first`() {
        val callers = root.walkTopDown().filter { it.isFile && it.extension == "kt" }
            .filter { f -> CALLS.any { it in f.readText() } }.toList()
        assertEquals(KNOWN_CALLERS, callers.map { it.name }.toSet())
        for (f in callers) {
            val text = f.readText()
            for (call in CALLS) {
                var at = text.indexOf(call)
                while (at >= 0) {
                    val prefetch = text.lastIndexOf(PREFETCH, at)
                    assertTrue("${f.name}: $call at offset $at has no earlier $PREFETCH", prefetch in 0 until at)
                    at = text.indexOf(call, at + 1)
                }
            }
        }
    }

    private companion object {
        val CALLS = listOf("appendAll(LiveRecordBuilders.DNS_MONITOR", "chunks.dns(")
        const val PREFETCH = "prefetchDomainIndicators("
        val KNOWN_CALLERS = setOf("WriterSessions.kt", "IntrusionLogAnalyzer.kt")
    }
}

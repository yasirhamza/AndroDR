package com.androdr.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The ioc_match provider reads domain rows from the prefetch cache (the VPN path
 * must stay off Room, #71). A DNS evaluation without a prefetch first yields
 * findings that cannot name their family, so every caller of `evaluateDns` must
 * prefetch earlier in the same file. A new caller fails here until it is
 * reviewed and added to [KNOWN_CALLERS].
 */
class DnsEvaluationPrefetchTest {
    private val root = listOf(File("app/src/main/java"), File("src/main/java")).first { it.isDirectory }

    @Test
    fun `every evaluateDns caller prefetches domain indicators first`() {
        val callers = root.walkTopDown().filter { it.isFile && it.extension == "kt" }
            .filter { CALL in it.readText() }.toList()
        assertEquals(KNOWN_CALLERS, callers.map { it.name }.toSet())
        for (f in callers) {
            val text = f.readText()
            var at = text.indexOf(CALL)
            while (at >= 0) {
                val prefetch = text.lastIndexOf(PREFETCH, at)
                assertTrue("${f.name}: evaluateDns at offset $at has no earlier $PREFETCH", prefetch in 0 until at)
                at = text.indexOf(CALL, at + 1)
            }
        }
    }

    private companion object {
        const val CALL = ".evaluateDns("
        const val PREFETCH = "prefetchDomainIndicators("
        val KNOWN_CALLERS = setOf("ScanOrchestrator.kt", "IntrusionLogAnalyzer.kt")
    }
}

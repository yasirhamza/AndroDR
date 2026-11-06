package com.androdr.util

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/**
 * Network bodies are read through [readTextCapped], never `readText()`: `readText()`
 * buffers the whole body before any size check can run, so an endless or oversized
 * response is an OutOfMemoryError however carefully the caller compares lengths
 * afterwards (PASTA F-003/F-005; quality review item 5).
 *
 * Scope: the fetchers this gate has been applied to. Add a file here when it is
 * migrated; the remaining feeds are tracked as a follow-up.
 */
class NetworkBodyReadGateTest {

    private val guarded = listOf(
        "ioc/SafeHttpFetch.kt",
        "sigma/SigmaRuleFeed.kt",
        "ioc/feeds/MvtIndicatorsFeed.kt",
        "data/repo/CveRepository.kt",
    )

    @Test
    fun `guarded fetchers read network bodies only through readTextCapped`() {
        val offenders = guarded.flatMap { rel ->
            val f = listOf(File("src/main/java/com/androdr/$rel"), File("app/src/main/java/com/androdr/$rel"))
                .first { it.isFile }
            val lines = f.readLines()
            lines.mapIndexedNotNull { i, line ->
                // A bundled raw resource is not a network body; its read may stay uncapped.
                val bundled = (maxOf(0, i - 1)..i).any { lines[it].contains("openRawResource") }
                if (line.contains(".readText()") && !bundled) "$rel:${i + 1}: ${line.trim()}" else null
            }
        }
        assertEquals("uncapped readText() on a network body", emptyList<String>(), offenders)
    }
}

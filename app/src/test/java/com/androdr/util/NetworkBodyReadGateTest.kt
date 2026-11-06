package com.androdr.util

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/**
 * Network bodies are read through [readTextCapped], never `readText()`/`readBytes()`/
 * `readLines()`: those buffer the whole body before any size check can run, so an
 * endless or oversized response is an OutOfMemoryError however carefully the caller
 * compares lengths afterwards (PASTA F-003/F-005).
 *
 * Every file under `src/main` that opens an HTTP connection is in scope, so a NEW
 * fetcher written with `readText()` fails here by default. [knownUncapped] lists the
 * fetchers not yet migrated (tracked follow-up); the second assertion fails when
 * one of them is migrated and left in the list, so the list only shrinks.
 */
class NetworkBodyReadGateTest {

    private val knownUncapped = setOf(
        "ioc/feeds/HaGeZiTifFeed.kt",
        "ioc/feeds/PlexusKnownAppFeed.kt",
        "ioc/feeds/StalkerwareCertHashFeed.kt",
        "ioc/feeds/StalkerwareIndicatorsFeed.kt",
        "ioc/feeds/UadKnownAppFeed.kt",
        "ioc/feeds/ZimperiumIocFeed.kt",
    )

    private val uncappedRead = Regex("""\.(readText|readBytes|readLines)\(""")
    // Any way this codebase could open a network stream; a fetcher written another way is in scope too.
    private val opensHttp = Regex("""HttpURLConnection|openConnection\(\)|openStream\(\)|java\.net\.URL\b|okhttp""")

    private fun offenders(): Map<String, List<String>> {
        val root = listOf(File("src/main/java/com/androdr"), File("app/src/main/java/com/androdr"))
            .first { it.isDirectory }
        return root.walkTopDown().filter { it.isFile && it.extension == "kt" }
            .filter { opensHttp.containsMatchIn(it.readText()) }
            .associate { f ->
                val lines = f.readLines()
                val hits = lines.mapIndexedNotNull { i, line ->
                    // A bundled raw resource is not a network body; its read may stay uncapped.
                    val bundled = (maxOf(0, i - 1)..i).any { "openRawResource" in lines[it] || "R.raw." in lines[it] }
                    if (uncappedRead.containsMatchIn(line) && !bundled) "${i + 1}: ${line.trim()}" else null
                }
                f.relativeTo(root).path to hits
            }
            .filterValues { it.isNotEmpty() }
    }

    @Test
    fun `every HTTP fetcher reads bodies only through readTextCapped, except the listed follow-ups`() {
        val unexpected = offenders().filterKeys { it !in knownUncapped }
        assertEquals("uncapped body read in a fetcher not on the follow-up list", emptyMap<String, Any>(), unexpected)
    }

    @Test
    fun `the follow-up list names only fetchers that are still uncapped`() {
        val stale = knownUncapped - offenders().keys
        assertEquals("migrated fetcher still listed as a follow-up", emptySet<String>(), stale)
    }
}

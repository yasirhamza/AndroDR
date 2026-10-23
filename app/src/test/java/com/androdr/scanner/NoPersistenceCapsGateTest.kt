package com.androdr.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * C1 (spec §5.5, §9): no persistence cap anywhere in the scan → store → Timeline path. Every match of
 * the cap pattern in `main` must be on the Phase C allow-list: the permanent ones
 * (`ScanResultDao.getLatestTwo`, `IndicatorDao.lookup`, the DNS monitor's
 * `DnsEventDao.getRecentEvents` / `getRecentSnapshot`) and the two D2 removes
 * (`FINDINGS_PERSIST_CAP`, `ScanResultDao.getAllScans`).
 */
class NoPersistenceCapsGateTest {

    private val cap = Regex("""_PERSIST_CAP|_ROW_LIMIT|\bLIMIT\s+\d+|limit:\s*Int\s*=\s*\d+""")

    /** Allowed queries, as `Owner.function` of the `@Query` (or function) the match belongs to. */
    private val allowedFunctions = setOf(
        "ScanResultDao.getLatestTwo", "IndicatorDao.lookup",
        "DnsEventDao.getRecentEvents", "DnsEventDao.getRecentSnapshot",
        "ScanResultDao.getAllScans",
    )

    /** Allowed identifiers: the interim findings top-K cap, removed in D2. */
    private val allowedNames = setOf("FINDINGS_PERSIST_CAP")

    private fun root(): File = listOf(File("src/main/java/com/androdr"), File("app/src/main/java/com/androdr"))
        .first { it.isDirectory }

    private val funRe = Regex("""\bfun\s+(\w+)""")

    /** A declaration at the start of a line (so "class" or "object" in a KDoc sentence is not one). */
    private val ownerRe = Regex(
        """^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:private|internal|public|abstract|open|data|sealed|enum)\s+)*""" +
            """(?:interface|class|object)\s+(\w+)""",
        RegexOption.MULTILINE,
    )
    private val wordRe = Regex("""\w*$""")

    /**
     * Each disallowed match in [src] (file [name]) as `name:line: text`. A match inside an
     * annotation (`@Query(…)` after the previous `fun`) belongs to the function it annotates; any
     * other match belongs to the function whose body encloses it.
     */
    private fun violations(name: String, src: String): List<String> = cap.findAll(src).mapNotNull { m ->
        val before = src.substring(0, m.range.first)
        val word = wordRe.find(before)!!.value + m.value
        if (word in allowedNames) return@mapNotNull null
        val owner = ownerRe.findAll(before).lastOrNull()?.groupValues?.get(1) ?: "?"
        val lastFun = funRe.findAll(before).lastOrNull()
        val inAnnotation = before.lastIndexOf("@Query(") > (lastFun?.range?.first ?: -1)
        val fn = if (inAnnotation) funRe.find(src, m.range.first)?.groupValues?.get(1) else lastFun?.groupValues?.get(1)
        if ("$owner.$fn" in allowedFunctions) return@mapNotNull null
        val line = before.count { it == '\n' } + 1
        "$name:$line: ${m.value} ($owner.$fn)"
    }.toList()

    @Test
    fun `no persistence cap outside the Phase C allow-list`() {
        val files = root().walkTopDown().filter { it.extension == "kt" }.toList()
        assertTrue(files.size > 100)
        val bad = files.flatMap { violations(it.name, it.readText()) }
        assertTrue("persistence caps (spec §5.5):\n" + bad.joinToString("\n"), bad.isEmpty())
    }

    @Test
    fun `the gate sees each cap shape and honours the allow-list`() {
        val src = """
            interface FooDao {
                @Query("SELECT * FROM t ORDER BY x LIMIT 500")
                fun recent(): List<X>
                fun page(limit: Int = 200): List<X>
            }
            object Caps { const val DNS_PERSIST_CAP = 1; const val INTRUSION_ROW_LIMIT = 2 }
            /** This class holds an object. */
            interface ScanResultDao {
                fun helper() { db.query("SELECT * FROM t LIMIT 3") }
                @Query("SELECT * FROM ScanResult LIMIT 2")
                fun getLatestTwo(): List<X>
            }
            val k = ScanOrchestrator.FINDINGS_PERSIST_CAP
        """.trimIndent()
        assertEquals(listOf("LIMIT 500", "limit: Int = 200", "_PERSIST_CAP", "_ROW_LIMIT", "LIMIT 3"),
            violations("F.kt", src).map { it.substringAfter(": ").substringBefore(" (") })
        assertEquals("a body match belongs to its enclosing function, under the real owner",
            "ScanResultDao.helper", violations("F.kt", src).last().substringAfter("(").substringBefore(")"))
    }
}

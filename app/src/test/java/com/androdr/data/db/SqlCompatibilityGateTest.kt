package com.androdr.data.db

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Q1 gates for the minSdk-26 SQLite (3.18-era) and its 999 bound-variable limit.
 *
 * Syntax: SQL string literals in the data/db Kotlin sources must not use syntax newer than API 26's SQLite.
 * Parameters: every @Query function taking a List/Collection must only be called inside
 * [chunkedIn] / [chunkedEach], so the bound-variable count stays under the limit.
 */
class SqlCompatibilityGateTest {

    private val forbidden = listOf(
        "ON CONFLICT", "RETURNING", "OVER (", "NULLS LAST", "NULLS FIRST",
        "DROP COLUMN", "RENAME COLUMN", "IIF(", "->>", "FILTER ("
    )

    /**
     * Pre-existing violations, each pinned to its exact literal. MIGRATION_11_12 (sprint #75)
     * renames a column, which needs SQLite 3.25 (API 30): a database still at schema 11 on
     * API 26-29 would crash there. Known debt, reported rather than fixed here; remove the
     * entry together with the fix. [allowlist entries are all still present] keeps it honest.
     */
    private val knownLegacyViolations = setOf(
        "Migrations.kt" to "ALTER TABLE forensic_timeline RENAME COLUMN timestamp TO startTimestamp"
    )

    @Test
    fun `sql literals in data db use only API 26 SQLite syntax`() {
        val files = dbSources()
        assertTrue("no data/db sources found", files.isNotEmpty())
        val violations = files.flatMap { f ->
            stringLiterals(f.readText()).flatMap { lit ->
                forbidden.filter { lit.uppercase().contains(it) }
                    .filter { (f.name to lit) !in knownLegacyViolations }
                    .map { "${f.name}: '$it' in \"${lit.take(60)}\"" }
            }
        }
        assertTrue("SQL needing newer SQLite than API 26:\n" + violations.joinToString("\n"), violations.isEmpty())
    }

    @Test
    fun `allowlist entries are all still present`() {
        for ((name, literal) in knownLegacyViolations) {
            val f = dbSources().single { it.name == name }
            assertTrue("stale allowlist entry: $literal", literal in stringLiterals(f.readText()))
        }
    }

    @Test
    fun `syntax gate detects each forbidden construct`() {
        for (token in forbidden) {
            val src = "const val Q = \"SELECT 1 $token x\""
            val lits = stringLiterals(src)
            assertTrue("literal not extracted for $token", lits.any { it.uppercase().contains(token) })
        }
        assertEquals(listOf("a b", "c\nd"), stringLiterals("val x = \"a b\"\nval y = \"\"\"c\nd\"\"\""))
    }

    @Test
    fun `list-parameter queries are only called inside chunkedIn or chunkedEach`() {
        val listQueries = dbSources().flatMap { listParamQueryNames(it.readText()) }
        val violations = mainSources().flatMap { f ->
            unchunkedCalls(f.readText(), listQueries).map { "${f.name}: $it" }
        }
        assertTrue("list-bound @Query called outside chunkedIn/chunkedEach:\n" + violations.joinToString("\n"),
            violations.isEmpty())
    }

    @Test
    fun `parameter gate detects unchunked calls and accepts chunked ones`() {
        val dao = "@Dao interface D {\n @Query(\"SELECT * FROM t WHERE id IN (:ids)\")\n" +
            " suspend fun byIds(ids: List<Long>): List<T>\n" +
            " @Query(\"SELECT 1\")\n suspend fun one(): Int\n @Insert suspend fun ins(x: List<T>)\n}"
        assertEquals(listOf("byIds"), listParamQueryNames(dao))
        // A multi-line @Query( "..." + "..." ) is recognised too.
        val multi = "@Query(\n  \"SELECT * FROM t \" +\n  \"WHERE id IN (:ids)\"\n)\n" +
            "suspend fun many(ids: List<Long>): List<T>"
        assertEquals(listOf("many"), listParamQueryNames(multi))
        assertEquals(listOf("byIds"), unchunkedCalls("val r = dao.byIds(keys)", listOf("byIds")))
        val ok = "val r = chunkedIn(keys) { c ->\n dao.byIds(c)\n}"
        assertTrue(unchunkedCalls(ok, listOf("byIds")).isEmpty())
        val nested = "chunkedEach(keys, 500) { c -> if (c.isNotEmpty()) { dao.byIds(c) } }"
        assertTrue(unchunkedCalls(nested, listOf("byIds")).isEmpty())
        assertEquals(listOf("byIds"), unchunkedCalls("chunkedIn(a) { dao.one() }\ndao.byIds(b)", listOf("byIds")))
    }

    private fun root(): File = listOf(File("src/main/java/com/androdr"), File("app/src/main/java/com/androdr"))
        .first { it.isDirectory }

    private fun dbSources(): List<File> = File(root(), "data/db").listFiles { f -> f.extension == "kt" }!!.toList()

    private fun mainSources(): List<File> = root().walkTopDown().filter { it.extension == "kt" }.toList()

    /** Contents of every "..." and """...""" literal (escapes left as written). */
    private fun stringLiterals(src: String): List<String> =
        Regex("\"\"\"([\\s\\S]*?)\"\"\"|\"((?:[^\"\\\\\\n]|\\\\.)*)\"")
            .findAll(src).map { it.groups[1]?.value ?: it.groups[2]!!.value }.toList()

    private fun listParamQueryNames(src: String): List<String> {
        val quoted = "\"(?:[^\"\\\\]|\\\\.)*\""
        val re = Regex(
            "@Query\\(\\s*(?:\"\"\"[\\s\\S]*?\"\"\"|$quoted)(?:\\s*\\+\\s*$quoted)*\\s*\\)\\s*" +
                "(?:@\\w+\\s*)*(?:suspend\\s+)?fun\\s+(\\w+)\\s*\\(([^)]*)\\)"
        )
        val listy = Regex("(?:vararg\\s|:\\s*(?:List|Collection|Set|Iterable|Array)<)")
        return re.findAll(src).filter { listy.containsMatchIn(it.groupValues[2]) }.map { it.groupValues[1] }.toList()
    }

    /** Offsets covered by the argument list of every chunkedIn/chunkedEach call. */
    private fun chunkedRanges(src: String): List<IntRange> = Regex("chunked(?:In|Each)\\s*[({]").findAll(src).map { m ->
        val open = m.range.last
        var depth = 0
        var i = open
        while (i < src.length) {
            when (src[i]) {
                '(', '{' -> depth++
                ')', '}' -> if (--depth == 0) break
            }
            i++
        }
        // chunkedIn(keys) { ... }: the trailing lambda follows the closing paren.
        var end = i
        if (src[open] == '(') {
            val rest = Regex("^\\s*\\{").find(src.substring(minOf(i + 1, src.length)))
            if (rest != null) {
                var d = 0
                var j = i + 1 + rest.range.last
                while (j < src.length) {
                    when (src[j]) { '{' -> d++; '}' -> if (--d == 0) break }
                    j++
                }
                end = j
            }
        }
        open..end
    }.toList()

    private fun unchunkedCalls(src: String, names: List<String>): List<String> {
        if (names.isEmpty()) return emptyList()
        val ranges = chunkedRanges(src)
        val call = Regex("\\.(" + names.joinToString("|") + ")\\s*\\(")
        return call.findAll(src).filter { m -> ranges.none { m.range.first in it } }.map { it.groupValues[1] }.toList()
    }
}

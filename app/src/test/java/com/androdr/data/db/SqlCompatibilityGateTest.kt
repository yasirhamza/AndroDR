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
                forbiddenIn(lit)
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
            assertTrue("literal not extracted for $token", lits.any { token in forbiddenIn(it) })
        }
        assertEquals(listOf("a b", "c\nd"), stringLiterals("val x = \"a b\"\nval y = \"\"\"c\nd\"\"\""))
    }

    @Test
    fun `syntax gate ignores whitespace and case around a forbidden construct`() {
        // OVER( / FILTER( with no space, a line break before the paren and lower case are the same
        // SQL as OVER ( / FILTER (; a plain substring match on "OVER (" missed them.
        assertEquals(listOf("OVER ("), forbiddenIn("SELECT row_number() OVER(ORDER BY id) FROM t"))
        assertEquals(listOf("FILTER ("), forbiddenIn("SELECT count(*) filter(WHERE x) FROM t"))
        assertEquals(listOf("OVER ("), forbiddenIn("SELECT sum(x) over\n  (PARTITION BY y) FROM t"))
        assertEquals(listOf("OVER ("), forbiddenIn("SELECT sum(x) over\\n(PARTITION BY y) FROM t"))
        assertEquals(listOf("ON CONFLICT"), forbiddenIn("INSERT INTO t VALUES (1) ON  CONFLICT DO NOTHING"))
        assertEquals(listOf("IIF("), forbiddenIn("SELECT iif (a, b, c) FROM t"))
        assertEquals(emptyList<String>(), forbiddenIn("SELECT overall, filtered, leftover(x) FROM t WHERE x IN (1)"))
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

    @Test
    fun `parameter gate detects function references and unqualified calls`() {
        val names = listOf("byIds")
        // A bound reference used outside a chunked call binds the whole list at once.
        assertEquals(listOf("byIds"), unchunkedCalls("val r = keys.let(dao::byIds)", names))
        assertEquals(listOf("byIds"), unchunkedCalls("keys.let(::byIds)", names))
        // An unqualified call in the source declaring the query: a DAO default/@Transaction method.
        val dao = "@Dao interface D {\n @Query(\"SELECT * FROM t WHERE id IN (:ids)\")\n" +
            " suspend fun byIds(ids: List<Long>): List<T>\n" +
            " @Transaction suspend fun all(k: List<Long>) = byIds(k)\n}"
        assertEquals(listOf("byIds"), unchunkedCalls(dao, names))
        assertTrue(unchunkedCalls(dao.replace("= byIds(k)", "= chunkedIn(k) { byIds(it) }"), names).isEmpty())
        // Elsewhere an unqualified name(…) is some other function (a wrapper, a lambda parameter).
        assertTrue(unchunkedCalls("suspend fun all(k: List<Long>) = byIds(k)", names).isEmpty())
        // Inside a chunked call a reference is fine, and the declaration itself is not a use.
        assertTrue(unchunkedCalls("chunkedIn(keys, 500, dao::byIds)", names).isEmpty())
        assertTrue(unchunkedCalls(dao.substringBefore("@Transaction"), names).isEmpty())
        // Longer names that merely contain the query name are other functions; comments are no use.
        assertTrue(unchunkedCalls("dao.byIdsCount(keys); dao.allByIds(keys) /** [byIds] */", names).isEmpty())
        assertTrue(unchunkedCalls("// calls dao.byIds(keys)\n/* dao::byIds */ val u = \"//\"", names).isEmpty())
    }

    /**
     * The [forbidden] constructs in one SQL literal. Case and whitespace are normalised first
     * (any run collapses to one space, none before a paren), so `OVER(` and `over\n (` are
     * caught as well as `OVER (`.
     */
    private fun forbiddenIn(lit: String): List<String> {
        val sql = normaliseSql(lit.replace("\\n", " ").replace("\\t", " "))
        return forbidden.filter { token ->
            val t = normaliseSql(token)
            Regex((if (t.first().isLetter()) "\\b" else "") + Regex.escape(t)).containsMatchIn(sql)
        }
    }

    private fun normaliseSql(s: String): String =
        s.uppercase().replace(Regex("\\s+"), " ").replace(" (", "(")

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

    /**
     * Uses of [names] outside every chunked call, comments ignored: qualified calls (`dao.name(`),
     * function references (`dao::name`, `::name`), and unqualified calls with an argument
     * (`name(x)`) in the source that declares the query (a DAO default or @Transaction method).
     * Elsewhere an unqualified `name(…)` is some other function of the same name (a wrapper, a
     * lambda parameter), so it is not flagged; `with(dao) { name(x) }` is the one form missed.
     */
    private fun unchunkedCalls(src: String, names: List<String>): List<String> {
        if (names.isEmpty()) return emptyList()
        val code = blankComments(src)
        val local = listParamQueryNames(src).toSet()
        val ranges = chunkedRanges(code)
        val use = Regex("(\\bfun\\s+)?(::|\\.)?\\b(" + names.joinToString("|") + ")\\b(\\s*\\(\\s*[^)\\s])?")
        return use.findAll(code)
            .filter { m ->
                val name = m.groupValues[3]
                val calls = m.groups[4] != null
                m.groups[1] == null && when (m.groups[2]?.value) {
                    "::" -> true
                    "." -> calls || code.substring(m.range.last + 1).trimStart().startsWith("(")
                    else -> calls && name in local
                }
            }
            .filter { m -> ranges.none { m.range.first in it } }
            .map { it.groupValues[3] }.toList()
    }

    /** [src] with every `//` and `/* */` comment blanked to spaces (offsets kept); strings are left alone. */
    private fun blankComments(src: String): String {
        val out = StringBuilder(src)
        var i = 0
        fun blank(from: Int, to: Int) { for (k in from until to) if (out[k] != '\n') out[k] = ' ' }
        while (i < src.length) {
            when {
                src.startsWith("\"\"\"", i) ->
                    i = src.indexOf("\"\"\"", i + 3).let { if (it < 0) src.length else it + 3 }
                src[i] == '"' -> {
                    i++
                    while (i < src.length && src[i] != '"' && src[i] != '\n') i += if (src[i] == '\\') 2 else 1
                    i++
                }
                src.startsWith("//", i) -> {
                    val end = src.indexOf('\n', i).let { if (it < 0) src.length else it }
                    blank(i, end)
                    i = end
                }
                src.startsWith("/*", i) -> {
                    val end = src.indexOf("*/", i + 2).let { if (it < 0) src.length else it + 2 }
                    blank(i, end)
                    i = end
                }
                else -> i++
            }
        }
        return out.toString()
    }
}

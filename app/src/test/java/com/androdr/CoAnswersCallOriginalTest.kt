package com.androdr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Guards against `coEvery { x.f(..) } coAnswers { ..; callOriginal() }` where `f` is a suspend
 * function returning `Unit`.
 *
 * MockK runs a `coAnswers` block inside `runBlocking` and `callOriginal()` hands the original the
 * caller's continuation. When the original really suspends (a Room transaction does, depending on
 * thread timing), a `Unit` answer drops the suspension marker, so the stub returns to the caller
 * *before the original has finished*. `StartupSweepTest > a scan started during the sweep survives
 * it` failed in CI this way (PR #408): `completeDelete(1)` "returned", the sweep counted it, and
 * scan 1 was still `IN_PROGRESS` when the test read it (reproduced 111–150 of 200 runs locally).
 * Call the real, unspied instance from the answer instead (e.g. `w.repo.completeDelete(id)`).
 *
 * A stubbed function is allowed only when every main-source `suspend fun` of that name declares an
 * explicit non-`Unit` return type; an unresolvable or expression-bodied declaration is refused.
 */
class CoAnswersCallOriginalTest {

    @Test
    fun `no coAnswers block calls callOriginal on a Unit suspend function`() {
        val main = root("main").walkTopDown().filter { it.isFile && it.extension == "kt" }
            .joinToString("\n") { it.readText() }
        val offenders = root("test").walkTopDown()
            .filter { it.isFile && it.extension == "kt" && it.name != "CoAnswersCallOriginalTest.kt" }
            .flatMap { file -> offenders(file.readText(), main).map { "${file.name}: $it" } }
            .toList()
        assertTrue(
            "coAnswers { callOriginal() } on a suspend fun that returns Unit (or whose return type " +
                "cannot be verified) can return before the original finishes. Call the real instance " +
                "instead. See CoAnswersCallOriginalTest's KDoc.\n" + offenders.joinToString("\n"),
            offenders.isEmpty(),
        )
    }

    @Test
    fun `the scanner flags the original StartupSweepTest stub and accepts a non-Unit one`() {
        val main = """
            suspend fun completeDelete(scanId: Long) {
                store.deleteScanTelemetry(scanId)
            }
            suspend fun persistChunk(
                scanId: Long, chunk: List<StoreRecord>,
            ): ChunkResult = db.withTransaction { x }
        """.trimIndent()
        val original = """
            coEvery { repo.completeDelete(1L) } coAnswers {
                w.lock.withWriter { w.writer.begin(w.scan(2L), liveEvents = false) }
                callOriginal()
            }
        """.trimIndent()
        val nonUnit = "coEvery { store.persistChunk(any(), capture(p)) } coAnswers { callOriginal() }"
        val fixed = "coEvery { repo.completeDelete(1L) } coAnswers { w.repo.completeDelete(1L) }"
        assertEquals(listOf("completeDelete (line 1)"), offenders(original, main))
        assertEquals(emptyList<String>(), offenders(nonUnit, main))
        assertEquals(emptyList<String>(), offenders(fixed, main))
        assertEquals("an undeclared function is refused", listOf("missing (line 1)"),
            offenders("coEvery { a.missing() } coAnswers { callOriginal() }", main))
    }

    /** `name (line n)` for each coAnswers block calling callOriginal() on a not-provably-non-Unit fun. */
    private fun offenders(test: String, main: String): List<String> =
        Regex("""coEvery\s*\{""").findAll(test).mapNotNull { stub ->
            val name = calledOriginalOn(test, stub.range.last) ?: return@mapNotNull null
            if (provablyNonUnit(name, main)) null
            else "$name (line ${test.substring(0, stub.range.first).count { it == '\n' } + 1})"
        }.toList()

    /** The stubbed function's name when the `coEvery {` at [stubOpen] has a coAnswers calling callOriginal(). */
    private fun calledOriginalOn(test: String, stubOpen: Int): String? {
        val stubClose = close(test, stubOpen, '{', '}') ?: return null
        val name = Regex("""\.(\w+)\s*\(""").find(test.substring(stubOpen, stubClose))?.groupValues?.get(1)
        val answer = Regex("""^\s*coAnswers\s*\{""").find(test.substring(stubClose + 1)) ?: return null
        val open = stubClose + 1 + answer.range.last
        val body = close(test, open, '{', '}')?.let { test.substring(open, it) }
        return name?.takeIf { body != null && "callOriginal()" in body }
    }

    private fun provablyNonUnit(name: String, main: String): Boolean {
        val decls = Regex("""suspend\s+fun\s+(?:[\w.<>]+\.)?$name\s*\(""").findAll(main).toList()
        if (decls.isEmpty()) return false
        return decls.all { d ->
            val paren = close(main, d.range.last, '(', ')') ?: return@all false
            val type = Regex("""^\s*:\s*([^={]+?)\s*[={]""").find(main.substring(paren + 1))?.groupValues?.get(1)
            type != null && type != "Unit"
        }
    }

    /** Index of the bracket closing the one at [open], or null. */
    private fun close(s: String, open: Int, l: Char, r: Char): Int? {
        var depth = 0
        for (i in open until s.length) {
            when (s[i]) {
                l -> depth++
                r -> if (--depth == 0) return i
            }
        }
        return null
    }

    private fun root(set: String): File =
        listOf(File("src/$set/java/com/androdr"), File("app/src/$set/java/com/androdr")).firstOrNull { it.isDirectory }
            ?: error("cannot find src/$set from ${File(".").absolutePath}")
}

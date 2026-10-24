package com.androdr.data.repo

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Review C1/I1 source gate: no reader outside [FindingsRepository] reads a whole scan's findings into
 * memory (`findingsOf(` / `withFindings(`). An import can hold 100k findings, so every other reader
 * counts in SQL, takes a bounded sample, pages, or streams with `forEachFinding`. Inside the
 * repository the only caller is [FindingsRepository.latestLive], a live scan (bounded by rules ×
 * live records).
 */
class BoundedFindingReadersGateTest {

    private fun root(): File = listOf(File("src/main/java/com/androdr"), File("app/src/main/java/com/androdr"))
        .first { it.isDirectory }

    private val call = Regex("""\b(findingsOf|withFindings)\(""")

    private fun calls(src: String): List<String> = src.lines().filter { line ->
        val code = line.substringBefore("//").trim()
        !code.startsWith("*") && !code.startsWith("/*") && call.containsMatchIn(code) &&
            !Regex("""fun\s+(findingsOf|withFindings)\(""").containsMatchIn(code)
    }.map { it.trim() }

    @Test
    fun `whole-scan reads happen only in FindingsRepository, for the latest live scan`() {
        val files = root().walkTopDown().filter { it.extension == "kt" }.toList()
        val outside = files.filter { it.name != "FindingsRepository.kt" }
            .flatMap { f -> calls(f.readText()).map { "${f.name}: $it" } }
        assertTrue("whole-scan finding reads outside FindingsRepository:\n" + outside.joinToString("\n"),
            outside.isEmpty())
        val inside = calls(files.single { it.name == "FindingsRepository.kt" }.readText())
        assertEquals(listOf(
            "ScanWithFindings(scan, findingsOf(scan.id, triggeredOnly))",
            ".map { scans.latestLiveOnce()?.let { withFindings(it) } }",
        ), inside)
    }

    @Test
    fun `the gate sees a call and ignores declarations and comments`() {
        val src = "suspend fun findingsOf(id: Long) = 1\n// findingsOf(x)\n * withFindings(s)\n" +
            "val a = repo.findingsOf(3)"
        assertEquals(listOf("val a = repo.findingsOf(3)"), calls(src))
    }
}

package com.androdr

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * V1 (telemetry store spec §3, §9): the retired phrases stay out of main Kotlin, string resources
 * and the docs (except `docs/superpowers/`), and ARCHITECTURE.md's glossary defines all ten terms.
 */
class VocabularyGateTest {

    private val root: File = listOf(File("."), File(".."))
        .map { it.canonicalFile }
        .first { File(it, "docs/ARCHITECTURE.md").isFile && File(it, "app/src/main").isDirectory }

    private val bannedPhrases = listOf(
        Regex("raw telemetry", RegexOption.IGNORE_CASE),
        Regex("informational telemetry", RegexOption.IGNORE_CASE),
        Regex("""(?<![A-Za-z0-9_])class TimelineEvent\b"""),
    )

    private fun scannedFiles(): List<File> {
        val kotlin = File(root, "app/src/main/java").walkTopDown().filter { it.isFile && it.extension == "kt" }
        val values = File(root, "app/src/main/res").walkTopDown()
            .filter { it.isFile && it.parentFile.name.startsWith("values") && it.extension == "xml" }
        val docs = File(root, "docs").listFiles { f -> f.isFile && f.extension == "md" }.orEmpty().asSequence()
        return (kotlin + values + docs).toList()
    }

    @Test
    fun `retired phrases do not appear`() {
        val files = scannedFiles()
        assertTrue("the gate found no files to scan", files.size > 50)
        val hits = files.flatMap { f ->
            f.readLines().withIndex().flatMap { (i, line) ->
                bannedPhrases.filter { it.containsMatchIn(line) }
                    .map { "${f.relativeTo(root).path}:${i + 1} matches /${it.pattern}/" }
            }
        }
        assertTrue("Retired vocabulary (spec §3):\n${hits.joinToString("\n")}", hits.isEmpty())
    }

    @Test
    fun `glossary lists all ten terms`() {
        val text = File(root, "docs/ARCHITECTURE.md").readText()
        val start = text.indexOf("## Glossary")
        assertTrue("ARCHITECTURE.md has no '## Glossary' section", start >= 0)
        val rest = text.substring(start + "## Glossary".length)
        val end = Regex("""\n## """).find(rest)?.range?.first ?: rest.length
        val glossary = rest.substring(0, end)
        val missing = TERMS.filterNot { glossary.contains("| **$it** |") }
        assertTrue("Glossary is missing: $missing", missing.isEmpty())
    }

    private companion object {
        val TERMS = listOf(
            "Telemetry record", "Snapshot record", "Event record", "Fact", "Observation",
            "Timeline event", "Finding", "Alert", "Provenance", "Watermark",
        )
    }
}

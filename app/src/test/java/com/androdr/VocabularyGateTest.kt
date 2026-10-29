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
        Regex("""raw\s+telemetry""", RegexOption.IGNORE_CASE),
        Regex("""informational\s+telemetry""", RegexOption.IGNORE_CASE),
        Regex("""(?<![A-Za-z0-9_])class TimelineEvent\b"""),
    )

    private fun kotlinFiles(): List<File> =
        File(root, "app/src/main/java").walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()

    private fun valuesFiles(): List<File> =
        File(root, "app/src/main/res").walkTopDown()
            .filter { it.isFile && it.parentFile.name.startsWith("values") && it.extension == "xml" }.toList()

    private fun docFiles(): List<File> =
        File(root, "docs").listFiles { f -> f.isFile && f.extension == "md" }.orEmpty().toList()

    private fun hitsIn(name: String, text: String): List<String> =
        bannedPhrases.flatMap { re ->
            re.findAll(text).map { m ->
                val line = text.substring(0, m.range.first).count { it == '\n' } + 1
                "$name:$line matches /${re.pattern}/"
            }.toList()
        }

    @Test
    fun `every scanned source is non-empty`() {
        assertTrue("no main Kotlin scanned", kotlinFiles().isNotEmpty())
        assertTrue("no res/values files scanned", valuesFiles().isNotEmpty())
        assertTrue("no docs scanned", docFiles().isNotEmpty())
        assertTrue("ARCHITECTURE.md not scanned", docFiles().any { it.name == "ARCHITECTURE.md" })
    }

    @Test
    fun `retired phrases do not appear`() {
        val hits = (kotlinFiles() + valuesFiles() + docFiles()).flatMap { f ->
            hitsIn(f.relativeTo(root).path, f.readText())
        }
        assertTrue("Retired vocabulary (spec §3):\n${hits.joinToString("\n")}", hits.isEmpty())
    }

    @Test
    fun `control cases`() {
        assertTrue(hitsIn("x", "class TimelineEvent(val a: Int)").isNotEmpty())
        assertTrue(hitsIn("x", "class ForensicTimelineEvent(val a: Int)").isEmpty())
        assertTrue(hitsIn("x", "the Raw\ntelemetry").isNotEmpty())
        assertTrue(hitsIn("x", "Informational\n  Telemetry").isNotEmpty())
        assertTrue(hitsIn("x", "stored telemetry").isEmpty())
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

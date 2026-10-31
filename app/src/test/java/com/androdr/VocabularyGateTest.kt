package com.androdr

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * V1 (telemetry store spec §3, §9): the retired phrases stay out of main Kotlin, string resources
 * and the docs (except `docs/superpowers/`), and ARCHITECTURE.md's glossary defines all ten terms.
 *
 * A phrase is caught however it wraps: across a KDoc or line-comment break (`raw\n * telemetry`,
 * `raw\n// telemetry`) as well as plain whitespace. Any declaration named `TimelineEvent` (class,
 * object, interface, typealias) is retired, and docs are scanned in every subdirectory except
 * `docs/superpowers/`.
 */
class VocabularyGateTest {

    private val root: File = listOf(File("."), File(".."))
        .map { it.canonicalFile }
        .first { File(it, "docs/ARCHITECTURE.md").isFile && File(it, "app/src/main").isDirectory }

    /** Whitespace between two words, possibly across a comment line break (` * `, `// `). */
    private val sep = """(?:\s|\*|//)*\s(?:\s|\*|//)*"""

    private val bannedPhrases = listOf(
        Regex("""\braw${sep}telemetry""", RegexOption.IGNORE_CASE),
        Regex("""\binformational${sep}telemetry""", RegexOption.IGNORE_CASE),
        Regex("""(?<![A-Za-z0-9_])(?:class|object|interface|typealias)\s+TimelineEvent\b"""),
    )

    private fun kotlinFiles(): List<File> =
        File(root, "app/src/main/java").walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()

    private fun valuesFiles(): List<File> =
        File(root, "app/src/main/res").walkTopDown()
            .filter { it.isFile && it.parentFile.name.startsWith("values") && it.extension == "xml" }.toList()

    private fun docFiles(): List<File> {
        val superpowers = File(root, "docs/superpowers")
        return File(root, "docs").walkTopDown().onEnter { it != superpowers }
            .filter { it.isFile && it.extension == "md" }.toList()
    }

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
        // Wrapped across a KDoc or line-comment break.
        assertTrue(hitsIn("x", "/**\n * The raw\n * telemetry of a scan\n */").isNotEmpty())
        assertTrue(hitsIn("x", "// informational\n    // telemetry").isNotEmpty())
        assertTrue(hitsIn("x", "@raw/telemetry_dict_app").isEmpty())
        assertTrue(hitsIn("x", "drawn telemetry").isEmpty())
        // Any declaration of the retired name.
        assertTrue(hitsIn("x", "data class TimelineEvent(val a: Int)").isNotEmpty())
        assertTrue(hitsIn("x", "typealias TimelineEvent = ForensicTimelineEvent").isNotEmpty())
        assertTrue(hitsIn("x", "object TimelineEvent").isNotEmpty())
        assertTrue(hitsIn("x", "interface  TimelineEvent").isNotEmpty())
        assertTrue(hitsIn("x", "object TimelineEvents").isEmpty())
    }

    @Test
    fun `docs in subdirectories are scanned, docs superpowers is not`() {
        val docs = docFiles().map { it.relativeTo(root).invariantSeparatorsPath }
        assertTrue(docs.any { it.startsWith("docs/") && it.count { c -> c == '/' } >= 2 })
        assertTrue(docs.none { it.startsWith("docs/superpowers/") })
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

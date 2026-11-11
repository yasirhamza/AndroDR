package com.androdr.privacy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Formatting gate for the privacy-scan sources (T10-5). The project's detekt has no formatting rule set, so the
 * two slips the final review found are checked here: a named argument glued to the previous comma
 * (`a = x,b = y`) and a blank line right before a closing brace. Also: no raw invisible formatting
 * character (bidi override, zero-width) in source; test inputs write them as `\\u` escapes, so the code a
 * reviewer reads is the code that runs.
 */
class PrivacySourceStyleTest {

    private fun dirs(): List<File> {
        val roots = listOf(File("src"), File("app/src")).filter { it.isDirectory }
        assertTrue("cannot find src from ${File(".").absolutePath}", roots.isNotEmpty())
        val root = roots.first()
        return listOf(
            "main/java/com/androdr/privacy", "main/java/com/androdr/ui/privacy", "main/java/com/androdr/ui/apps",
            "main/java/com/androdr/ui/dashboard", "test/java/com/androdr/privacy", "test/java/com/androdr/ui/privacy",
            "test/java/com/androdr/ui/apps", "test/java/com/androdr/ui/dashboard",
        ).map { File(root, it) }
    }

    private fun files(): List<File> =
        dirs().flatMap { d -> d.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList() }
            .filter { it.name != "PrivacySourceStyleTest.kt" } // its own examples are the banned shapes

    private val gluedNamedArgument = Regex(""",[A-Za-z_][A-Za-z0-9_]* = """)
    private val blankBeforeBrace = Regex("""\n[ \t]*\n[ \t]*}""")
    private val rawFormatCharacter = Regex("""\p{Cf}""")

    private fun offenders(rule: Regex): List<String> = files().flatMap { f ->
        val text = f.readText()
        rule.findAll(text).map { m -> "${f.path}:${text.substring(0, m.range.first).count { it == '\n' } + 1}" }
    }

    @Test fun `no named argument follows a comma without a space`() {
        assertEquals(emptyList<String>(), offenders(gluedNamedArgument))
    }

    @Test fun `no blank line before a closing brace`() {
        assertEquals(emptyList<String>(), offenders(blankBeforeBrace))
    }

    @Test fun `no raw invisible formatting character in source`() {
        assertEquals(emptyList<String>(), offenders(rawFormatCharacter))
    }

    @Test fun `the rules see each shape`() {
        assertTrue(gluedNamedArgument.containsMatchIn("PrivacyCard(state = privacyCard,onNavigate = onNavigate)"))
        assertTrue(blankBeforeBrace.containsMatchIn("        job.cancel()\n    }\n\n}\n"))
        assertTrue(rawFormatCharacter.containsMatchIn("val s = \"com.\u202Eevil\""))
        assertTrue(!rawFormatCharacter.containsMatchIn("val s = \"com.\\u202Eevil\""))
        assertTrue(files().size > 20)
    }
}

package com.androdr

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/**
 * Release builds are minified with R8. Reflecting into library internals (Compose's internal
 * `getMotionEvent$ui_release` accessor was one) can be renamed or stripped there, so a security
 * control built on it would fail in release while every debug test stays green. No main source
 * may name a Kotlin internal-visibility mangled member (`$ui_release`, `$foundation_release`, ...).
 */
class NoLibraryInternalsReflectionTest {
    private val mangled = Regex("""\$[a-z0-9_]+_(release|debug)\b""")

    @Test
    fun `main sources do not reference mangled library internals`() {
        val root = listOf(File("src/main/java"), File("app/src/main/java")).first { it.isDirectory }
        val offenders = root.walkTopDown().filter { it.isFile && it.extension == "kt" }
            .flatMap { f ->
                f.readLines().withIndex()
                    .filter { (_, line) -> mangled.containsMatchIn(line) || "ui_release" in line }
                    .map { (i, line) -> "${f.name}:${i + 1}: ${line.trim()}" }
            }.toList()
        assertEquals("reflection into library internals: $offenders", emptyList<String>(), offenders)
    }
}

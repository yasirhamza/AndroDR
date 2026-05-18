package com.androdr.ui.theme

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Guards against re-introducing hardcoded Color(0xFF…) literals in UI code.
 * The only allowed location for raw color values is inside ui/theme/.
 * If you need a new semantic color, add it to ExtendedColors instead.
 *
 * Sub-percent washes — e.g. critical.copy(alpha = 0.08f) — are intentionally
 * allowed and not matched by this regex.
 *
 * Suppress per-line with: // hardcoded-color-ok: <reason>
 */
class HardcodedColorGuardTest {

    @Test
    fun `no hardcoded Color(0xFF…) literals outside ui-theme package`() {
        val sourceRoot = findSourceRoot()
        val pattern = Regex("""Color\(0x[0-9A-Fa-f]{8}\)""")
        val allowMarker = "hardcoded-color-ok"

        val offenders = sourceRoot.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .filterNot { it.path.replace('\\', '/').contains("/ui/theme/") }
            .flatMap { file ->
                file.readLines().mapIndexedNotNull { idx, line ->
                    if (pattern.containsMatchIn(line) && !line.contains(allowMarker)) {
                        "${file.relativeTo(sourceRoot)}:${idx + 1}  ${line.trim()}"
                    } else null
                }
            }
            .toList()

        assertTrue(
            "Hardcoded Color(0xFF…) literals found outside ui/theme/.\n" +
                "Move the color to ExtendedColors, or append `// hardcoded-color-ok: <reason>` " +
                "to the line if it is genuinely a one-off (debug overlay, preview fixture, etc.):\n" +
                offenders.joinToString("\n"),
            offenders.isEmpty()
        )
    }

    private fun findSourceRoot(): File {
        // Gradle JVM tests run with cwd = module dir (app/). IDE run configs sometimes
        // use the repo root. Cover both.
        val candidates = listOf(
            File("src/main/java/com/androdr"),
            File("app/src/main/java/com/androdr"),
            File("../app/src/main/java/com/androdr")
        )
        return candidates.firstOrNull { it.exists() }
            ?: error(
                "Could not locate source root from ${File(".").absolutePath}. " +
                    "Tried: ${candidates.map { it.path }}"
            )
    }
}

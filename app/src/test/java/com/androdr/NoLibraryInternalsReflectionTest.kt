package com.androdr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * Release builds are minified with R8. Reflecting into library internals (Compose's internal
 * `getMotionEvent$ui_release` accessor was one) can be renamed or stripped there, so a security
 * control built on it would fail in release while every debug test stays green.
 *
 * Rules, over every `.kt` and `.java` file under `src/main` (any source root):
 * 1. No source names a Kotlin internal-visibility mangled member (`$ui_release`, `$foundation_debug`,
 *    ...), including a split literal such as `"getMotionEvent\$ui_" + "release"`.
 * 2. No source uses private-member reflection (`getDeclaredMethod`/`getDeclaredField`,
 *    `setAccessible`, `isAccessible =`).
 * 3. Files in `com.androdr.ui.security` (by path or package) use no reflection API at all.
 * 4. Elsewhere, public reflection (`Class.forName`, `getMethod`, `getField`, `::class.java.get...`)
 *    is allowed only in [publicReflectionAllowlist].
 *
 * Comments count too: the gate is line based on purpose, so it is simple and hard to dodge.
 */
class NoLibraryInternalsReflectionTest {

    @get:Rule val tmp = TemporaryFolder()

    @Test
    fun `main sources do not reflect into library internals`() {
        val main = listOf(File("src/main"), File("app/src/main")).first { it.isDirectory }
        val offenders = scanTree(main)
        assertEquals("reflection into library internals: $offenders", emptyList<String>(), offenders)
    }

    // --- self-tests: each pattern planted in a fixture must be caught ---

    private val securityPath = "java/com/androdr/ui/security/Planted.kt"

    @Test
    fun `every banned pattern in ui security is caught`() {
        val planted = listOf(
            """val m = Foo::class.java.getMethod("x")""",
            """val m = Foo::class.java.getDeclaredMethod("x")""",
            """val f = Foo::class.java.getField("x")""",
            """val f = Foo::class.java.getDeclaredField("x")""",
            """f.setAccessible(true)""",
            """f.isAccessible = true""",
            """f.apply { isAccessible=true }""",
            """val c = Class.forName("a.B")""",
            """val ms = Foo::class.java.getMethods()""",
            """val ctor = Foo::class.java.getConstructor()""",
            """val k = view.javaClass.getMethod("x")""",
        )
        for (line in planted) {
            val text = "package com.androdr.ui.security\n$line"
            assertTrue("not caught: $line", scanText(securityPath, text).isNotEmpty())
        }
    }

    @Test
    fun `security package is matched by package declaration as well as path`() {
        val text = "package com.androdr.ui.security\nval c = Class.forName(\"a.B\")"
        assertTrue(scanText("java/com/androdr/elsewhere/Moved.kt", text).isNotEmpty())
        assertTrue(scanText("java/com/androdr/ui/security/Sub.java", "val c = Class.forName(\"a.B\")").isNotEmpty())
    }

    @Test
    fun `mangled names are caught anywhere in main, whole or split`() {
        val other = "java/com/androdr/scanner/Planted.kt"
        val planted = listOf(
            """// getMotionEvent${'$'}ui_release""",
            """val n = "getMotionEvent\${'$'}ui_release"""",
            """val n = "getMotionEvent\${'$'}ui_" + "release"""",
            """val n = "x\${'$'}foundation_debug"""",
            """String n = "getFoo${'$'}runtime_release";""",
            """val n = "ui_" + "release"""",
            """val n = "_release"""",
        )
        for (line in planted) {
            assertTrue("not caught: $line", scanText(other, line).isNotEmpty())
        }
    }

    @Test
    fun `private reflection is caught outside ui security and public reflection outside the allowlist`() {
        val other = "java/com/androdr/scanner/Planted.java"
        assertTrue(scanText(other, "m = c.getDeclaredMethod(\"x\");").isNotEmpty())
        assertTrue(scanText(other, "f.setAccessible(true);").isNotEmpty())
        assertTrue(scanText(other, "Class<?> c = Class.forName(\"a.B\");").isNotEmpty())
        assertTrue(scanText(other, "m = c.getMethod(\"x\");").isNotEmpty())
    }

    @Test
    fun `allowlisted platform reflection and plain code pass`() {
        val allowed = "java/com/androdr/scanner/DeviceAuditor.kt"
        assertEquals(emptyList<String>(), scanText(allowed, "val c = Class.forName(\"android.os.SystemProperties\")"))
        val plain = "package com.androdr.ui.security\nval x = BuildConfig.DEBUG"
        assertEquals(emptyList<String>(), scanText(securityPath, plain))
    }

    @Test
    fun `tree walk covers java files and every source root`() {
        val root = tmp.newFolder("main")
        File(root, "kotlin/com/androdr/ui/security").mkdirs()
        File(root, "kotlin/com/androdr/ui/security/A.kt").writeText("val c = Class.forName(\"a.B\")")
        File(root, "java/com/androdr/x").mkdirs()
        File(root, "java/com/androdr/x/B.java").writeText("m = c.getDeclaredMethod(\"x\");")
        File(root, "java/com/androdr/x/C.txt").writeText("getDeclaredMethod")
        val offenders = scanTree(root)
        assertEquals(offenders.toString(), 2, offenders.size)
    }

    companion object {
        /** Files (by name) allowed public reflection on platform classes, with the reason. */
        private val publicReflectionAllowlist = setOf(
            "DeviceAuditor.kt", // android.os.SystemProperties, a platform hidden API, not a library internal
        )

        private val mangled = listOf(
            Regex("""\$[A-Za-z0-9_]+_(release|debug)\b"""), // getX$ui_release
            Regex("""\$[A-Za-z0-9_]+_"\s*\+"""), // "getX$ui_" + ...
            Regex(""""[^"]*_(release|debug)\b[^"]*""""), // "ui_release", "_release"
            Regex("""_"\s*\+\s*"(release|debug)""""), // "ui_" + "release"
        )
        private val privateReflection =
            Regex("""getDeclared(Method|Field|Constructor)s?\b|setAccessible\b|isAccessible\s*=""")
        private val publicReflection =
            Regex("""Class\.forName\b|\bget(Method|Field|Constructor)s?\s*\(|::class\.java\.get|javaClass\.get""")

        fun scanTree(root: File): List<String> =
            root.walkTopDown().filter { it.isFile && (it.extension == "kt" || it.extension == "java") }
                .flatMap { f -> scanText(f.relativeTo(root).invariantSeparatorsPath, f.readText()) }
                .toList()

        /** Offending lines of one source file; [path] is relative to the `src/main` directory. */
        fun scanText(path: String, text: String): List<String> {
            val name = path.substringAfterLast('/')
            val inSecurity = "com/androdr/ui/security/" in path ||
                Regex("""^\s*package\s+com\.androdr\.ui\.security\b""", RegexOption.MULTILINE).containsMatchIn(text)
            return text.lines().withIndex().filter { (_, line) ->
                mangled.any { it.containsMatchIn(line) } ||
                    privateReflection.containsMatchIn(line) ||
                    (publicReflection.containsMatchIn(line) && (inSecurity || name !in publicReflectionAllowlist))
            }.map { (i, line) -> "$path:${i + 1}: ${line.trim()}" }
        }
    }
}

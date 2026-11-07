package com.androdr.privacy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Source scan of the privacy boundary (spec §5.1): privacy results never reach reports, rules, History or the
 * security store; the privacy scan never takes the security scan's lock or rows; the APK reader stays
 * registry-independent; the UI never drives the registry or the reader directly; `privacy/model` has no
 * package cycle with `ioc`.
 */
class PrivacyBoundaryTest {

    private fun root(): File =
        listOf(File("src/main/java/com/androdr"), File("app/src/main/java/com/androdr")).firstOrNull { it.isDirectory }
            ?: error("cannot find src/main from ${File(".").absolutePath}")

    private fun kotlinFiles(relative: String): List<File> {
        val f = File(root(), relative)
        assertTrue("missing $relative", f.exists())
        return if (f.isFile) listOf(f) else f.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
    }

    private fun offenders(paths: List<String>, banned: Regex): List<String> =
        paths.flatMap { kotlinFiles(it) }.filter { banned.containsMatchIn(it.readText()) }.map { it.path }

    @Test fun `reports, rules, History and the security store never touch privacy`() {
        val paths = listOf("reporting", "sigma", "ui/history", "data/repo/ScanWriteRepository.kt", "data/store")
        assertEquals(emptyList<String>(), offenders(paths, Regex("""com\.androdr\.privacy|privacy_""")))
    }

    @Test fun `the privacy scan never references the security scan's lock or results`() {
        assertEquals(emptyList<String>(), offenders(listOf("privacy"), Regex("""\bScanLock\b|\bScanResult\b""")))
    }

    @Test fun `the APK reader and inspector stay registry-independent`() {
        val paths = listOf("privacy/DexPackageReader.kt", "privacy/ApkPackageInspector.kt")
        assertEquals(emptyList<String>(), offenders(paths, Regex("""\b(TrackerRegistry|TrackerSet|Tracker)\b""")))
    }

    @Test fun `the UI never imports the registry or the APK reader`() {
        val banned = Regex(
            "^import\\s+com\\.androdr\\." +
                """(ioc\.TrackerRegistry|privacy\.DexPackageReader|privacy\.ApkPackageInspector)\b""",
            RegexOption.MULTILINE,
        )
        assertEquals(emptyList<String>(), offenders(listOf("ui"), banned))
    }

    @Test fun `privacy model never imports ioc`() {
        val banned = Regex("""^import\s+com\.androdr\.ioc\b""", RegexOption.MULTILINE)
        assertEquals(emptyList<String>(), offenders(listOf("privacy/model"), banned))
    }

    @Test fun `the scans see each banned shape`() {
        assertTrue(Regex("""\b(TrackerRegistry|TrackerSet|Tracker)\b""").containsMatchIn("val t: Tracker = x"))
        assertTrue(Regex("""\bScanLock\b|\bScanResult\b""").containsMatchIn("import com.androdr.data.repo.ScanLock"))
        assertTrue(Regex("""com\.androdr\.privacy|privacy_""").containsMatchIn("SELECT * FROM privacy_scan"))
    }
}

package com.androdr.ioc

import com.androdr.integrity.ManifestVerifier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Build-time guard: every ioc-data YAML file in the pinned submodule is listed in
 * `ioc-data.sha256` with a matching hash, computed the way the device computes it
 * ([ManifestVerifier.sha256] over the UTF-8 text), so a non-UTF-8 byte or a stale
 * manifest fails CI instead of silently dropping the file on devices (fail-closed).
 */
class IocDataManifestIntegrityTest {

    private fun repoRoot(): File? = listOf(
        File("third-party/android-sigma-rules"),
        File("../third-party/android-sigma-rules"),
    ).firstOrNull { it.isDirectory }

    @Test
    fun `ioc-data manifest lists every file with the device-computed hash`() {
        val root = repoRoot()
        assumeTrue("android-sigma-rules submodule not checked out - skipping", root != null)
        requireNotNull(root)
        val manifestFile = File(root, "ioc-data.sha256")
        // A hard failure, not a skip: Plan A A7 shipped the manifest, and without it devices
        // drop every remote ioc-data file (fail-closed).
        assertTrue("ioc-data.sha256 missing - devices would drop all remote ioc-data", manifestFile.isFile)

        val expected = ManifestVerifier.parse(manifestFile.readText())
        val onDisk = File(root, "ioc-data").listFiles { f -> f.name.endsWith(".yml") }.orEmpty()
            .map { "ioc-data/${it.name}" }.sorted()
        assertTrue("no ioc-data files found", onDisk.isNotEmpty())

        val problems = mutableListOf<String>()
        for (rel in onDisk) {
            val want = expected[rel]
            if (want == null) { problems += "$rel is not listed in ioc-data.sha256"; continue }
            val actual = ManifestVerifier.sha256(File(root, rel).readText())
            if (!actual.equals(want, ignoreCase = true)) problems += "$rel: manifest=$want device-hash=$actual"
        }
        (expected.keys - onDisk.toSet()).forEach { problems += "$it is listed but absent on disk" }
        if (problems.isNotEmpty()) fail("ioc-data.sha256 drift:\n" + problems.joinToString("\n"))
        assertEquals(onDisk.toSet(), expected.keys)
    }
}

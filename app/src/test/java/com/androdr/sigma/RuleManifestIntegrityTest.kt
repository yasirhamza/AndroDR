package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * Build-time guard against rule-feed integrity drift.
 *
 * The app fetches `rules.txt` + `rules.sha256` from the android-sigma-rules repo
 * and skips any rule whose content hash does not match the manifest
 * (`SigmaRuleFeed.fetchFromRepo`). If a rule YAML is edited without regenerating
 * `rules.sha256`, the integrity check fails silently on-device and that rule is
 * dropped — degrading detection with no build-time signal.
 *
 * Scope: this checks the **submodule manifest's** internal consistency
 * (`rules.txt` ⇔ `rules.sha256` ⇔ on-disk file content) — i.e. the data the
 * remote feed serves. It does NOT cross-check the bundled `res/raw` cold-start
 * copies, and rules that live under `staging/` (not yet listed in `rules.txt`)
 * are out of scope until promoted. Regenerate the manifest with:
 *
 *     cd third-party/android-sigma-rules
 *     while read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done < rules.txt > rules.sha256
 */
class RuleManifestIntegrityTest {

    private fun repoRoot(): File? = listOf(
        File("third-party/android-sigma-rules"),
        File("../third-party/android-sigma-rules"),
        File("/home/yasir/AndroDR/third-party/android-sigma-rules"),
    ).firstOrNull { it.isDirectory }

    private fun sha256Hex(file: File): String =
        MessageDigest.getInstance("SHA-256").digest(file.readBytes())
            .joinToString("") { "%02x".format(it) }

    @Test
    fun `rules manifest and hashes are in sync with rule files`() {
        val root = repoRoot()
        assumeTrue("android-sigma-rules submodule not checked out — skipping", root != null)
        requireNotNull(root)

        val manifest = File(root, "rules.txt")
        val hashManifest = File(root, "rules.sha256")
        assumeTrue("rules.txt missing — skipping", manifest.isFile)
        assumeTrue("rules.sha256 missing — skipping", hashManifest.isFile)

        val listedFiles = manifest.readLines().map { it.trim() }.filter { it.endsWith(".yml") }
        val expectedHashes = parseHashManifest(hashManifest.readLines())

        val problems = findManifestProblems(listedFiles, expectedHashes) { rel ->
            File(root, rel).takeIf { it.isFile }?.let { sha256Hex(it) }
        }

        if (problems.isNotEmpty()) {
            fail(
                "rules.sha256 is out of sync with rule content — these rules would be " +
                    "silently skipped on-device. Regenerate rules.sha256 (see test header).\n" +
                    problems.joinToString("\n"),
            )
        }
    }

    /**
     * Proves the guard itself detects drift, independent of the real submodule
     * state, so the positive test above cannot pass merely because the manifest
     * happens to be in sync right now.
     */
    @Test
    fun `findManifestProblems detects stale hash, missing file, and set mismatch`() {
        val listed = listOf("a.yml", "b.yml", "c.yml")
        val expected = mapOf(
            "a.yml" to "aaaa",            // will match
            "b.yml" to "ffff",            // stale — content hashes to "bbbb"
            // c.yml present in rules.txt but absent from rules.sha256 → set mismatch
        )
        val onDisk = mapOf("a.yml" to "aaaa", "b.yml" to "bbbb") // c.yml missing on disk

        val problems = findManifestProblems(listed, expected) { onDisk[it] }

        assertTrue("should flag stale hash for b.yml", problems.any { it.contains("STALE") && it.contains("b.yml") })
        assertTrue("should flag missing file c.yml", problems.any { it.contains("MISSING") && it.contains("c.yml") })
        assertTrue("should flag manifest set mismatch", problems.any { it.contains("SET-MISMATCH") })

        // And a fully-consistent manifest yields no problems.
        val clean = findManifestProblems(
            listOf("a.yml"),
            mapOf("a.yml" to "aaaa"),
        ) { mapOf("a.yml" to "aaaa")[it] }
        assertEquals(emptyList<String>(), clean)
    }

    private companion object {

        /** sha256sum convention: "<hex>  <path>" (two-space separator). */
        fun parseHashManifest(lines: List<String>): Map<String, String> = lines.mapNotNull { line ->
            val parts = line.trim().split(Regex("\\s+"), limit = 2)
            if (parts.size == 2) parts[1] to parts[0].lowercase() else null
        }.toMap()

        /**
         * Pure comparison core shared by the live and synthetic tests.
         * @param hashProvider returns the actual content hash for a listed path,
         *   or null if the file does not exist.
         */
        fun findManifestProblems(
            listedFiles: List<String>,
            expectedHashes: Map<String, String>,
            hashProvider: (String) -> String?,
        ): List<String> {
            val problems = mutableListOf<String>()
            if (listedFiles.toSortedSet() != expectedHashes.keys.toSortedSet()) {
                problems += "SET-MISMATCH: rules.txt and rules.sha256 list different files"
            }
            for (rel in listedFiles) {
                val actual = hashProvider(rel)
                if (actual == null) {
                    problems += "MISSING: $rel (listed in rules.txt but not on disk)"
                    continue
                }
                val expected = expectedHashes[rel]
                if (expected != null && actual.lowercase() != expected.lowercase()) {
                    problems += "STALE:   $rel (expected=$expected actual=$actual)"
                }
            }
            return problems
        }
    }
}

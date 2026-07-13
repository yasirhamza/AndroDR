package com.androdr.sigma

import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Enforces the bundled↔mirror parity policy mechanically (#175).
 *
 * The android-sigma-rules repo is the public catalog AND the OTA delivery
 * channel: the app fetches `rules.txt` from that repo's main every 12h and
 * REPLACES a bundled rule with the same-id remote copy
 * (`SigmaRuleEngine.setRemoteRules`). Two drift classes are therefore
 * silent behavior bugs, not cosmetic:
 *
 *  1. A bundled rule edited without updating the mirror — devices keep
 *     running the stale remote copy (this reverted the androdr-015
 *     severity downgrade in the field for two months).
 *  2. A bundled rule never listed in `rules.txt` — it can only ever be
 *     changed via a full app release (androdr-079..082).
 *
 * Mirror-only rules in `rules.txt` are deliberately allowed: shipping a new
 * rule remotely before it is bundled is a supported delivery path. The
 * invariant is one-directional — everything bundled must be mirrored
 * byte-equal and (correlation rules excepted, see
 * decisions/2026-07-13-mirror-reconcile.yml) listed for delivery.
 *
 * When this test fails: copy the bundled file over its mirror counterpart
 * (strip the `sigma_` prefix; directory = logsource service), add the entry
 * to rules.txt by hand, regenerate rules.sha256 from it (recipe in
 * CLAUDE.md), and bump the submodule via the safe ordering in CLAUDE.md.
 */
class BundledMirrorParityTest {

    // Bundled rules missing is a broken checkout, never a skippable
    // condition — only the (optional) submodule may assume-skip.
    private fun bundledDir(): File = listOf(
        File("app/src/main/res/raw"),
        File("src/main/res/raw"),
        File("/home/yasir/AndroDR/app/src/main/res/raw"),
    ).firstOrNull { it.isDirectory }
        ?: error("res/raw not found — parity gate cannot run from this working directory")

    private fun mirrorRoot(): File? = listOf(
        File("third-party/android-sigma-rules"),
        File("../third-party/android-sigma-rules"),
        File("/home/yasir/AndroDR/third-party/android-sigma-rules"),
    ).firstOrNull { it.isDirectory && File(it, "rules.txt").isFile }

    /** Top-level rule directories of the mirror — excludes staging (aspirational
     *  rules), validation fixtures, and non-rule data dirs. */
    private fun mirrorRuleFiles(root: File): Map<String, File> =
        root.listFiles { f: File -> f.isDirectory && f.name !in EXCLUDED_DIRS }
            .orEmpty()
            .flatMap { dir -> dir.listFiles { f: File -> f.extension == "yml" }.orEmpty().toList() }
            .associateBy { it.name }

    private fun bundledRuleFiles(dir: File): List<File> {
        val files = dir.listFiles { f: File ->
            f.name.startsWith("sigma_androdr_") && f.extension == "yml"
        }.orEmpty().sortedBy { it.name }
        // Vacuous-pass guard, same floor as BundledRulesSchemaCrossCheckTest:
        // a naming-convention change must not silently disable the gate.
        assertTrue(
            "Expected at least 40 bundled sigma_androdr_*.yml files, found ${files.size}",
            files.size >= 40,
        )
        return files
    }

    private fun deliveredEntries(mirror: File): List<String> =
        File(mirror, "rules.txt").readLines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }

    @Test
    fun `every bundled rule has a byte-equal mirror counterpart`() {
        val bundled = bundledDir()
        val mirror = mirrorRoot()
        assumeTrue("submodule not checked out — skipping", mirror != null)
        requireNotNull(mirror)

        val mirrorByName = mirrorRuleFiles(mirror)
        val failures = mutableListOf<String>()

        for (file in bundledRuleFiles(bundled)) {
            val mirrorName = file.name.removePrefix("sigma_")
            val counterpart = mirrorByName[mirrorName]
            when {
                counterpart == null ->
                    failures.add("${file.name}: no mirror counterpart '$mirrorName'")
                !counterpart.readBytes().contentEquals(file.readBytes()) ->
                    failures.add(
                        "${file.name}: differs from mirror " +
                            "${counterpart.relativeTo(mirror).path} — devices are " +
                            "running the mirror copy, not the bundled one"
                    )
            }
        }

        assertTrue(
            "Bundled↔mirror parity broken (fix recipe in this test's KDoc):\n" +
                failures.joinToString("\n"),
            failures.isEmpty(),
        )
    }

    @Test
    fun `mirror rule basenames are unique across service dirs`() {
        // Both parity checks and the on-device fetch identify rules by
        // basename/path; a same-named file in two service dirs makes parity
        // ambiguous (byte-compare could hit the copy rules.txt does NOT
        // deliver). The rules-repo delivery-set gate enforces this for
        // rules.txt; this guards the whole catalog at the pinned commit.
        val mirror = mirrorRoot()
        assumeTrue("submodule not checked out — skipping", mirror != null)
        requireNotNull(mirror)

        // mirrorRuleFiles' associateBy silently dedupes, so collisions must
        // be detected from the raw directory walk.
        val counts = mutableMapOf<String, MutableList<String>>()
        mirror.listFiles { f: File -> f.isDirectory && f.name !in EXCLUDED_DIRS }
            .orEmpty()
            .forEach { dir ->
                dir.listFiles { f: File -> f.extension == "yml" }.orEmpty()
                    .forEach { counts.getOrPut(it.name) { mutableListOf() }.add("${dir.name}/${it.name}") }
            }
        val dupes = counts.filterValues { it.size > 1 }
        assertTrue(
            "Duplicate rule basenames across mirror service dirs (parity would " +
                "be ambiguous): $dupes",
            dupes.isEmpty(),
        )
    }

    @Test
    fun `every bundled non-correlation rule is delivered byte-equal via rules_txt`() {
        val bundled = bundledDir()
        val mirror = mirrorRoot()
        assumeTrue("submodule not checked out — skipping", mirror != null)
        requireNotNull(mirror)

        // Key by basename but byte-compare the EXACT listed path — a
        // rules.txt entry pointing at a same-named file elsewhere (e.g.
        // staging/) must fail here, not pass on the name match.
        val deliveredByName = deliveredEntries(mirror).associateBy { it.substringAfterLast('/') }
        val failures = mutableListOf<String>()

        for (file in bundledRuleFiles(bundled)) {
            if (file.name.startsWith("sigma_androdr_corr_")) continue
            val name = file.name.removePrefix("sigma_")
            val entry = deliveredByName[name]
            when {
                entry == null ->
                    failures.add("$name: missing from rules.txt (OTA-unreachable)")
                !File(mirror, entry).isFile ->
                    failures.add("$name: rules.txt entry '$entry' does not exist")
                !File(mirror, entry).readBytes().contentEquals(file.readBytes()) ->
                    failures.add("$name: rules.txt delivers '$entry' which differs from bundled")
            }
        }

        assertTrue(
            "Delivery-channel parity broken:\n" + failures.joinToString("\n"),
            failures.isEmpty(),
        )
    }

    @Test
    fun `rules_txt never lists correlation or staging paths`() {
        // Correlation rules are cataloged but undeliverable (the on-device
        // parser drops remote corr payloads); staging rules are aspirational.
        // The rules repo's delivery-set gate enforces this on its main; this
        // enforces it at the pinned submodule commit.
        val mirror = mirrorRoot()
        assumeTrue("submodule not checked out — skipping", mirror != null)
        requireNotNull(mirror)

        val contained = deliveredEntries(mirror)
            .filter { it.substringBefore('/') in setOf("correlation", "staging") }
        assertTrue(
            "rules.txt lists undeliverable paths (see decisions/" +
                "2026-07-13-mirror-reconcile.yml): $contained",
            contained.isEmpty(),
        )
    }

    private companion object {
        val EXCLUDED_DIRS = setOf(
            "staging", "validation", "docs", "decisions",
            "ioc-data", "pipeline-runs", ".git", ".github",
        )
    }
}

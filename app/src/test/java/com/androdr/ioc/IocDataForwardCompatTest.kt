package com.androdr.ioc

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Forward-compat gate (spec R5): every threat file in the pinned rules repo's
 * `ioc-data/` must still be readable by the parsing that shipped binaries use,
 * so new provenance keys (`reference`, `campaign`, `block_by_default`, ...) can
 * be added to the data without breaking old app versions.
 *
 * Why this is sufficient: the named-key reads in [PublicRepoIocFeed.parseIocYaml]
 * (the `entries` list and the per-entry `indicator` / `family` / `category` /
 * `severity` / `description` keys) are unchanged since `d51ae42` (2026-03-28),
 * i.e. across every released version. Verified with
 * `git log -L '/internal fun parseIocYaml/,+15:...PublicRepoIocFeed.kt'`, which
 * lists only 402c4d7 and d51ae42. Unknown keys are simply never read.
 *
 * File selection mirrors the app: [PublicRepoIocFeed] fetches exactly
 * package-names, c2-domains, cert-hashes and malware-hashes through
 * `parseIocYaml` (each must yield entries with an `indicator`), and
 * popular-apps through `parsePopularAppsYaml`. campaigns.yml, brand-*.yml and
 * known-oem-prefixes.yml are never fed to the feed parser (separate resolvers),
 * so they are intentionally not asserted here.
 */
class IocDataForwardCompatTest {

    private val feed = PublicRepoIocFeed(
        indicatorDao = io.mockk.mockk(relaxed = true),
        knownAppEntryDao = io.mockk.mockk(relaxed = true)
    )

    private fun iocDataDir(): File {
        // Relative candidates only: a hardcoded absolute fallback could silently
        // test a different checkout than the one under test.
        val dir = listOf(
            File("third-party/android-sigma-rules/ioc-data"),
            File("../third-party/android-sigma-rules/ioc-data")
        ).firstOrNull { it.isDirectory }
        checkNotNull(dir) { "pinned ioc-data directory not found; run git submodule update --init" }
        return dir
    }

    @Test
    fun `every threat file parses and each entry yields an indicator value`() {
        val threatFiles = listOf(
            "package-names.yml", "c2-domains.yml", "cert-hashes.yml", "malware-hashes.yml"
        )
        for (name in threatFiles) {
            val file = File(iocDataDir(), name)
            assertTrue("$name missing from pinned ioc-data", file.isFile)
            val entries = feed.parseIocYaml(file.readText())
            assertTrue("$name yielded no entries", entries.isNotEmpty())
            entries.forEachIndexed { i, entry ->
                val indicator = entry["indicator"]?.toString()
                assertTrue("$name entry #$i has no indicator: $entry", !indicator.isNullOrBlank())
            }
        }
    }

    @Test
    fun `popular-apps parses with the popular apps parser`() {
        val file = File(iocDataDir(), "popular-apps.yml")
        assertTrue("popular-apps.yml missing from pinned ioc-data", file.isFile)
        val entries = feed.parsePopularAppsYaml(file.readText())
        assertTrue("popular-apps.yml yielded no entries", entries.isNotEmpty())
        entries.forEachIndexed { i, entry ->
            assertTrue("popular-apps entry #$i has no packageName", entry["packageName"] != null)
        }
    }
}

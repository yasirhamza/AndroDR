package com.androdr.ioc

import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Enforces bundled↔mirror parity for the OEM prefix allowlist.
 *
 * [OemPrefixResolver.refresh] fetches `ioc-data/known-oem-prefixes.yml` from
 * the android-sigma-rules repo's main every 12h and **replaces** the in-memory
 * allowlist wholesale (`data.set(parsed)` — not a merge). The bundled
 * `res/raw/known_oem_prefixes.yml` is therefore only a cold-start seed: within
 * 12h of install, every device is running the mirror copy. Any prefix present
 * in the bundle but missing from the mirror is silently dropped on-device.
 *
 * This is not hypothetical. #203 ("cover partner pre-installs in OEM
 * allowlist — HONOR FP fix") added `partner_preinstall_prefixes` plus
 * `org.codeaurora.` to the bundle on 2026-05-19. The mirror sync that day
 * (rules#26) captured #199 but not #203, so the HONOR fix never reached a
 * single device that refreshed its feed — dead in the field for two months
 * until an OPPO field report surfaced it (#263 follow-up).
 *
 * [com.androdr.sigma.BundledMirrorParityTest] guards the rule directories
 * only; its walk excludes `ioc-data`, which is why the drift went unnoticed.
 * This gate is deliberately file-specific rather than a blanket ioc-data
 * sweep: the OEM prefix allowlist and (since #299) the brand impersonation
 * registry seeds (`brand_names.yml`, `brand_domains.yml`) are the ioc-data
 * files with a bundled res/raw counterpart — add a case below if another
 * appears.
 *
 * There is a **third** hand-maintained copy at
 * `src/test/resources/raw/known_oem_prefixes.yml`, loaded by every
 * OemPrefixResolver/AppScanner unit test. It is not generated — when it
 * drifts, those tests assert against an allowlist that no device ever runs,
 * so it is gated here alongside the mirror.
 *
 * When this test fails: copy the bundled file over its mirror counterpart
 * (note the filename differs — underscores bundled, hyphens mirrored), bump
 * the `version:` field, and ship it via the safe ordering in CLAUDE.md.
 * Unlike `rules.txt` entries this feed has no sha256 manifest — `refresh()`
 * only sanity-checks prefix length and count — so nothing else will catch it.
 */
class OemPrefixMirrorParityTest {

    // A missing bundled file is a broken checkout, never a skippable
    // condition — only the (optional) submodule may assume-skip.
    private fun bundledFile(): File = listOf(
        File("app/src/main/res/raw/known_oem_prefixes.yml"),
        File("src/main/res/raw/known_oem_prefixes.yml"),
        File("/home/yasir/AndroDR/app/src/main/res/raw/known_oem_prefixes.yml"),
    ).firstOrNull { it.isFile }
        ?: error("known_oem_prefixes.yml not found — parity gate cannot run from this working directory")

    private fun mirrorFile(): File? = listOf(
        File("third-party/android-sigma-rules/ioc-data/known-oem-prefixes.yml"),
        File("../third-party/android-sigma-rules/ioc-data/known-oem-prefixes.yml"),
        File("/home/yasir/AndroDR/third-party/android-sigma-rules/ioc-data/known-oem-prefixes.yml"),
    ).firstOrNull { it.isFile }

    private fun testFixtureFile(): File = listOf(
        File("app/src/test/resources/raw/known_oem_prefixes.yml"),
        File("src/test/resources/raw/known_oem_prefixes.yml"),
        File("/home/yasir/AndroDR/app/src/test/resources/raw/known_oem_prefixes.yml"),
    ).firstOrNull { it.isFile }
        ?: error("test-resources known_oem_prefixes.yml not found — parity gate cannot run")

    @Test
    fun `bundled OEM prefix allowlist is byte-equal to its mirror counterpart`() {
        val bundled = bundledFile()
        val mirror = mirrorFile()
        // The skip is a local-convenience path only. `build-and-test` checks out
        // with `submodules: true`, so a missing mirror under CI means the
        // checkout regressed — skipping there would make this gate silently
        // green, which is the exact failure mode it exists to prevent.
        assertTrue(
            "submodule not checked out under CI — build-and-test uses " +
                "submodules: true, so this means the checkout regressed and the " +
                "parity gate would have passed without comparing anything",
            mirror != null || System.getenv("CI") != "true",
        )
        assumeTrue("submodule not checked out — skipping", mirror != null)
        requireNotNull(mirror)

        assertTrue(
            "known_oem_prefixes.yml differs from ioc-data/known-oem-prefixes.yml. " +
                "OemPrefixResolver.refresh() replaces the allowlist wholesale from the " +
                "mirror, so anything bundled-only is dropped on-device within 12h of " +
                "install (this is exactly how #203's HONOR fix died in the field). " +
                "Fix recipe in this test's KDoc.",
            mirror.readBytes().contentEquals(bundled.readBytes()),
        )
    }

    // ── Brand impersonation registry (#299): same feed model, same gate ──
    // BrandImpersonationResolver.refresh() also replaces its state wholesale
    // from the ioc-data mirrors, so the bundled seeds are cold-start-only and
    // bundled-only content dies on-device within 12h — the #203 failure mode.

    private fun brandPairs(): List<Pair<String, String>> = listOf(
        "brand_names.yml" to "brand-names.yml",
        "brand_domains.yml" to "brand-domains.yml",
    )

    private fun bundledBrandFile(name: String): File = listOf(
        File("app/src/main/res/raw/$name"),
        File("src/main/res/raw/$name"),
    ).firstOrNull { it.isFile }
        ?: error("$name not found — brand parity gate cannot run from this working directory")

    private fun mirrorBrandFile(name: String): File? = listOf(
        File("third-party/android-sigma-rules/ioc-data/$name"),
        File("../third-party/android-sigma-rules/ioc-data/$name"),
    ).firstOrNull { it.isFile }

    @Test
    fun `bundled brand registry seeds are byte-equal to their mirror counterparts`() {
        for ((bundledName, mirrorName) in brandPairs()) {
            val bundled = bundledBrandFile(bundledName)
            val mirror = mirrorBrandFile(mirrorName)
            assertTrue(
                "submodule not checked out under CI — build-and-test uses " +
                    "submodules: true, so this means the checkout regressed and the " +
                    "brand parity gate would have passed without comparing anything",
                mirror != null || System.getenv("CI") != "true",
            )
            assumeTrue("submodule not checked out — skipping", mirror != null)
            requireNotNull(mirror)

            assertTrue(
                "$bundledName differs from ioc-data/$mirrorName. " +
                    "BrandImpersonationResolver.refresh() replaces the registry " +
                    "wholesale from the mirror, so anything bundled-only is dropped " +
                    "on-device within 12h of install. Copy the mirror file over the " +
                    "bundled one (filenames differ: underscores bundled, hyphens " +
                    "mirrored) and ship via the safe ordering in CLAUDE.md.",
                mirror.readBytes().contentEquals(bundled.readBytes()),
            )
        }
    }

    @Test
    fun `unit-test fixture copy is byte-equal to the bundled allowlist`() {
        val bundled = bundledFile()
        val fixture = testFixtureFile()

        assertTrue(
            "src/test/resources/raw/known_oem_prefixes.yml differs from the bundled " +
                "res/raw copy. Every OemPrefixResolver and AppScanner unit test loads " +
                "the fixture, so while it is stale those tests assert against an " +
                "allowlist no device runs — a prefix can be added, pass CI, and still " +
                "be a false positive in the field. Copy the bundled file over it.",
            fixture.readBytes().contentEquals(bundled.readBytes()),
        )
    }
}

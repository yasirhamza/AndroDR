package com.androdr.sigma

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Rule-level tests for androdr-010 after the WebAPK exemption was removed
 * (reverses #296/#311). Loads the ACTUAL bundled rule file so the tests gate
 * the shipped artifact.
 *
 * Design decision (#311): Chrome-minted WebAPKs are NOT exempted — a minted
 * WebAPK can be a genuine credential-phishing app (Google's minter is
 * unauthenticated), so it must surface as a REVIEW-level "Sideloaded
 * Application" finding rather than be silently trusted. The only WebAPK
 * exemption that remains is the general from_trusted_store path (Play-installed
 * WebAPKs on older Android), which is not WebAPK-specific.
 *
 * The #311 lesson is retained: every record sets from_trusted_store EXPLICITLY,
 * so trusted-store exemption vs. sideload firing is never left ambiguous.
 */
class Rule010WebApkFilterTest {

    private fun loadRule(): SigmaRule {
        val f = listOf(
            File("app/src/main/res/raw/sigma_androdr_010_sideloaded_app.yml"),
            File("src/main/res/raw/sigma_androdr_010_sideloaded_app.yml"),
        ).firstOrNull { it.isFile }
            ?: error("bundled androdr-010 not found from ${File(".").absolutePath}")
        return SigmaRuleParser.parse(f.readText())
            ?: error("androdr-010 failed to parse")
    }

    // known_good_app_db MUST be present: the R1 fail-closed evaluator skips
    // any rule referencing a lookup name absent from this map.
    private val lookups = mapOf<String, (Any) -> Boolean>(
        "known_good_app_db" to { pkg -> pkg.toString() == "com.x8bit.bitwarden" }
    )

    private fun fires(record: Map<String, Any?>): Boolean =
        SigmaRuleEvaluator.evaluate(listOf(loadRule()), listOf(record), "app_scanner", lookups)
            .any { it.triggered }

    private fun app(pkg: String, fromTrustedStore: Boolean) = mapOf(
        "package_name" to pkg,
        "is_system_app" to false,
        "from_trusted_store" to fromTrustedStore,
        "is_known_oem_app" to false,
    )

    // ── WebAPKs are no longer exempted — they surface as reviewable sideloads ──

    @Test
    fun `non-store webapk fires (no exemption)`() =
        assertTrue(fires(app("org.chromium.webapk.a1b2c3d4", fromTrustedStore = false)))

    @Test
    fun `a second distinct webapk also fires (no per-device dependence)`() =
        assertTrue(fires(app("org.chromium.webapk.deadbeef99", fromTrustedStore = false)))

    // ── The only remaining exemption is the general trusted-store path ──

    @Test
    fun `play-installed webapk stays exempt via from_trusted_store`() =
        assertFalse(fires(app("org.chromium.webapk.a1b2c3d4", fromTrustedStore = true)))

    // ── Regression guards for the base rule ──

    @Test
    fun `plain sideload still fires`() =
        assertTrue(fires(app("com.random.sideload", fromTrustedStore = false)))

    @Test
    fun `trusted-store app does not fire`() =
        assertFalse(fires(app("com.some.playapp", fromTrustedStore = true)))

    @Test
    fun `known good app stays exempt via existing filter`() =
        assertFalse(fires(app("com.x8bit.bitwarden", fromTrustedStore = false)))
}

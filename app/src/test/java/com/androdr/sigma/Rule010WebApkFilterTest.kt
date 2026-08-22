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
 * exemption that remains is the general trusted-store path, expressed since
 * #136 Phase 2 as the negated `store_installed` selection
 * (installer|ioc_lookup: trusted_installer_db) — not WebAPK-specific.
 *
 * The #311 lesson is retained: every record sets its `installer` EXPLICITLY, so
 * trusted-store exemption vs. sideload firing is never left ambiguous. Post-#136
 * Phase 2 the trusted-store exemption is driven by the installer lookup rather
 * than the from_trusted_store boolean.
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

    // Both lookups MUST be present: the R1 fail-closed evaluator skips any rule
    // referencing a lookup name absent from this map. trusted_installer_db is
    // the #136 Phase 2 replacement for the from_trusted_store boolean.
    private val lookups = mapOf<String, (Any) -> Boolean>(
        "known_good_app_db" to { pkg -> pkg.toString() == "com.x8bit.bitwarden" },
        "trusted_installer_db" to { inst -> inst.toString() == "com.android.vending" },
    )

    private fun fires(record: Map<String, Any?>): Boolean =
        SigmaRuleEvaluator.evaluate(listOf(loadRule()), listOf(record), "app_scanner", lookups)
            .any { it.triggered }

    /**
     * @param installer drives the negated `store_installed` exemption
     *   (installer|ioc_lookup: trusted_installer_db). "com.android.vending" is
     *   the trusted store; null / any other value is an untrusted (sideload)
     *   install channel.
     */
    private fun app(pkg: String, installer: String?) = mapOf(
        "package_name" to pkg,
        "is_system_app" to false,
        "installer" to installer,
        "is_known_oem_app" to false,
    )

    // ── WebAPKs are no longer exempted — they surface as reviewable sideloads ──

    @Test
    fun `non-store webapk fires (no exemption)`() =
        assertTrue(fires(app("org.chromium.webapk.a1b2c3d4", installer = null)))

    @Test
    fun `a second distinct webapk also fires (no per-device dependence)`() =
        assertTrue(fires(app("org.chromium.webapk.deadbeef99", installer = "com.evil.sideloader")))

    // ── The only remaining exemption is the general trusted-store path ──

    @Test
    fun `play-installed webapk stays exempt via trusted installer`() =
        assertFalse(fires(app("org.chromium.webapk.a1b2c3d4", installer = "com.android.vending")))

    // ── Regression guards for the base rule ──

    @Test
    fun `plain sideload still fires`() =
        assertTrue(fires(app("com.random.sideload", installer = null)))

    @Test
    fun `trusted-store app does not fire`() =
        assertFalse(fires(app("com.some.playapp", installer = "com.android.vending")))

    @Test
    fun `known good app stays exempt via existing filter`() =
        assertFalse(fires(app("com.x8bit.bitwarden", installer = null)))
}

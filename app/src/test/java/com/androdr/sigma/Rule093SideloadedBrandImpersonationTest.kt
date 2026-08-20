package com.androdr.sigma

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Behavior spec for androdr-093 (#299): a sideloaded (non-store-installed)
 * native app whose display name matches a protected brand fires. The
 * known-good exemption is installer-gated and therefore deliberately
 * unreachable for sideloads (impersonation backstop — androdr-089 pattern);
 * WebAPKs are excluded (androdr-092's domain). Loads the ACTUAL bundled
 * rule file so the tests gate the shipped artifact.
 */
class Rule093SideloadedBrandImpersonationTest {

    private fun loadRule(): SigmaRule {
        val f = listOf(
            File("app/src/main/res/raw/sigma_androdr_093_sideloaded_brand_impersonation.yml"),
            File("src/main/res/raw/sigma_androdr_093_sideloaded_brand_impersonation.yml"),
        ).firstOrNull { it.isFile }
            ?: error("bundled androdr-093 not found from ${File(".").absolutePath}")
        return SigmaRuleParser.parse(f.readText())
            ?: error("androdr-093 failed to parse")
    }

    // All three lookups MUST be registered or the fail-closed evaluator
    // skips the rule whole.
    private val lookups = mapOf<String, (Any) -> Boolean>(
        "brand_name_db" to { v -> v.toString() == "PayPal" },
        "trusted_installer_db" to { v -> v.toString() == "com.android.vending" },
        "known_good_app_db" to { v -> v.toString() == "com.paypal.android.p2pmobile" },
    )

    private fun fires(record: Map<String, Any?>): Boolean =
        SigmaRuleEvaluator.evaluate(listOf(loadRule()), listOf(record), "app_scanner", lookups)
            .any { it.triggered }

    private fun app(
        appName: String,
        installer: String?,
        pkg: String = "com.fake.bankapp",
        isSystemApp: Boolean = false,
    ) = mapOf(
        "package_name" to pkg,
        "app_name" to appName,
        "installer" to installer,
        "is_system_app" to isSystemApp,
    )

    @Test
    fun `sideloaded brand-named app fires`() =
        assertTrue(fires(app("PayPal", installer = null)))

    @Test
    fun `store-installed brand-named app does not fire`() =
        assertFalse(fires(app("PayPal", installer = "com.android.vending")))

    @Test
    fun `sideloaded app with GENUINE brand package name still fires`() =
        // The known-good exemption is installer-gated: unreachable for
        // sideloads BY DESIGN (a fake can adopt any package name).
        assertTrue(fires(app("PayPal", installer = null, pkg = "com.paypal.android.p2pmobile")))

    @Test
    fun `system app does not fire`() =
        assertFalse(fires(app("PayPal", installer = null, isSystemApp = true)))

    @Test
    fun `webapk package is excluded (androdr-092 territory)`() =
        assertFalse(fires(app("PayPal", installer = null, pkg = "org.chromium.webapk.a1b2c3d4_v2")))

    @Test
    fun `sideloaded non-brand app does not fire`() =
        assertFalse(fires(app("Sudoku Deluxe", installer = null)))
}

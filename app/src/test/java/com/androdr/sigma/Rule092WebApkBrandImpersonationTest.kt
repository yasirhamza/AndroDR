package com.androdr.sigma

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Behavior spec for androdr-092 (#299): a WebAPK whose display name matches
 * a protected brand fires UNLESS its scope is inside the brand ecosystem's
 * official domains. Loads the ACTUAL bundled rule file so the tests gate
 * the shipped artifact.
 *
 * Anti-vacuity (#296 lesson): every record pins every field the rule
 * references, and installer-trust fields are pinned BOTH ways to prove the
 * rule is independent of them.
 */
class Rule092WebApkBrandImpersonationTest {

    private fun loadRule(): SigmaRule {
        val f = listOf(
            File("app/src/main/res/raw/sigma_androdr_092_webapk_brand_impersonation.yml"),
            File("src/main/res/raw/sigma_androdr_092_webapk_brand_impersonation.yml"),
        ).firstOrNull { it.isFile }
            ?: error("bundled androdr-092 not found from ${File(".").absolutePath}")
        return SigmaRuleParser.parse(f.readText())
            ?: error("androdr-092 failed to parse")
    }

    // Stubs stand in for BrandImpersonationResolver; matcher semantics are
    // covered by BrandImpersonationResolverTest. Both lookups MUST be
    // registered or the fail-closed evaluator skips the rule whole.
    private val lookups = mapOf<String, (Any) -> Boolean>(
        "brand_name_db" to { v -> v.toString() == "PayPal" },
        "brand_domain_db" to { v -> v.toString() == "https://paypal.com/" },
    )

    private fun fires(record: Map<String, Any?>): Boolean =
        SigmaRuleEvaluator.evaluate(listOf(loadRule()), listOf(record), "app_scanner", lookups)
            .any { it.triggered }

    private fun webapk(
        appName: String,
        scope: String?,
        pkg: String = "org.chromium.webapk.a1b2c3d4_v2",
        fromTrustedStore: Boolean = false,
        installer: String? = null,
    ) = mapOf(
        "package_name" to pkg,
        "app_name" to appName,
        "webapk_scope" to scope,
        "is_system_app" to false,
        "from_trusted_store" to fromTrustedStore,
        "installer" to installer,
    )

    @Test
    fun `brand-named webapk with foreign scope fires`() =
        assertTrue(fires(webapk("PayPal", "https://evil.example/")))

    @Test
    fun `genuine brand webapk with official scope does not fire`() =
        assertFalse(fires(webapk("PayPal", "https://paypal.com/")))

    @Test
    fun `play-installed brand-named webapk with foreign scope STILL fires`() =
        // Installer trust must not gate behavior — the #296 lesson.
        assertTrue(
            fires(
                webapk(
                    "PayPal", "https://evil.example/",
                    fromTrustedStore = true, installer = "com.android.vending",
                )
            )
        )

    @Test
    fun `brand-named webapk with NO scope meta-data fires`() =
        assertTrue(fires(webapk("PayPal", scope = null)))

    @Test
    fun `non-brand webapk does not fire`() =
        assertFalse(fires(webapk("Recipe Box", "https://recipes.example/")))

    @Test
    fun `brand-named NON-webapk package does not fire on this rule`() =
        assertFalse(fires(webapk("PayPal", null, pkg = "com.fake.paypal")))

    @Test
    fun `rule is high severity`() {
        val rule = loadRule()
        assertTrue(rule.level.equals("high", ignoreCase = true))
    }
}

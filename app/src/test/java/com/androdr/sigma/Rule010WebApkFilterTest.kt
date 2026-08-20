package com.androdr.sigma

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Rule-level tests for androdr-010's WebAPK exemption (#296/#311).
 * Loads the ACTUAL bundled rule file so the tests gate the shipped artifact.
 *
 * #311 lesson baked in: every record here sets `from_trusted_store` to false
 * EXPLICITLY, so the exemption filter itself is what's exercised — a record
 * that would be exempted by the trusted-store conjunct instead would make
 * these tests vacuously green (exactly how the #296 on-device verification
 * went wrong).
 *
 * Semantics under test: a WebAPK is exempt iff its package carries the
 * org.chromium.webapk. prefix AND its RECORDED installer is Play services or
 * Chrome (the system-attested minted-install channel). Cert anchoring
 * returns with the cert_hashes emitter in 0.9.0.617+ (#311).
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

    private fun app(pkg: String, installer: String?) = mapOf(
        "package_name" to pkg,
        "is_system_app" to false,
        // Explicit: the trusted-store conjunct must NOT be what exempts here.
        "from_trusted_store" to false,
        "is_known_oem_app" to false,
        "installer" to installer,
    )

    @Test
    fun `gms-installed webapk is exempt even when not trusted-store`() =
        assertFalse(fires(app("org.chromium.webapk.a1b2c3d4", "com.google.android.gms")))

    @Test
    fun `chrome-installed webapk is exempt even when not trusted-store`() =
        assertFalse(fires(app("org.chromium.webapk.a1b2c3d4", "com.android.chrome")))

    @Test
    fun `webapk with null installer still fires`() =
        assertTrue(fires(app("org.chromium.webapk.evil", null)))

    @Test
    fun `webapk installed by an arbitrary app still fires`() =
        assertTrue(fires(app("org.chromium.webapk.evil", "com.evil.installer")))

    @Test
    fun `gms installer on a non-webapk package still fires`() =
        assertTrue(fires(app("com.evil.app", "com.google.android.gms")))

    @Test
    fun `chrome installer on a non-webapk package still fires`() =
        assertTrue(fires(app("com.evil.app", "com.android.chrome")))

    @Test
    fun `webapk prefix without trailing dot still fires`() =
        assertTrue(fires(app("org.chromium.webapkevil", "com.evil.installer")))

    @Test
    fun `plain sideload still fires`() =
        assertTrue(fires(app("com.random.sideload", null)))

    @Test
    fun `known good app stays exempt via existing filter`() =
        assertFalse(fires(app("com.x8bit.bitwarden", null)))
}

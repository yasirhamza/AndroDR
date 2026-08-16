package com.androdr.sigma

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Rule-level tests for androdr-010's cert-anchored WebAPK exemption (#296).
 * Loads the ACTUAL bundled rule file so the tests gate the shipped artifact,
 * not a hand-built copy. The minter certs are duplicated here on purpose: if
 * the rule file's cert values drift, these tests fail.
 */
class Rule010WebApkFilterTest {

    private val minterCertSigner1 = "16ec831c994af033e958063c3555b22de7b078c4a6a424bdbebf7753ca73eceb"
    private val minterCertSigner2 = "f9a8f75a7f0b5d2ccae8c2b570855640e709995558cd9706af74b84e68962faa"

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

    private fun app(pkg: String, cert: String?) = mapOf(
        "package_name" to pkg,
        "is_system_app" to false,
        "from_trusted_store" to false,
        "is_known_oem_app" to false,
        "cert_hash" to cert,
    )

    @Test
    fun `google minted webapk is exempt`() =
        assertFalse(fires(app("org.chromium.webapk.a1b2c3d4", minterCertSigner1)))

    @Test
    fun `second co-signer cert is also exempt`() =
        assertFalse(fires(app("org.chromium.webapk.a1b2c3d4", minterCertSigner2)))

    @Test
    fun `webapk prefix with wrong cert still fires`() =
        assertTrue(fires(app("org.chromium.webapk.evil", "deadbeef".repeat(8))))

    @Test
    fun `minter cert on non webapk package still fires`() =
        assertTrue(fires(app("com.evil.app", minterCertSigner1)))

    @Test
    fun `webapk prefix with null cert still fires`() =
        assertTrue(fires(app("org.chromium.webapk.evil", null)))

    @Test
    fun `plain sideload still fires`() =
        assertTrue(fires(app("com.random.sideload", "ab".repeat(32))))

    @Test
    fun `known good app stays exempt`() =
        assertFalse(fires(app("com.x8bit.bitwarden", "ab".repeat(32))))

    @Test
    fun `cert match is case insensitive`() =
        assertFalse(fires(app("org.chromium.webapk.a1b2c3d4", minterCertSigner1.uppercase())))
}

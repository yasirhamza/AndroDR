package com.androdr.sigma

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Rule-level tests for androdr-066 after the #331 sideload gate: the rule
 * moved from `receiver_audit` (fired on ANY non-system boot receiver — six
 * store-installed false positives on a clean device) to `app_scanner`, and
 * fires only when a boot receiver co-occurs with a sideload signal. Loads
 * the ACTUAL bundled rule file so the tests gate the shipped artifact.
 *
 * Mirrors androdr-010's #136 Phase 2 shape: the store exemption is the
 * negated `store_installed` selection (installer|ioc_lookup:
 * trusted_installer_db), not the from_trusted_store boolean.
 */
class Rule066BootPersistenceGateTest {

    private fun loadRule(): SigmaRule {
        val f = listOf(
            File("app/src/main/res/raw/sigma_androdr_066_boot_persistence.yml"),
            File("src/main/res/raw/sigma_androdr_066_boot_persistence.yml"),
        ).firstOrNull { it.isFile }
            ?: error("bundled androdr-066 not found from ${File(".").absolutePath}")
        return SigmaRuleParser.parse(f.readText())
            ?: error("androdr-066 failed to parse")
    }

    // Both lookups MUST be present: the R1 fail-closed evaluator skips any rule
    // referencing a lookup name absent from this map.
    private val lookups = mapOf<String, (Any) -> Boolean>(
        "known_good_app_db" to { pkg -> pkg.toString() == "com.x8bit.bitwarden" },
        "trusted_installer_db" to { inst -> inst.toString() == "com.android.vending" },
    )

    private fun fires(record: Map<String, Any?>): Boolean =
        SigmaRuleEvaluator.evaluate(listOf(loadRule()), listOf(record), "app_scanner", lookups)
            .any { it.triggered }

    private fun app(
        pkg: String,
        installer: String?,
        hasBootReceiver: Boolean = true,
        isSystem: Boolean = false,
    ) = mapOf(
        "package_name" to pkg,
        "installer" to installer,
        "has_boot_receiver" to hasBootReceiver,
        "is_system_app" to isSystem,
    )

    // ── The gated detection: boot receiver + sideload fires ──

    @Test
    fun `sideloaded app with boot receiver fires`() =
        assertTrue(fires(app("com.evil.persist", installer = null)))

    @Test
    fun `untrusted installer with boot receiver fires`() =
        assertTrue(fires(app("com.evil.persist", installer = "com.shady.store")))

    // ── The #331 false-positive class: store-installed apps stay silent ──

    @Test
    fun `play-installed app with boot receiver does not fire`() =
        assertFalse(fires(app("com.AmexApp", installer = "com.android.vending")))

    // ── Non-sideload postures stay silent ──

    @Test
    fun `system app with boot receiver does not fire`() =
        assertFalse(fires(app("com.oem.system", installer = null, isSystem = true)))

    // OEM preloads are exempt via the known-good DB (is_known_oem_app is a
    // judgment-kind field the #136 emitter contract forbids new rules from
    // referencing) — represented here by the known_good_app_db lookup case.
    @Test
    fun `known good app stays exempt via existing filter`() =
        assertFalse(fires(app("com.x8bit.bitwarden", installer = null)))

    @Test
    fun `sideloaded app without boot receiver does not fire`() =
        assertFalse(fires(app("com.random.sideload", installer = null, hasBootReceiver = false)))

    // ── FLEET SAFETY regression guard (#331): has_boot_receiver appears only in
    // a POSITIVE selection, so a record from an old binary that does not emit
    // the field must evaluate silent — never invert into a fire. ──

    @Test
    fun `record missing has_boot_receiver entirely stays silent (old fleet)`() {
        val oldBinaryRecord = mapOf<String, Any?>(
            "package_name" to "com.evil.persist",
            "installer" to null,
            "is_system_app" to false,
            "is_known_oem_app" to false,
        )
        assertFalse(fires(oldBinaryRecord))
    }
}

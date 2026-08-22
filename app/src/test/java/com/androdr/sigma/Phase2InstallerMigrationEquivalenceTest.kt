// app/src/test/java/com/androdr/sigma/Phase2InstallerMigrationEquivalenceTest.kt
package com.androdr.sigma

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Phase 2 (#136) semantic-equivalence gate: proves that migrating a bundled
 * rule's detection from the legacy `from_trusted_store` boolean field onto
 * `installer|ioc_lookup: trusted_installer_db` preserves firing behavior
 * exactly, for one representative of each of the two transforms:
 *
 *  - **Transform A** (androdr-010, androdr-011): the positive `selection`
 *    block drops `from_trusted_store: false` in favor of a sibling
 *    `store_installed` block, negated in the condition.
 *  - **Transform B** (androdr-089, androdr-068, and again androdr-011): a
 *    filter block's `from_trusted_store: true` matcher is replaced in place
 *    by `installer|ioc_lookup: trusted_installer_db`.
 *
 * Each test loads the ACTUAL bundled rule file by basename (not a synthetic
 * copy), so it proves the shipped YAML's real field names and condition —
 * not a hand-authored stand-in that would pass regardless of whether the
 * migration actually happened. Split out of SigmaRuleEvaluatorTest to keep
 * that class under detekt's LargeClass threshold.
 */
class Phase2InstallerMigrationEquivalenceTest {

    private fun loadBundledRule(fileName: String): SigmaRule {
        val candidates = listOf(
            File("app/src/main/res/raw/$fileName"),
            File("src/main/res/raw/$fileName"),
            File("/home/yasir/AndroDR/app/src/main/res/raw/$fileName"),
        )
        val file = candidates.firstOrNull { it.isFile }
            ?: error("$fileName not found; tried: ${candidates.map { it.absolutePath }}")
        return SigmaRuleParser.parse(file.readText()) ?: error("$fileName failed to parse")
    }

    /** The Phase 2 (#136) pure-emitter lookup stand-in: only enumerated stores are trusted. */
    private val trustedInstallerLookup: (Any) -> Boolean = { v ->
        v.toString() in setOf("com.android.vending", "com.sec.android.app.samsungapps")
    }

    @Test
    fun `androdr-010 migrated semantics match pre-migration from_trusted_store behavior (#136)`() {
        // Transform A: selection drops from_trusted_store, gains sibling `store_installed`
        // keyed on installer|ioc_lookup: trusted_installer_db; condition negates it.
        val rule = loadBundledRule("sigma_androdr_010_sideloaded_app.yml")
        val lookups = mapOf<String, (Any) -> Boolean>(
            "trusted_installer_db" to trustedInstallerLookup,
            "known_good_app_db" to { false }, // isolate the installer effect
        )
        fun base(installer: String?) = mapOf<String, Any?>(
            "is_system_app" to false,
            "is_known_oem_app" to false,
            "package_name" to "com.evil.foo",
            "installer" to installer,
        )

        assertTrue(
            "sideloaded (installer=null) must fire",
            SigmaRuleEvaluator.evaluate(listOf(rule), listOf(base(null)), "app_scanner", lookups)
                .any { it.triggered },
        )
        assertTrue(
            "store-installed (com.android.vending) must NOT fire",
            SigmaRuleEvaluator.evaluate(
                listOf(rule), listOf(base("com.android.vending")), "app_scanner", lookups
            ).none { it.triggered },
        )
        assertTrue(
            "untrusted installer (com.evil.foo) must fire",
            SigmaRuleEvaluator.evaluate(listOf(rule), listOf(base("com.evil.foo")), "app_scanner", lookups)
                .any { it.triggered },
        )
    }

    @Test
    fun `androdr-011 migrated semantics match pre-migration behavior for both transforms (#136)`() {
        // Transform A (selection → store_installed) AND Transform B
        // (filter_known_good's from_trusted_store: true → installer|ioc_lookup).
        val rule = loadBundledRule("sigma_androdr_011_surveillance_permissions.yml")
        val lookups = mapOf<String, (Any) -> Boolean>(
            "trusted_installer_db" to trustedInstallerLookup,
            "known_good_app_db" to { false }, // isolate the installer effect
        )
        fun base(installer: String?) = mapOf<String, Any?>(
            "is_system_app" to false,
            "is_known_oem_app" to false,
            "surveillance_permission_count" to 3,
            "package_name" to "com.evil.foo",
            "installer" to installer,
        )

        assertTrue(
            "sideloaded (installer=null) must fire",
            SigmaRuleEvaluator.evaluate(listOf(rule), listOf(base(null)), "app_scanner", lookups)
                .any { it.triggered },
        )
        assertTrue(
            "store-installed (com.android.vending) must NOT fire",
            SigmaRuleEvaluator.evaluate(
                listOf(rule), listOf(base("com.android.vending")), "app_scanner", lookups
            ).none { it.triggered },
        )
        assertTrue(
            "untrusted installer (com.evil.foo) must fire",
            SigmaRuleEvaluator.evaluate(listOf(rule), listOf(base("com.evil.foo")), "app_scanner", lookups)
                .any { it.triggered },
        )
    }

    @Test
    fun `androdr-089 migrated semantics match pre-migration behavior (Transform B, is_sideloaded selection) (#136)`() {
        // Selection keeps its literal `is_sideloaded: true` untouched; only
        // filter_known_good's from_trusted_store: true migrates to
        // installer|ioc_lookup: trusted_installer_db.
        val rule = loadBundledRule("sigma_androdr_089_sms_notification_otp_theft.yml")
        val lookups = mapOf<String, (Any) -> Boolean>(
            "trusted_installer_db" to trustedInstallerLookup,
            "known_good_app_db" to { pkg -> pkg.toString() == "com.google.android.apps.messaging" },
        )
        // is_sideloaded is forced true regardless of installer, to isolate
        // filter_known_good's own gating logic (a realistic record never pairs
        // is_sideloaded=true with a trusted installer — see class-level rule KDoc).
        fun base(installer: String?) = mapOf<String, Any?>(
            "is_sideloaded" to true,
            "permissions" to listOf("RECEIVE_SMS"),
            "service_permissions" to listOf("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"),
            "package_name" to "com.google.android.apps.messaging",
            "installer" to installer,
        )

        assertTrue(
            "sideloaded (installer=null) must fire despite known-good package name",
            SigmaRuleEvaluator.evaluate(listOf(rule), listOf(base(null)), "app_scanner", lookups)
                .any { it.triggered },
        )
        assertTrue(
            "genuinely store-installed (com.android.vending) known-good package must be exempt",
            SigmaRuleEvaluator.evaluate(
                listOf(rule), listOf(base("com.android.vending")), "app_scanner", lookups
            ).none { it.triggered },
        )
        assertTrue(
            "untrusted installer (com.evil.foo) must fire despite known-good package name",
            SigmaRuleEvaluator.evaluate(listOf(rule), listOf(base("com.evil.foo")), "app_scanner", lookups)
                .any { it.triggered },
        )
    }

    @Test
    fun `androdr-068 migrated semantics match pre-migration behavior (Transform B, separate filter) (#136)`() {
        // filter_trusted_store is its own block (distinct from filter_known_good);
        // its lone from_trusted_store: true matcher migrates to installer|ioc_lookup.
        val rule = loadBundledRule("sigma_androdr_068_hidden_launcher.yml")
        val lookups = mapOf<String, (Any) -> Boolean>(
            "trusted_installer_db" to trustedInstallerLookup,
            "known_good_app_db" to { false }, // isolate the installer effect
        )
        fun base(installer: String?) = mapOf<String, Any?>(
            "has_launcher_activity" to false,
            "is_system_app" to false,
            "is_known_oem_app" to false,
            "package_name" to "com.evil.hidden",
            "installer" to installer,
        )

        assertTrue(
            "sideloaded (installer=null) must fire",
            SigmaRuleEvaluator.evaluate(listOf(rule), listOf(base(null)), "app_scanner", lookups)
                .any { it.triggered },
        )
        assertTrue(
            "store-installed (com.android.vending) must NOT fire",
            SigmaRuleEvaluator.evaluate(
                listOf(rule), listOf(base("com.android.vending")), "app_scanner", lookups
            ).none { it.triggered },
        )
        assertTrue(
            "untrusted installer (com.evil.foo) must fire",
            SigmaRuleEvaluator.evaluate(listOf(rule), listOf(base("com.evil.foo")), "app_scanner", lookups)
                .any { it.triggered },
        )
    }
}

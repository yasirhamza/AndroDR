package com.androdr.sigma

import com.androdr.scanner.AppScanner
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * End-to-end firing test for androdr-089 (#247): sideloaded app that both holds
 * RECEIVE_SMS and binds a NotificationListenerService — the OTP-theft signature
 * of SMS-stealing banking trojans (Mamont, RedWing, GoldPickaxe).
 *
 * Loads and parses the ACTUAL bundled YAML (not a synthetic copy), so it proves
 * the shipped rule's exact field names, its three-condition floor, and its
 * trusted-store-gated known-good filter all behave — the pipeline's Gate-5
 * rejected the original candidate because the telemetry half (RECEIVE_SMS in the
 * exposed permission set) did not exist; this guards both halves against silent
 * regression.
 */
class Rule089OtpTheftTest {

    private fun loadRule(): SigmaRule {
        val file = listOf(
            File("app/src/main/res/raw/sigma_androdr_089_sms_notification_otp_theft.yml"),
            File("src/main/res/raw/sigma_androdr_089_sms_notification_otp_theft.yml"),
            File("/home/yasir/AndroDR/app/src/main/res/raw/sigma_androdr_089_sms_notification_otp_theft.yml"),
        ).firstOrNull { it.isFile } ?: error("androdr-089 rule file not found")
        return SigmaRuleParser.parse(file.readText())
            ?: error("androdr-089 failed to parse")
    }

    // The rule filters on package_name|ioc_lookup: known_good_app_db.
    private val knownGoodLookup = mapOf<String, (Any) -> Boolean>(
        "known_good_app_db" to { pkg -> pkg.toString() == "com.google.android.apps.messaging" },
    )

    /**
     * @param sideloaded also drives from_trusted_store — the two are inverse in
     *   AppScanner (is_sideloaded = !system && !fromTrustedStore && !knownOem), so
     *   a realistic record never has both true.
     */
    private fun record(
        sideloaded: Boolean = true,
        permissions: List<String> = listOf("RECEIVE_SMS"),
        // The scanner emits the FQN for service_permissions (ServiceInfo.permission).
        servicePermissions: List<String> = listOf("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"),
        packageName: String = "com.evil.mamont",
    ): Map<String, Any?> = mapOf(
        "is_sideloaded" to sideloaded,
        "from_trusted_store" to !sideloaded,
        "permissions" to permissions,
        "service_permissions" to servicePermissions,
        "package_name" to packageName,
    )

    private fun fires(record: Map<String, Any?>): Boolean =
        SigmaRuleEvaluator.evaluate(listOf(loadRule()), listOf(record), "app_scanner", knownGoodLookup)
            .any { it.triggered }

    @Test
    fun `RECEIVE_SMS is exposed by the scanner so the rule literal can match`() {
        // The telemetry half of #247 — without this the rule is a dead literal.
        assertTrue(
            "AppScanner must expose RECEIVE_SMS in the permissions field",
            AppScanner.EXPOSED_PERMISSION_SHORT_NAMES.contains("RECEIVE_SMS"),
        )
    }

    @Test
    fun `rule parses and is high severity`() {
        val rule = loadRule()
        assertNotNull(rule)
        assertTrue("androdr-089 should be level high", rule.level.equals("high", ignoreCase = true))
    }

    @Test
    fun `fires on the full sideloaded SMS plus notification combo`() {
        assertTrue("OTP-theft combo on an unknown sideloaded app must fire", fires(record()))
    }

    @Test
    fun `does not fire without RECEIVE_SMS`() {
        assertFalse(
            "notification listener alone (no SMS interception) must not fire androdr-089",
            fires(record(permissions = listOf("NFC"))),
        )
    }

    @Test
    fun `does not fire without the notification listener binding`() {
        assertFalse(
            "SMS interception alone (no notification access) must not fire androdr-089",
            fires(record(servicePermissions = emptyList())),
        )
    }

    @Test
    fun `does not fire on a trusted-store app`() {
        assertFalse(
            "a store-installed app with the same capabilities must not fire",
            fires(record(sideloaded = false)),
        )
    }

    @Test
    fun `sideloaded impersonator of a known-good package still fires`() {
        // Security regression guard (ceremony finding): the known-good filter is
        // gated on from_trusted_store, so a sideloaded banker cannot escape by
        // declaring a known-good package name. Without that gate this exact
        // record would be silently exempted (the androdr-011 bypass class).
        assertTrue(
            "a sideloaded app impersonating a known-good package must NOT be exempted",
            fires(record(packageName = "com.google.android.apps.messaging")),
        )
    }
}

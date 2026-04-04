package com.androdr.sigma

import org.junit.Assert.assertTrue
import org.junit.Test

class KnownGoodFilterTest {

    @Test
    fun `rule with filter_known_good suppresses known good app`() {
        val rule = SigmaRule(
            id = "test-065", title = "Test", status = "production",
            description = "", product = "androdr", service = "appops_audit",
            level = "medium", tags = emptyList(),
            detection = SigmaDetection(
                selections = mapOf(
                    "selection" to SigmaSelection(listOf(
                        SigmaFieldMatcher(
                            "operation", SigmaModifier.EQUALS,
                            listOf("android:request_install_packages")
                        ),
                        SigmaFieldMatcher(
                            "is_system_app", SigmaModifier.EQUALS, listOf(false)
                        )
                    )),
                    "filter_known_good" to SigmaSelection(listOf(
                        SigmaFieldMatcher("package_name", SigmaModifier.IOC_LOOKUP, listOf("known_good_db"))
                    ))
                ),
                condition = "selection and not filter_known_good"
            ),
            falsepositives = emptyList(), remediation = emptyList(),
            display = SigmaDisplay(category = "app_risk")
        )

        val iocLookups = mapOf<String, (Any) -> Boolean>(
            "known_good_db" to { pkg ->
                pkg.toString() in setOf("com.google.android.apps.docs", "com.x8bit.bitwarden")
            }
        )

        // Known good app — should NOT fire
        val googleDrive = mapOf<String, Any?>(
            "operation" to "android:request_install_packages",
            "is_system_app" to false,
            "package_name" to "com.google.android.apps.docs"
        )
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(googleDrive), "appops_audit", iocLookups)
        val triggered = findings.filter { it.triggered }
        assertTrue("Google Drive should NOT trigger", triggered.isEmpty())

        // Unknown app — SHOULD fire
        val evilApp = mapOf<String, Any?>(
            "operation" to "android:request_install_packages",
            "is_system_app" to false,
            "package_name" to "com.evil.installer"
        )
        val evilFindings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(evilApp), "appops_audit", iocLookups)
        val evilTriggered = evilFindings.filter { it.triggered }
        assertTrue("Evil app should trigger", evilTriggered.isNotEmpty())
    }
}

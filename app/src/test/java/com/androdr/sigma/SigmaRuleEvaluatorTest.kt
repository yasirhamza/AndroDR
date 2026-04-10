// app/src/test/java/com/androdr/sigma/SigmaRuleEvaluatorTest.kt
package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SigmaRuleEvaluatorTest {

    private fun makeRule(
        id: String = "test",
        service: String = "app_scanner",
        selections: Map<String, SigmaSelection>,
        condition: String = "selection",
        level: String = "high",
        category: RuleCategory = RuleCategory.INCIDENT,
        reportSafeState: Boolean = false,
    ) = SigmaRule(
        id = id, title = "Test", status = "production", description = "",
        product = "androdr", service = service, level = level,
        category = category,
        tags = emptyList(), detection = SigmaDetection(selections, condition),
        falsepositives = emptyList(), remediation = listOf("Fix it"),
        display = SigmaDisplay(category = if (service == "device_auditor") "device_posture" else "app_risk"),
        reportSafeState = reportSafeState
    )

    @Test
    fun `matches boolean field`() {
        val rule = makeRule(selections = mapOf(
            "selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("is_sideloaded", SigmaModifier.EQUALS, listOf(true))
            ))
        ))
        val record = mapOf<String, Any?>("is_sideloaded" to true)
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner")
        assertEquals(1, findings.size)
    }

    @Test
    fun `no match when field differs`() {
        val rule = makeRule(selections = mapOf(
            "selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("is_sideloaded", SigmaModifier.EQUALS, listOf(true))
            ))
        ))
        val record = mapOf<String, Any?>("is_sideloaded" to false)
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner")
        assertEquals(0, findings.size)
    }

    @Test
    fun `contains modifier matches substring`() {
        val rule = makeRule(selections = mapOf(
            "selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("app_name", SigmaModifier.CONTAINS, listOf("System"))
            ))
        ))
        val record = mapOf<String, Any?>("app_name" to "System Service")
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner")
        assertEquals(1, findings.size)
    }

    @Test
    fun `gte modifier matches numeric field`() {
        val rule = makeRule(selections = mapOf(
            "selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("surveillance_permission_count", SigmaModifier.GTE, listOf(4))
            ))
        ))
        val match = mapOf<String, Any?>("surveillance_permission_count" to 5)
        val noMatch = mapOf<String, Any?>("surveillance_permission_count" to 2)
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(match), "app_scanner").size)
        assertEquals(0, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(noMatch), "app_scanner").size)
    }

    @Test
    fun `compound AND condition`() {
        val rule = makeRule(
            selections = mapOf(
                "sel_a" to SigmaSelection(listOf(
                    SigmaFieldMatcher("is_sideloaded", SigmaModifier.EQUALS, listOf(true))
                )),
                "sel_b" to SigmaSelection(listOf(
                    SigmaFieldMatcher("has_accessibility_service", SigmaModifier.EQUALS, listOf(true))
                ))
            ),
            condition = "sel_a and sel_b"
        )
        val bothTrue = mapOf<String, Any?>("is_sideloaded" to true, "has_accessibility_service" to true)
        val oneTrue = mapOf<String, Any?>("is_sideloaded" to true, "has_accessibility_service" to false)
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(bothTrue), "app_scanner").size)
        assertEquals(0, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(oneTrue), "app_scanner").size)
    }

    @Test
    fun `ioc_lookup modifier delegates to lookup function`() {
        val rule = makeRule(selections = mapOf(
            "selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("cert_hash", SigmaModifier.IOC_LOOKUP, listOf("cert_hash_ioc_db"))
            ))
        ))
        val knownBad = setOf("abc123")
        val lookups = mapOf<String, (Any) -> Boolean>("cert_hash_ioc_db" to { v -> v.toString() in knownBad })

        val match = mapOf<String, Any?>("cert_hash" to "abc123")
        val noMatch = mapOf<String, Any?>("cert_hash" to "def456")
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(match), "app_scanner", lookups).size)
        assertEquals(0, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(noMatch), "app_scanner", lookups).size)
    }

    @Test
    fun `skips rules for different service`() {
        val rule = makeRule(service = "device_auditor", selections = mapOf(
            "selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("adb_enabled", SigmaModifier.EQUALS, listOf(true))
            ))
        ))
        val record = mapOf<String, Any?>("adb_enabled" to true)
        assertEquals(0, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner").size)
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "device_auditor").size)
    }

    @Test
    fun `condition expression evaluator`() {
        assertTrue(SigmaRuleEvaluator.evaluateConditionExpression("a and b", mapOf("a" to true, "b" to true)))
        assertFalse(SigmaRuleEvaluator.evaluateConditionExpression("a and b", mapOf("a" to true, "b" to false)))
        assertTrue(SigmaRuleEvaluator.evaluateConditionExpression("a or b", mapOf("a" to false, "b" to true)))
        assertFalse(SigmaRuleEvaluator.evaluateConditionExpression("a or b", mapOf("a" to false, "b" to false)))
    }

    @Test
    fun `condition expression supports not operator`() {
        // "selection and not filter" — the pattern used by known_good_app_db rules
        // selection=true, filter=true → should NOT fire (known good app)
        assertFalse(SigmaRuleEvaluator.evaluateConditionExpression(
            "selection and not filter", mapOf("selection" to true, "filter" to true)
        ))
        // selection=true, filter=false → SHOULD fire (unknown app)
        assertTrue(SigmaRuleEvaluator.evaluateConditionExpression(
            "selection and not filter", mapOf("selection" to true, "filter" to false)
        ))
        // selection=false, filter=false → should NOT fire (doesn't match selection)
        assertFalse(SigmaRuleEvaluator.evaluateConditionExpression(
            "selection and not filter", mapOf("selection" to false, "filter" to false)
        ))
    }

    @Test
    fun `condition expression supports leading not`() {
        assertTrue(SigmaRuleEvaluator.evaluateConditionExpression(
            "not a", mapOf("a" to false)
        ))
        assertFalse(SigmaRuleEvaluator.evaluateConditionExpression(
            "not a", mapOf("a" to true)
        ))
    }

    @Test
    fun `condition expression supports or with not`() {
        // "sel_a and not filter or sel_b and not filter" — pattern from call receiver rule
        assertTrue(SigmaRuleEvaluator.evaluateConditionExpression(
            "sel_a and not filter or sel_b and not filter",
            mapOf("sel_a" to true, "sel_b" to false, "filter" to false)
        ))
        assertTrue(SigmaRuleEvaluator.evaluateConditionExpression(
            "sel_a and not filter or sel_b and not filter",
            mapOf("sel_a" to false, "sel_b" to true, "filter" to false)
        ))
        // Both match but filter is true → neither should fire
        assertFalse(SigmaRuleEvaluator.evaluateConditionExpression(
            "sel_a and not filter or sel_b and not filter",
            mapOf("sel_a" to true, "sel_b" to true, "filter" to true)
        ))
    }

    @Test
    fun `ioc_lookup filter integration with not operator`() {
        // Simulates the known_good_app_db pattern end-to-end
        val rule = makeRule(
            selections = mapOf(
                "selection" to SigmaSelection(listOf(
                    SigmaFieldMatcher("is_system_app", SigmaModifier.EQUALS, listOf(false)),
                    SigmaFieldMatcher("is_enabled", SigmaModifier.EQUALS, listOf(true))
                )),
                "filter_known_good" to SigmaSelection(listOf(
                    SigmaFieldMatcher("package_name", SigmaModifier.IOC_LOOKUP, listOf("known_good_db"))
                ))
            ),
            condition = "selection and not filter_known_good"
        )

        val iocLookups = mapOf<String, (Any) -> Boolean>(
            "known_good_db" to { pkg -> pkg.toString() in setOf("com.x8bit.bitwarden", "com.google.chrome") }
        )

        // Known good app — should NOT fire
        val knownGoodRecord = mapOf<String, Any?>(
            "is_system_app" to false, "is_enabled" to true,
            "package_name" to "com.x8bit.bitwarden"
        )
        val knownGoodFindings = SigmaRuleEvaluator.evaluate(
            listOf(rule), listOf(knownGoodRecord), "app_scanner", iocLookups
        )
        assertTrue("Known good app should not trigger", knownGoodFindings.none { it.triggered })

        // Unknown app — SHOULD fire
        val unknownRecord = mapOf<String, Any?>(
            "is_system_app" to false, "is_enabled" to true,
            "package_name" to "com.evil.spy"
        )
        val unknownFindings = SigmaRuleEvaluator.evaluate(
            listOf(rule), listOf(unknownRecord), "app_scanner", iocLookups
        )
        assertTrue("Unknown app should trigger", unknownFindings.any { it.triggered })
    }

    @Test
    fun `rule 011 pattern - sideloaded impersonator is not exempted by package-name allowlist`() {
        // Regression: rule 011 used `package_name|ioc_lookup: known_good_app_db` alone in
        // filter_known_good. A sideloaded impersonator (e.g. com.android.chrome installed from
        // an untrusted source) could be silently exempted because the allowlist match was
        // package-name-only. Fix: require `from_trusted_store: true` in the filter clause so
        // sideloaded apps can never reach the exemption.
        val rule = makeRule(
            selections = mapOf(
                "selection" to SigmaSelection(listOf(
                    SigmaFieldMatcher("is_system_app", SigmaModifier.EQUALS, listOf(false)),
                    SigmaFieldMatcher("from_trusted_store", SigmaModifier.EQUALS, listOf(false)),
                    SigmaFieldMatcher("surveillance_permission_count", SigmaModifier.GTE, listOf(2))
                )),
                "filter_known_good" to SigmaSelection(listOf(
                    SigmaFieldMatcher("package_name", SigmaModifier.IOC_LOOKUP, listOf("known_good_db")),
                    SigmaFieldMatcher("from_trusted_store", SigmaModifier.EQUALS, listOf(true))
                ))
            ),
            condition = "selection and not filter_known_good"
        )
        val iocLookups = mapOf<String, (Any) -> Boolean>(
            "known_good_db" to { pkg -> pkg.toString() == "com.android.chrome" }
        )

        // Sideloaded impersonator: package matches allowlist BUT not from trusted store →
        // filter must NOT exempt → rule SHOULD fire.
        val impersonator = mapOf<String, Any?>(
            "is_system_app" to false,
            "from_trusted_store" to false,
            "surveillance_permission_count" to 3,
            "package_name" to "com.android.chrome"
        )
        val impersonatorFindings = SigmaRuleEvaluator.evaluate(
            listOf(rule), listOf(impersonator), "app_scanner", iocLookups
        )
        assertTrue(
            "Sideloaded impersonator must not be exempted by package-name allowlist",
            impersonatorFindings.any { it.triggered }
        )
    }

    @Test
    fun `device posture rule emits safe finding when not matched and reportSafeState is true`() {
        val rule = makeRule(
            service = "device_auditor",
            reportSafeState = true,
            selections = mapOf("selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("adb_enabled", SigmaModifier.EQUALS, listOf(true))
            )))
        ).copy(display = SigmaDisplay(
            category = "device_posture",
            triggeredTitle = "ADB Enabled",
            safeTitle = "ADB Disabled",
            evidenceType = "none"
        ))
        val record = mapOf<String, Any?>("adb_enabled" to false)
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "device_auditor")
        assertEquals(1, findings.size)
        assertEquals(false, findings[0].triggered)
        assertEquals("ADB Disabled", findings[0].title)
        assertEquals(FindingCategory.DEVICE_POSTURE, findings[0].category)
    }

    @Test
    fun `device posture rule without reportSafeState does not emit when not matched`() {
        val rule = makeRule(
            service = "device_auditor",
            reportSafeState = false,
            selections = mapOf("selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("adb_enabled", SigmaModifier.EQUALS, listOf(true))
            )))
        ).copy(display = SigmaDisplay(
            category = "device_posture",
            triggeredTitle = "ADB Enabled",
            safeTitle = "ADB Disabled",
            evidenceType = "none"
        ))
        val record = mapOf<String, Any?>("adb_enabled" to false)
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "device_auditor")
        assertEquals(0, findings.size)
    }

    @Test
    fun `device posture rule emits triggered finding with display title`() {
        val rule = makeRule(
            service = "device_auditor",
            reportSafeState = true,
            selections = mapOf("selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("adb_enabled", SigmaModifier.EQUALS, listOf(true))
            )))
        ).copy(display = SigmaDisplay(
            category = "device_posture",
            triggeredTitle = "ADB Enabled",
            safeTitle = "ADB Disabled",
            evidenceType = "none"
        ))
        val record = mapOf<String, Any?>("adb_enabled" to true)
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "device_auditor")
        assertEquals(1, findings.size)
        assertEquals(true, findings[0].triggered)
        assertEquals("ADB Enabled", findings[0].title)
    }

    @Test
    fun `app_risk rule does not emit when not matched`() {
        val rule = makeRule(selections = mapOf("selection" to SigmaSelection(listOf(
            SigmaFieldMatcher("is_sideloaded", SigmaModifier.EQUALS, listOf(true))
        )))).copy(display = SigmaDisplay(category = "app_risk"))
        val record = mapOf<String, Any?>("is_sideloaded" to false)
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner")
        assertEquals(0, findings.size)
    }

    @Test
    fun `evidence provider called when evidence_type is set`() {
        val rule = makeRule(
            service = "device_auditor",
            reportSafeState = true,
            selections = mapOf("selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("unpatched_cve_count", SigmaModifier.GTE, listOf(1))
            ))), level = "critical"
        ).copy(
            display = SigmaDisplay(
                category = "device_posture",
                triggeredTitle = "{count} Unpatched CVEs",
                evidenceType = "cve_list"
            ),
            remediation = listOf("Update to {target_patch_level}.")
        )
        var providerCalled = false
        val providers = mapOf<String, EvidenceProvider>("cve_list" to EvidenceProvider { _, _ ->
            providerCalled = true
            listOf(EvidenceResult(
                evidence = Evidence.CveList(emptyList(), "2025-03-01", 0),
                titleVars = mapOf("count" to "5"),
                remediationVars = mapOf("target_patch_level" to "2025-03-01")
            ))
        })
        val record = mapOf<String, Any?>("unpatched_cve_count" to 5)
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(rule), listOf(record), "device_auditor",
            evidenceProviders = providers
        )
        assertTrue(providerCalled)
        assertEquals(1, findings.size)
        assertEquals("5 Unpatched CVEs", findings[0].title)
        assertEquals("Update to 2025-03-01.", findings[0].remediation[0])
        assertTrue(findings[0].evidence is Evidence.CveList)
    }

    @Test
    fun `backward compat - rule without display block uses title field`() {
        val rule = makeRule(selections = mapOf("selection" to SigmaSelection(listOf(
            SigmaFieldMatcher("is_sideloaded", SigmaModifier.EQUALS, listOf(true))
        ))))
        val record = mapOf<String, Any?>("is_sideloaded" to true)
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner")
        assertEquals(1, findings.size)
        assertEquals("Test", findings[0].title)
    }

    @Test
    fun `regex pattern exceeding max length is rejected`() {
        val longPattern = "a".repeat(501)
        val rule = makeRule(
            selections = mapOf("selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("app_name", SigmaModifier.RE, listOf(longPattern))
            )))
        )
        val record = mapOf<String, Any?>("app_name" to "a".repeat(501))
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner")
        assertEquals(0, findings.size)
    }

    @Test
    fun `operator precedence - AND binds tighter than OR`() {
        // a or b and c → a or (b and c), NOT (a or b) and c
        assertTrue(SigmaRuleEvaluator.evaluateConditionExpression(
            "a or b and c", mapOf("a" to true, "b" to false, "c" to false)
        ))
        // Verify: a=false, b=true, c=true → false or (true and true) = true
        assertTrue(SigmaRuleEvaluator.evaluateConditionExpression(
            "a or b and c", mapOf("a" to false, "b" to true, "c" to true)
        ))
        // Verify: a=false, b=true, c=false → false or (true and false) = false
        assertFalse(SigmaRuleEvaluator.evaluateConditionExpression(
            "a or b and c", mapOf("a" to false, "b" to true, "c" to false)
        ))
    }

    @Test
    fun `operator precedence with leading not`() {
        // not a or b and c → (not a) or (b and c)
        assertTrue(SigmaRuleEvaluator.evaluateConditionExpression(
            "not a or b and c", mapOf("a" to true, "b" to true, "c" to true)
        ))
        assertTrue(SigmaRuleEvaluator.evaluateConditionExpression(
            "not a or b and c", mapOf("a" to false, "b" to false, "c" to false)
        ))
        assertFalse(SigmaRuleEvaluator.evaluateConditionExpression(
            "not a or b and c", mapOf("a" to true, "b" to true, "c" to false)
        ))
    }

    @Test
    fun `empty or malformed condition defaults to false`() {
        assertFalse(SigmaRuleEvaluator.evaluateConditionExpression(
            "nonexistent", mapOf("a" to true)
        ))
    }

    @Test
    fun `invalid regex pattern does not crash`() {
        val rule = makeRule(
            selections = mapOf("selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("app_name", SigmaModifier.RE, listOf("[invalid"))
            )))
        )
        val record = mapOf<String, Any?>("app_name" to "test")
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner")
        assertEquals(0, findings.size)
    }

    @Test
    fun `valid regex pattern matches correctly`() {
        val rule = makeRule(
            selections = mapOf("selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("app_name", SigmaModifier.RE, listOf("^System.*Service$"))
            )))
        )
        val match = mapOf<String, Any?>("app_name" to "System Update Service")
        val noMatch = mapOf<String, Any?>("app_name" to "User App")
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(match), "app_scanner").size)
        assertEquals(0, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(noMatch), "app_scanner").size)
    }

    // ── List-aware matching ─────────────────────────────────────────────

    @Test
    fun `contains modifier matches element in list field`() {
        val rule = makeRule(selections = mapOf(
            "selection" to SigmaSelection(listOf(
                SigmaFieldMatcher(
                    "service_permissions", SigmaModifier.CONTAINS,
                    listOf("BIND_NOTIFICATION_LISTENER")
                )
            ))
        ))
        val match = mapOf<String, Any?>(
            "service_permissions" to listOf(
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
            )
        )
        val noMatch = mapOf<String, Any?>(
            "service_permissions" to listOf(
                "android.permission.BIND_ACCESSIBILITY_SERVICE"
            )
        )
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(match), "app_scanner")
        assertTrue("Should match list element containing substring", findings.any { it.triggered })

        val noFindings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(noMatch), "app_scanner")
        assertTrue("Should not match when no element contains substring", noFindings.none { it.triggered })
    }

    @Test
    fun `equals modifier matches exact element in list field`() {
        val rule = makeRule(selections = mapOf(
            "selection" to SigmaSelection(listOf(
                SigmaFieldMatcher(
                    "permissions", SigmaModifier.EQUALS,
                    listOf("android.permission.CAMERA")
                )
            ))
        ))
        val match = mapOf<String, Any?>(
            "permissions" to listOf("android.permission.CAMERA", "android.permission.INTERNET")
        )
        val noMatch = mapOf<String, Any?>(
            "permissions" to listOf("android.permission.INTERNET")
        )
        assertTrue(
            SigmaRuleEvaluator.evaluate(listOf(rule), listOf(match), "app_scanner").any { it.triggered }
        )
        assertTrue(
            SigmaRuleEvaluator.evaluate(listOf(rule), listOf(noMatch), "app_scanner").none { it.triggered }
        )
    }

    @Test
    fun `contains on list does not match across element boundaries`() {
        // "audio" should NOT match because no single element equals "audio"
        // It should only match if an element CONTAINS "audio" as a substring
        val rule = makeRule(selections = mapOf(
            "selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("perms", SigmaModifier.CONTAINS, listOf("audio"))
            ))
        ))
        val record = mapOf<String, Any?>(
            "perms" to listOf("RECORD_AUDIO", "CAMERA")
        )
        // "audio" IS a substring of "RECORD_AUDIO" so this should match
        assertTrue(
            SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner").any { it.triggered }
        )

        val noRecord = mapOf<String, Any?>(
            "perms" to listOf("CAMERA", "INTERNET")
        )
        assertTrue(
            SigmaRuleEvaluator.evaluate(listOf(rule), listOf(noRecord), "app_scanner").none { it.triggered }
        )
    }

    @Test
    fun `empty list field does not match any modifier`() {
        val rule = makeRule(selections = mapOf(
            "selection" to SigmaSelection(listOf(
                SigmaFieldMatcher("services", SigmaModifier.CONTAINS, listOf("anything"))
            ))
        ))
        val record = mapOf<String, Any?>("services" to emptyList<String>())
        assertTrue(
            SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner").none { it.triggered }
        )
    }
}

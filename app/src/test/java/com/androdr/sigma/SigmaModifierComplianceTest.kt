package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Executable documentation of AndroDR's SIGMA dialect.
 *
 * The SUPPORTED group asserts which modifiers parse AND evaluate correctly.
 * Adding a new modifier MUST come with a new test here.
 *
 * The DELIBERATELY ABSENT group asserts which upstream SIGMA HQ modifiers
 * are rejected. Promoting one to "supported" requires moving its test from
 * the absent group to the supported group in the same PR.
 *
 * See GitHub issue #120 for background.
 */
class SigmaModifierComplianceTest {

    private fun ruleWithModifier(modifier: String, value: String = "\"test\""): String = """
        title: Compliance probe
        id: test-compliance
        category: incident
        logsource:
            product: androdr
            service: app_scanner
        detection:
            selection:
                package_name|$modifier: $value
            condition: selection
        level: medium
    """.trimIndent()

    // ------------------------- SUPPORTED MODIFIERS -------------------------

    @Test
    fun `contains modifier parses and matches substring`() {
        val yaml = ruleWithModifier("contains", "\"spyware\"")
        val rule = SigmaRuleParser.parse(yaml)!!
        val record = mapOf("package_name" to "com.evil.spyware.client")
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner")
        assertEquals(1, findings.size)
    }

    @Test
    fun `startswith modifier parses and matches prefix`() {
        val yaml = ruleWithModifier("startswith", "\"com.evil\"")
        val rule = SigmaRuleParser.parse(yaml)!!
        val record = mapOf("package_name" to "com.evil.client")
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner").size)
    }

    @Test
    fun `endswith modifier parses and matches suffix`() {
        val yaml = ruleWithModifier("endswith", "\".spyware\"")
        val rule = SigmaRuleParser.parse(yaml)!!
        val record = mapOf("package_name" to "com.evil.spyware")
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner").size)
    }

    @Test
    fun `re modifier parses and matches regex`() {
        val yaml = ruleWithModifier("re", "\"^com\\\\.evil\\\\..*\"")
        val rule = SigmaRuleParser.parse(yaml)!!
        val record = mapOf("package_name" to "com.evil.anything")
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner").size)
    }

    @Test
    fun `numeric comparison modifiers parse and evaluate`() {
        val yaml = """
            title: Numeric probe
            id: test-numeric-compliance
            category: device_posture
            logsource:
                product: androdr
                service: device_auditor
            detection:
                too_old:
                    patch_age_days|gte: 90
                too_new:
                    patch_age_days|lt: 1
                between:
                    patch_age_days|gt: 30
                bounded:
                    patch_age_days|lte: 365
                condition: too_old
            level: medium
        """.trimIndent()
        val rule = SigmaRuleParser.parse(yaml)!!
        val record = mapOf("patch_age_days" to 120)
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "device_auditor")
        assertEquals(1, findings.size)
    }

    @Test
    fun `all modifier standalone requires every value present in list field`() {
        val yaml = """
            title: All standalone
            id: test-all-standalone
            category: incident
            logsource:
                product: androdr
                service: app_scanner
            detection:
                selection:
                    permissions|all:
                        - android.permission.READ_SMS
                        - android.permission.SEND_SMS
                condition: selection
            level: medium
        """.trimIndent()
        val rule = SigmaRuleParser.parse(yaml)!!
        val matching = mapOf("permissions" to listOf(
            "android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.INTERNET"
        ))
        val partial = mapOf("permissions" to listOf("android.permission.READ_SMS"))
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(matching), "app_scanner").size)
        assertTrue(SigmaRuleEvaluator.evaluate(listOf(rule), listOf(partial), "app_scanner").isEmpty())
    }

    @Test
    fun `contains plus all combining modifier requires all values to contain-match`() {
        val yaml = """
            title: Contains + all
            id: test-contains-all
            category: incident
            logsource:
                product: androdr
                service: app_scanner
            detection:
                selection:
                    permissions|contains|all:
                        - READ_SMS
                        - SEND_SMS
                condition: selection
            level: medium
        """.trimIndent()
        val rule = SigmaRuleParser.parse(yaml)!!
        val matching = mapOf("permissions" to listOf(
            "android.permission.READ_SMS", "android.permission.SEND_SMS"
        ))
        val partial = mapOf("permissions" to listOf("android.permission.READ_SMS"))
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(matching), "app_scanner").size)
        assertTrue(SigmaRuleEvaluator.evaluate(listOf(rule), listOf(partial), "app_scanner").isEmpty())
    }

    @Test
    fun `ioc_lookup modifier parses and evaluates with registered database`() {
        val yaml = """
            title: IOC lookup probe
            id: test-ioc-compliance
            category: incident
            logsource:
                product: androdr
                service: app_scanner
            detection:
                selection:
                    package_name|ioc_lookup: malware_packages
                condition: selection
            level: high
        """.trimIndent()
        val rule = SigmaRuleParser.parse(yaml)!!
        val record = mapOf("package_name" to "com.evil.client")
        val lookups = mapOf<String, (Any) -> Boolean>(
            "malware_packages" to { v -> v.toString() == "com.evil.client" }
        )
        assertEquals(1, SigmaRuleEvaluator.evaluate(
            listOf(rule), listOf(record), "app_scanner", iocLookups = lookups
        ).size)
    }

    // ----------------------- DELIBERATELY ABSENT --------------------------

    private fun assertRejected(modifier: String) {
        val yaml = ruleWithModifier(modifier, "\"x\"")
        try {
            SigmaRuleParser.parse(yaml)
            fail("Modifier '$modifier' should be rejected but parsed successfully")
        } catch (e: SigmaRuleParseException) {
            assertTrue(
                "Exception message should mention the modifier name. Got: ${e.message}",
                e.message!!.contains(modifier)
            )
        }
    }

    @Test fun `base64 modifier is rejected`() = assertRejected("base64")
    @Test fun `base64offset modifier is rejected`() = assertRejected("base64offset")
    @Test fun `utf16 modifier is rejected`() = assertRejected("utf16")
    @Test fun `utf16le modifier is rejected`() = assertRejected("utf16le")
    @Test fun `utf16be modifier is rejected`() = assertRejected("utf16be")
    @Test fun `wide modifier is rejected`() = assertRejected("wide")
    @Test fun `cidr modifier is rejected`() = assertRejected("cidr")
    @Test fun `windash modifier is rejected`() = assertRejected("windash")
    @Test fun `expand modifier is rejected`() = assertRejected("expand")
    @Test fun `fieldref modifier is rejected`() = assertRejected("fieldref")

    @Test fun `contains_all hallucinated modifier is rejected`() = assertRejected("contains_all")

    @Test
    fun `unknown modifier emits parse error, not silent EQUALS fallback`() {
        // Guards against regression of the silent `EQUALS` fallback.
        val yaml = ruleWithModifier("nosuchmodifier", "\"x\"")
        try {
            SigmaRuleParser.parse(yaml)
            fail("Unknown modifier must raise SigmaRuleParseException, not silently map to EQUALS")
        } catch (e: SigmaRuleParseException) {
            assertTrue(e.message!!.contains("Unknown modifier"))
        }
    }
}

package com.androdr.ioc

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Matcher-semantics tests for the brand impersonation registry (#299).
 * Exercises the pure matching core via [BrandImpersonationResolver.BrandMatcher]
 * so no Android Context is needed.
 */
class BrandImpersonationResolverTest {

    private val matcher = BrandImpersonationResolver.BrandMatcher(
        nameVariants = listOf("PayPal", "Chase Bank", "PKO Bank Polski"),
        domains = setOf("paypal.com", "chase.com", "pkobp.pl"),
    )

    // ── name matching: word-boundary, case-insensitive containment ──

    @Test
    fun `exact label matches`() =
        assertTrue(matcher.matchesName("PayPal"))

    @Test
    fun `variant inside longer label matches`() =
        assertTrue(matcher.matchesName("Chase Bank Login"))

    @Test
    fun `case-insensitive`() =
        assertTrue(matcher.matchesName("payPAL secure"))

    @Test
    fun `substring inside a word does NOT match`() {
        // "chase" occurs inside "Purchase" with no word boundary — and the
        // seeded variant is the two-token "Chase Bank" anyway.
        assertFalse(matcher.matchesName("Purchase Tracker"))
    }

    @Test
    fun `multi-token variant does not match its tokens separately`() =
        assertFalse(matcher.matchesName("Chase Online"))

    @Test
    fun `unrelated label does not match`() =
        assertFalse(matcher.matchesName("Sudoku Deluxe"))

    @Test
    fun `blank label does not match`() =
        assertFalse(matcher.matchesName(""))

    // ── domain matching: URL host, label-boundary suffix walk ──

    @Test
    fun `exact scope host matches`() =
        assertTrue(matcher.matchesDomain("https://paypal.com/"))

    @Test
    fun `subdomain scope matches`() =
        assertTrue(matcher.matchesDomain("https://www.paypal.com/signin"))

    @Test
    fun `suffix without label boundary does NOT match`() =
        assertFalse(matcher.matchesDomain("https://notchase.com/"))

    @Test
    fun `unlisted domain does not match`() =
        assertFalse(matcher.matchesDomain("https://evil.example/"))

    @Test
    fun `non-URL scope does not match`() =
        assertFalse(matcher.matchesDomain("not a url"))

    @Test
    fun `blank scope does not match`() =
        assertFalse(matcher.matchesDomain(""))

    @Test
    fun `trailing-dot host is normalized`() =
        assertTrue(matcher.matchesDomain("https://paypal.com./"))

    // ── YAML parsing (structural brands: shape) ──

    @Test
    fun `parses display_names from structural yaml`() {
        val yaml = """
            version: "2026-08-20"
            brands:
              paypal:
                display_names: ["PayPal"]
              chase:
                display_names: ["Chase Bank", "Chase Mobile"]
        """.trimIndent()
        val names = BrandImpersonationResolver.parseBrandYaml(yaml, "display_names")
        assertTrue(names.containsAll(listOf("PayPal", "Chase Bank", "Chase Mobile")))
    }

    @Test
    fun `parses domains and malformed yaml yields empty`() {
        val yaml = """
            brands:
              paypal:
                domains: [paypal.com]
        """.trimIndent()
        assertTrue(BrandImpersonationResolver.parseBrandYaml(yaml, "domains").contains("paypal.com"))
        assertTrue(BrandImpersonationResolver.parseBrandYaml("{ not: [valid", "domains").isEmpty())
    }
}

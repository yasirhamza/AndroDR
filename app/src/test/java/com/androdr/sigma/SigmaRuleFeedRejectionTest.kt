package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * One unreadable remote rule must cost that rule, not every rule after it (#288).
 *
 * The parser deliberately throws on a rule it will not guess about -- a missing
 * `display.category` since #367, or any field a newer rules schema added that
 * this build does not know. That exception used to escape the per-file loop into
 * the fetch's outer catch, which returned only the rules parsed so far: one bad
 * file silently disabled every rule listed after it in rules.txt, on every
 * device, with nothing but a log line. Rules reach the fleet from the rules repo
 * every 12 hours without an app release, so the blast radius was the whole fleet.
 *
 * The loop is a pure function of (files, manifest) so it is testable without a
 * network, and a rejected file is reported rather than just logged.
 */
class SigmaRuleFeedRejectionTest {

    private fun rule(id: String, withDisplayCategory: Boolean = true) = buildString {
        appendLine("title: Probe $id")
        appendLine("id: $id")
        appendLine("status: experimental")
        appendLine("category: incident")
        appendLine("logsource:")
        appendLine("    product: androdr")
        appendLine("    service: app_scanner")
        appendLine("detection:")
        appendLine("    selection:")
        appendLine("        is_sideloaded: true")
        appendLine("    condition: selection")
        appendLine("level: medium")
        appendLine("display:")
        if (withDisplayCategory) appendLine("    category: app_risk")
        appendLine("    icon: warning")
    }

    private fun sha(text: String) = MessageDigest.getInstance("SHA-256")
        .digest(text.toByteArray()).joinToString("") { "%02x".format(it) }

    private val good1 = "a.yml" to rule("androdr-901")
    private val broken = "b.yml" to rule("androdr-902", withDisplayCategory = false)
    private val good2 = "c.yml" to rule("androdr-903")
    private val files = listOf(good1, broken, good2)
    private val hashes = files.associate { (name, yaml) -> name to sha(yaml) }

    @Test
    fun `a rule this build cannot read does not take the rules after it down`() {
        val result = SigmaRuleFeed.loadRuleFiles(files.asSequence(), hashes, requireManifest = true)

        assertEquals(
            "the rule listed after the broken one must still load",
            listOf("androdr-901", "androdr-903"),
            result.rules.map { it.id },
        )
    }

    @Test
    fun `the rejected file is reported, with the rule id it declared`() {
        val result = SigmaRuleFeed.loadRuleFiles(files.asSequence(), hashes, requireManifest = true)

        val rejected = result.rejected.single()
        assertEquals("b.yml", rejected.file)
        assertEquals("the id is recovered so History never calls this rule resolved", "androdr-902", rejected.ruleId)
        assertTrue("the reason says why: ${rejected.reason}", rejected.reason.contains("display.category"))
    }

    @Test
    fun `a broken first file does not stop the list`() {
        val result = SigmaRuleFeed.loadRuleFiles(sequenceOf(broken, good1, good2), hashes, requireManifest = true)

        assertEquals(2, result.rules.size)
        assertEquals(1, result.rejected.size)
    }

    @Test
    fun `a file failing the integrity check is dropped but is not a capability gap`() {
        // A hash mismatch is a publishing error on the rules side, gated in CI by
        // RuleManifestIntegrityTest. It is not "this build cannot read the rule",
        // so it must not be surfaced to the reader as "update the app".
        val tampered = hashes + ("a.yml" to "deadbeef")

        val result = SigmaRuleFeed.loadRuleFiles(sequenceOf(good1, good2), tampered, requireManifest = true)

        assertEquals(listOf("androdr-903"), result.rules.map { it.id })
        assertEquals(emptyList<Any>(), result.rejected)
    }

    @Test
    fun `a file that is not a rule at all is dropped quietly, as before`() {
        // The parser returns null (not throw) for plain junk; that path never
        // aborted the loop and has nothing a reader could act on.
        val junk = "d.yml" to "just: a scalar map\n"
        val allHashes = hashes + ("d.yml" to sha(junk.second))

        val result = SigmaRuleFeed.loadRuleFiles(sequenceOf(junk, good1), allHashes, requireManifest = true)

        assertEquals(listOf("androdr-901"), result.rules.map { it.id })
    }

    @Test
    fun `the declared id is read without trusting the rest of the file`() {
        assertEquals("androdr-902", SigmaRuleFeed.declaredId(broken.second))
        assertEquals(
            "quoted ids are read too",
            "androdr-905",
            SigmaRuleFeed.declaredId("title: x\nid: 'androdr-905'\n"),
        )
        assertEquals("no id line means no claim", null, SigmaRuleFeed.declaredId("title: x\n"))
        assertEquals(
            "an indented id belongs to a nested map, not the rule",
            null,
            SigmaRuleFeed.declaredId("title: x\ndisplay:\n    id: nested\n"),
        )
    }
}

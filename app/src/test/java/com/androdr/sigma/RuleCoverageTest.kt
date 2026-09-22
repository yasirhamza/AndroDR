package com.androdr.sigma

import com.androdr.data.model.FileArtifactTelemetry
import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Which rules produced no verdict, and why.
 *
 * Two rules in this codebase were structurally unable to fire and said nothing
 * about it: the CRITICAL artifact rule, whose paths no unprivileged app may read
 * (#366), and three of the four chain rules, whose legs need event kinds only an
 * imported bug report carries (#370). In both cases the report rendered exactly
 * like a device that had been checked and found clean.
 *
 * Coverage is computed here, as a pure function of the rules and the evidence, so
 * the report can state the limit instead of implying a pass.
 */
class RuleCoverageTest {

    private fun rule(id: String, service: String) = SigmaRule(
        id = id, title = "Rule $id", status = "production", description = "",
        product = "androdr", service = service, level = "critical",
        category = RuleCategory.INCIDENT,
        tags = emptyList(),
        detection = SigmaDetection(
            selections = mapOf(
                "selection" to SigmaSelection(
                    fieldMatchers = listOf(
                        SigmaFieldMatcher(
                            fieldName = "file_exists",
                            modifier = SigmaModifier.EQUALS,
                            values = listOf(true),
                        )
                    )
                )
            ),
            condition = "selection",
        ),
        falsepositives = emptyList(),
        remediation = emptyList(),
        display = SigmaDisplay(category = FindingCategory.DEVICE_POSTURE),
    )

    private fun fileRule(id: String) = rule(id = id, service = "file_scanner")

    private fun artifact(path: String, accessible: Boolean) = FileArtifactTelemetry(
        filePath = path,
        fileExists = false,
        fileSize = null,
        fileModified = null,
        source = TelemetrySource.LIVE_SCAN,
        accessible = accessible,
    )

    // -- artifact paths -------------------------------------------------------

    @Test
    fun `a file rule whose paths were all unreadable is reported as not evaluated`() {
        val telemetry = listOf(artifact("/data/local/tmp/.raptor", false), artifact("/sdcard/.x", false))

        val skips = RuleCoverage.unreadableArtifactSkips(listOf(fileRule("androdr-020")), telemetry)

        assertEquals(1, skips.size)
        assertEquals("androdr-020", skips.single().ruleId)
        assertEquals(NotEvaluatedReason.UNREADABLE_PATHS.sentinel, skips.single().exception)
        assertTrue("the message must count the paths", skips.single().message!!.contains("2 of 2"))
    }

    @Test
    fun `partial readability is still declared, because the unread paths were never checked`() {
        val telemetry = listOf(artifact("/readable/a", true), artifact("/data/local/tmp/.raptor", false))

        val skips = RuleCoverage.unreadableArtifactSkips(listOf(fileRule("androdr-020")), telemetry)

        assertEquals(1, skips.size)
        assertTrue(skips.single().message!!.contains("1 of 2"))
    }

    @Test
    fun `nothing is declared when every path was read`() {
        val telemetry = listOf(artifact("/readable/a", true), artifact("/readable/b", true))

        assertEquals(emptyList<Any>(), RuleCoverage.unreadableArtifactSkips(listOf(fileRule("androdr-020")), telemetry))
    }

    @Test
    fun `rules of other services are none of this check's business`() {
        val telemetry = listOf(artifact("/data/local/tmp/.raptor", false))
        val rules = listOf(fileRule("androdr-020"), rule(id = "androdr-003", service = "dns_monitor"))

        val skips = RuleCoverage.unreadableArtifactSkips(rules, telemetry)

        assertEquals(listOf("androdr-020"), skips.map { it.ruleId })
    }

    @Test
    fun `no artifact telemetry at all means no claim either way`() {
        val skips = RuleCoverage.unreadableArtifactSkips(listOf(fileRule("androdr-020")), emptyList())

        assertEquals(emptyList<Any>(), skips)
    }

    // -- correlation legs -----------------------------------------------------

    private fun chain(id: String, vararg refs: String) = CorrelationRule(
        id = id,
        title = "chain $id",
        type = CorrelationType.TEMPORAL_ORDERED,
        referencedRuleIds = refs.toList(),
        timespanMs = 60_000L,
        groupBy = listOf("package_name"),
        minEvents = 1,
        severity = "high",
        displayLabel = "Chain",
    )

    private val atomCategories = mapOf(
        "atom-install" to "package_install",
        "atom-permission" to "permission_use",
        "atom-admin" to "device_admin_grant",
    )

    @Test
    fun `a chain whose legs all have events is evaluable`() {
        val skips = RuleCoverage.noEventSkips(
            listOf(chain("corr-001", "atom-install", "atom-admin")),
            atomCategories,
            presentCategories = setOf("package_install", "device_admin_grant"),
        )

        assertEquals(emptyList<Any>(), skips)
    }

    @Test
    fun `a chain missing one leg's events is reported as not evaluated`() {
        val skips = RuleCoverage.noEventSkips(
            listOf(chain("corr-002", "atom-install", "atom-permission")),
            atomCategories,
            presentCategories = setOf("package_install"),
        )

        assertEquals(1, skips.size)
        assertEquals("corr-002", skips.single().ruleId)
        assertEquals(NotEvaluatedReason.NO_EVENTS_TO_CHECK.sentinel, skips.single().exception)
    }

    @Test
    fun `the message says what was missing in words a reader can act on`() {
        val skips = RuleCoverage.noEventSkips(
            listOf(chain("corr-004", "atom-permission")),
            atomCategories,
            presentCategories = emptySet(),
        )

        val message = skips.single().message.orEmpty()
        assertTrue("names the pattern: $message", message.contains("chain corr-004"))
        assertTrue("explains the missing evidence in plain words: $message", message.contains("permission"))
        assertTrue("says where it can come from: $message", message.contains("bug report"))
    }

    @Test
    fun `a leg referencing an atom rule that is not loaded is missing evidence too`() {
        // An atom rule whose category no producer writes binds to nothing, so the
        // chain can never fire. Silence there is how a dead rule stays dead.
        val skips = RuleCoverage.noEventSkips(
            listOf(chain("corr-003", "atom-permission", "atom-unknown")),
            atomCategories,
            presentCategories = setOf("permission_use"),
        )

        assertEquals(1, skips.size)
        assertEquals("corr-003", skips.single().ruleId)
    }

    @Test
    fun `every chain rule is judged, not just the first`() {
        val skips = RuleCoverage.noEventSkips(
            listOf(
                chain("corr-002", "atom-permission"),
                chain("corr-004", "atom-permission"),
                chain("corr-001", "atom-install"),
            ),
            atomCategories,
            presentCategories = setOf("package_install"),
        )

        assertEquals(listOf("corr-002", "corr-004"), skips.map { it.ruleId })
    }
}

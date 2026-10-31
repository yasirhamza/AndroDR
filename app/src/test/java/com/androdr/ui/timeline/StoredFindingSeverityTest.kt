package com.androdr.ui.timeline

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import com.androdr.ui.registerHostActivity
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.ui.theme.AndroDRTheme
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * #418: on Play 0.9.0.848 a stored finding row (a critical androdr-003 "Malicious Domain" from an
 * intrusion-log import) drew as a neutral info card with no severity, so it read as informational.
 * A `forensic_timeline` row that carries a `level` is a finding and shows its severity and rule;
 * a row without one stays the neutral telemetry card.
 */
@RunWith(RobolectricTestRunner::class)
class StoredFindingSeverityTest {
    private val composeRule = createComposeRule()

    @get:Rule val chain: RuleChain = RuleChain.outerRule(registerHostActivity()).around(composeRule)

    private fun row(level: String?, ruleId: String) = ForensicTimelineEvent(
        startTimestamp = 1_000L,
        source = "intrusion_log_analysis",
        category = "app_risk",
        description = "Malicious Domain: tracookiepixel.xyz",
        iocType = "domain",
        ruleId = ruleId,
        level = level,
        telemetrySource = TelemetrySource.INTRUSION_LOG_IMPORT,
    )

    @Test
    fun `a stored critical finding row shows its severity and rule`() {
        composeRule.setContent {
            AndroDRTheme { TimelineEventCard(event = row("critical", "androdr-003"), onClick = {}) }
        }
        composeRule.onNodeWithText("CRITICAL").assertExists()
        composeRule.onNodeWithText("androdr-003").assertExists()
    }

    @Test
    fun `a row without a level stays a neutral telemetry card`() {
        composeRule.setContent { AndroDRTheme { TimelineEventCard(event = row(null, ""), onClick = {}) } }
        listOf("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO").forEach {
            composeRule.onAllNodesWithText(it).assertCountEquals(0)
        }
    }
}

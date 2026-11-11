package com.androdr.ui.timeline

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.performSemanticsAction
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.ui.registerHostActivity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** A privacy entry's details sheet offers "Open in privacy results"; other entries do not (spec 2026-11-10 §5.1). */
@RunWith(RobolectricTestRunner::class)
class TimelinePrivacySheetTest {
    private val composeRule = createComposeRule()

    @get:Rule val chain: RuleChain = RuleChain.outerRule(registerHostActivity()).around(composeRule)

    private val privacy = ForensicTimelineEvent(
        startTimestamp = 5L, source = "privacy_scan", category = "privacy_app",
        description = "Some Game: 3 trackers found in code", packageName = "com.game", createdAt = 5L,
        telemetrySource = TelemetrySource.PRIVACY_SCAN,
    )

    private fun exists(text: String) = composeRule.onAllNodes(
        androidx.compose.ui.test.hasText(text, substring = true),
    ).fetchSemanticsNodes().isNotEmpty()

    @Test fun `the details sheet opens the app's privacy results`() {
        var opened: String? = null
        composeRule.setContent {
            TimelineEventDetailSheet(event = privacy, onDismiss = {},
                onOpenPrivacy = openPrivacyAction(privacy) { opened = it })
        }
        composeRule.onNodeWithText("Open in privacy results").performSemanticsAction(SemanticsActions.OnClick)
        assertEquals("com.game", opened)
    }

    @Test fun `another entry's sheet has no such action`() {
        val finding = privacy.copy(telemetrySource = TelemetrySource.LIVE_SCAN, ruleId = "androdr-001", level = "high")
        composeRule.setContent {
            TimelineEventDetailSheet(event = finding, onDismiss = {}, onOpenPrivacy = openPrivacyAction(finding) { })
        }
        assertTrue(!exists("Open in privacy results"))
    }
}

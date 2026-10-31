package com.androdr.ui.settings

import com.androdr.ui.registerHostActivity
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Battery B3: the retention slider used `steps = 94`, so Material drew 96 tick dots and an exact value
 * was hard to hit on touch. It is continuous (rounded to whole scans) with "one fewer" / "one more"
 * buttons, every value clamped to [TelemetrySettingsViewModel.RETENTION_RANGE] (5..100).
 */
@RunWith(RobolectricTestRunner::class)
class RetentionControlTest {
    private val composeRule = createComposeRule()

    @get:Rule val chain: RuleChain = RuleChain.outerRule(registerHostActivity()).around(composeRule)

    @Test
    fun `a slider position rounds to whole scans within 5 to 100`() {
        assertEquals(20, retentionFromSlider(20.4f))
        assertEquals(21, retentionFromSlider(20.5f))
        assertEquals(5, retentionFromSlider(4.2f))
        assertEquals(5, retentionFromSlider(-3f))
        assertEquals(100, retentionFromSlider(100.6f))
    }

    @Test
    fun `a fewer or more step is clamped to 5 to 100`() {
        assertEquals(21, retentionStep(20, 1))
        assertEquals(19, retentionStep(20, -1))
        assertEquals(5, retentionStep(5, -1))
        assertEquals(100, retentionStep(100, 1))
        assertEquals(5, retentionStep(2, 1))
    }

    @Test
    fun `the slider is continuous`() {
        composeRule.setContent { RetentionControl(keep = 20, onCommit = {}) }
        val slider = composeRule.onNode(SemanticsMatcher.keyIsDefined(SemanticsProperties.ProgressBarRangeInfo))
        val info = slider.fetchSemanticsNode().config[SemanticsProperties.ProgressBarRangeInfo]
        assertEquals("no tick steps", 0, info.steps)
        assertEquals(5f..100f, info.range)
    }

    @Test
    fun `the buttons commit one scan fewer or more`() {
        val committed = mutableListOf<Int>()
        composeRule.setContent { RetentionControl(keep = 20, onCommit = { committed += it }) }
        composeRule.onNodeWithContentDescription("Keep one scan more").performClick()
        composeRule.onNodeWithText("Keep snapshot telemetry for the last 21 scans").assertExists()
        composeRule.onNodeWithContentDescription("Keep one scan fewer").performClick()
        composeRule.onNodeWithContentDescription("Keep one scan fewer").performClick()
        assertEquals(listOf(21, 20, 19), committed)
    }

    @Test
    fun `at a limit the button toward it is disabled`() {
        composeRule.setContent { RetentionControl(keep = 5, onCommit = {}) }
        composeRule.onNodeWithContentDescription("Keep one scan fewer").assertIsNotEnabled()
    }
}

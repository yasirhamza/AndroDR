package com.androdr.ui.timeline

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import com.androdr.ui.registerHostActivity
import com.androdr.data.model.TelemetrySource
import com.androdr.data.store.DecodedRecord
import com.androdr.sigma.TimePrecision
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Battery B1: a Timeline fact whose service has no summary rule (e.g. `device_auditor`) showed
 * "Record could not be read" although its body decoded. The unreadable text is for an undecodable
 * body ONLY (`fields == null`), the same rule as the telemetry browser.
 */
@RunWith(RobolectricTestRunner::class)
class FactDescriptionTest {
    private val composeRule = createComposeRule()

    @get:Rule val chain: RuleChain = RuleChain.outerRule(registerHostActivity()).around(composeRule)

    private fun record(fields: Map<String, Any?>?, summary: String? = null, subjectKey: String? = null) =
        DecodedRecord(
            factId = 1L, scanId = 1L, service = "device_auditor", ordinal = 0, source = TelemetrySource.LIVE_SCAN,
            capturedAt = 1_000L, eventTime = null, precision = TimePrecision.EXACT, category = null,
            fields = fields, summary = summary, subjectKey = subjectKey,
        )

    @Test
    fun `a readable record without a summary rule is described, not called unreadable`() {
        assertEquals("check_id=adb_enabled, value=true",
            factDescription(record(mapOf("check_id" to "adb_enabled", "value" to true))))
        assertEquals("adb_enabled",
            factDescription(record(mapOf("check_id" to "adb_enabled"), subjectKey = "adb_enabled")))
    }

    @Test
    fun `the summary is used when there is one`() {
        assertEquals("ADB is on", factDescription(record(mapOf("a" to 1), summary = "ADB is on")))
    }

    @Test
    fun `only an undecodable body has no description`() {
        assertNull(factDescription(record(fields = null, summary = null)))
    }

    @Test
    fun `the fact card shows a readable record without the unreadable text`() {
        composeRule.setContent {
            FactCard(record = record(mapOf("check_id" to "adb_enabled")), timestamp = 1_000L)
        }
        composeRule.onAllNodesWithText("Record could not be read").assertCountEquals(0)
        composeRule.onNodeWithText("check_id=adb_enabled").assertExists()
    }

    @Test
    fun `the fact card calls an undecodable record unreadable`() {
        composeRule.setContent { FactCard(record = record(fields = null), timestamp = 1_000L) }
        composeRule.onNodeWithText("Record could not be read").assertExists()
    }
}

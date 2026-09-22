package com.androdr.sigma

import android.content.Context
import com.androdr.data.model.FileArtifactTelemetry
import com.androdr.data.model.TelemetrySource
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

/**
 * A path the app was refused is not evidence of absence.
 *
 * `FileArtifactScanner` now reports every probed path, including the ones it could
 * not read (#366). Those rows carry `fileExists = false` because nothing was
 * observed -- not because the file is known to be gone. Feeding them to rules would
 * turn "we were not allowed to look" into a clean pass on the report, which is the
 * failure #366 is about, one layer down. The filter therefore lives in the engine,
 * where no caller can forget it.
 */
class FileRuleUnreadablePathTest {

    private val mockContext = mockk<Context>(relaxed = true)
    private lateinit var engine: SigmaRuleEngine

    /** Fires on any record the rule is allowed to see: proves what reached evaluation. */
    private val everyRecordRule = SigmaRule(
        id = "androdr-020", title = "Known spyware artifact", status = "production",
        description = "", product = "androdr", service = "file_scanner", level = "critical",
        category = RuleCategory.INCIDENT, tags = emptyList(),
        detection = SigmaDetection(
            selections = mapOf(
                "selection" to SigmaSelection(
                    fieldMatchers = listOf(
                        SigmaFieldMatcher(
                            fieldName = "file_exists",
                            modifier = SigmaModifier.EQUALS,
                            values = listOf(false),
                        )
                    )
                )
            ),
            condition = "selection",
        ),
        falsepositives = emptyList(), remediation = emptyList(),
        display = SigmaDisplay(category = FindingCategory.DEVICE_POSTURE),
    )

    private fun path(path: String, accessible: Boolean) = FileArtifactTelemetry(
        filePath = path, fileExists = false, fileSize = null, fileModified = null,
        source = TelemetrySource.LIVE_SCAN, accessible = accessible,
    )

    @Before
    fun setUp() {
        engine = SigmaRuleEngine(mockContext)
        for (field in listOf("bundledRules", "rules")) {
            SigmaRuleEngine::class.java.getDeclaredField(field).apply { isAccessible = true }
                .set(engine, listOf(everyRecordRule))
        }
    }

    @Test
    fun `an unreadable path never reaches a rule`() {
        val findings = engine.evaluateFiles(listOf(path("/data/local/tmp/.raptor", accessible = false)))

        assertEquals("a refused path must produce no verdict at all", emptyList<Finding>(), findings)
    }

    @Test
    fun `a readable path does reach the rule`() {
        val findings = engine.evaluateFiles(listOf(path("/readable/.raptor", accessible = true)))

        assertEquals(1, findings.size)
    }

    @Test
    fun `a mixed list is judged only on what was actually read`() {
        val findings = engine.evaluateFiles(
            listOf(
                path("/data/local/tmp/.raptor", accessible = false),
                path("/readable/.raptor", accessible = true),
            )
        )

        assertEquals(1, findings.size)
    }
}

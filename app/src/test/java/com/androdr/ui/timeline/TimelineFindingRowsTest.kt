package com.androdr.ui.timeline

import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The timeline shows a correlation as its signal row -- the cluster head that
 * expands into the member events. Now that a correlation is also a [Finding] on the
 * scan (#350), it must NOT additionally appear as a FindingRow, or every chain shows
 * twice. [timelineFindingRows] is the single filter the timeline applies.
 */
class TimelineFindingRowsTest {

    private fun finding(id: String, category: FindingCategory, triggered: Boolean = true) = Finding(
        ruleId = id, title = id, level = "high", category = category, triggered = triggered,
    )

    @Test
    fun `correlation findings are excluded because their signal row already represents them`() {
        val rows = timelineFindingRows(
            listOf(
                finding("androdr-corr-001", FindingCategory.CORRELATION),
                finding("androdr-010", FindingCategory.APP_RISK),
                finding("androdr-040", FindingCategory.DEVICE_POSTURE),
            )
        )

        assertEquals(listOf("androdr-010", "androdr-040"), rows.map { it.ruleId })
    }

    @Test
    fun `untriggered findings are excluded as before`() {
        val rows = timelineFindingRows(listOf(finding("androdr-010", FindingCategory.APP_RISK, triggered = false)))

        assertEquals(emptyList<Finding>(), rows)
    }
}

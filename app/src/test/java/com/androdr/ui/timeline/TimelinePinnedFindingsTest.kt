package com.androdr.ui.timeline

import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Ruling R34 (F916B device test: an intrusion-log import's 167 findings buried the Timeline): the
 * pinned section lists the 3 most severe current findings until "Show all", which lists every one.
 */
class TimelinePinnedFindingsTest {
    private fun finding(i: Int, level: String) =
        Finding(ruleId = "r$i", title = "t$i", level = level, category = FindingCategory.DEVICE_POSTURE)

    private val levels = listOf("low", "medium", "high", "low", "critical", "medium", "high", "info")

    /** 167 findings, as on the device: mostly low, a few severe ones scattered through. */
    private val many = List(167) { i -> finding(i, levels[i % levels.size]) }

    @Test
    fun `collapsed lists the 3 most severe findings, most severe first`() {
        val shown = pinnedFindings(many, showAll = false)
        assertEquals(PINNED_FINDINGS_PREVIEW, shown.size)
        assertEquals(3, shown.size)
        assertEquals(listOf("critical", "critical", "critical"), shown.map { it.level })
        assertEquals("ties keep their scan order", listOf("r4", "r12", "r20"), shown.map { it.ruleId })
    }

    @Test
    fun `the toggle reveals every finding, most severe first`() {
        val shown = pinnedFindings(many, showAll = true)
        assertEquals(167, shown.size)
        assertEquals(many.toSet(), shown.toSet())
        assertEquals(shown.sortedByDescending { severityOrdinal(it.level) }, shown)
    }

    @Test
    fun `few findings are all listed collapsed`() {
        val two = listOf(finding(1, "low"), finding(2, "high"))
        assertEquals(listOf("r2", "r1"), pinnedFindings(two, showAll = false).map { it.ruleId })
    }
}

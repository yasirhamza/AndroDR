package com.androdr.scanner

import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertEquals
import org.junit.Test

/** Ruling R38: the display bound for findings a full disk could not take — exact counts, bounded sample. */
class UnsavedFindingsTest {

    private fun f(rule: String, level: String, time: Long) = Finding(ruleId = rule, title = rule, level = level,
        category = FindingCategory.APP_RISK, matchContext = mapOf("timestamp" to "$time"))

    @Test
    fun `counts are exact and the sample keeps the most severe, newest first, within the limit`() {
        val u = UnsavedFindings(limit = 3)
        u.add(f("a", "low", 1))
        u.add(f("b", "critical", 2))
        u.add(f("c", "high", 9))
        u.add(f("d", "critical", 5))
        u.add(f("e", "medium", 7))
        assertEquals(5L, u.count)
        assertEquals(mapOf(("a" to "low") to 1L, ("b" to "critical") to 1L, ("c" to "high") to 1L,
            ("d" to "critical") to 1L, ("e" to "medium") to 1L), u.countsByRuleLevel())
        assertEquals(listOf("d", "b", "c"), u.sample().map { it.ruleId })
    }

    @Test
    fun `the default display limit is 1000`() {
        assertEquals(1_000, UnsavedFindings.UNSAVED_DISPLAY_LIMIT)
        val u = UnsavedFindings()
        repeat(1_500) { u.add(f("r", "high", it.toLong())) }
        assertEquals(1_000, u.sample().size)
        assertEquals(1_500L, u.count)
    }
}

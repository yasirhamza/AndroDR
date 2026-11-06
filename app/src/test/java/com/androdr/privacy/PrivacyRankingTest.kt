package com.androdr.privacy

import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyScan
import com.androdr.data.model.PrivacyTrackerEvidence
import com.androdr.privacy.model.TrackerCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PrivacyRankingTest {

    private val default = TrackerCategory.entries.toSet() - TrackerCategory.CRASH_REPORTING - TrackerCategory.OTHER
    private val sep = "\u001F"

    private fun app(
        pkg: String,
        outcome: InspectOutcome = InspectOutcome.INSPECTED,
        system: Boolean = false,
        label: String = pkg,
        reason: String? = null
    ) = PrivacyAppResult(1, pkg, 1, label, system, outcome.name, reason)

    private fun ev(
        pkg: String,
        id: Int,
        vararg cats: String,
        inCode: Boolean = true,
        lookups: Int = 0,
        isNew: Boolean = false,
        name: String = "T$id"
    ) = PrivacyTrackerEvidence(
        1, pkg, id, name, "w", cats.joinToString(sep), inCode, lookups,
        if (lookups > 0) 1 else 0, null, null, null, isNew
    )

    private val scan = PrivacyScan(
        id = 1, startedAt = 10, finishedAt = 20, appsTotal = 0, appsInspected = 0,
        appsPartial = 0, appsFailed = 0, registrySize = 0, registrySha256 = "", dnsWindowStart = 0,
        dnsCoverageDays = 0, usageCoverageFrom = null, networkStatus = "COMPLETE"
    )

    private fun sections(
        results: List<PrivacyAppResult>,
        evidence: List<PrivacyTrackerEvidence>,
        refused: Set<TrackerCategory> = default,
        show: Boolean = true
    ) = PrivacyRanking.rows(results, evidence, refused, show).toMap()

    private fun names(m: Map<RowSection, List<AppPrivacyRow>>, s: RowSection) =
        m[s].orEmpty().map { it.packageName }

    @Test
    fun `network-only refused evidence does not make an app cross`() {
        val m = sections(listOf(app("a")), listOf(ev("a", 1, "Advertisement", inCode = false, lookups = 5)))
        assertEquals(emptyList<String>(), names(m, RowSection.CROSSING))
        assertEquals(listOf("a"), names(m, RowSection.OTHER))
    }

    @Test
    fun `code evidence of a refused category does`() {
        val m = sections(listOf(app("a")), listOf(ev("a", 1, "Advertisement")))
        assertEquals(listOf("a"), names(m, RowSection.CROSSING))
        assertEquals(1, m.getValue(RowSection.CROSSING).single().refusedInCode)
    }

    @Test
    fun `failed apps and partial apps without refused code trackers are in NEEDS_ATTENTION, never OTHER`() {
        val m = sections(
            listOf(app("f", InspectOutcome.COULD_NOT_INSPECT), app("p", InspectOutcome.PARTIAL)),
            listOf(ev("p", 1, "Crash reporting"))
        )
        assertEquals(setOf("f", "p"), names(m, RowSection.NEEDS_ATTENTION).toSet())
        assertEquals(emptyList<String>(), names(m, RowSection.OTHER))
    }

    @Test
    fun `a PARTIAL app with a refused tracker in code is CROSSING and counted in notInspected`() {
        val results = listOf(app("p", InspectOutcome.PARTIAL, reason = "partly inspected"))
        val evidence = listOf(ev("p", 1, "Advertisement"))
        val m = sections(results, evidence)
        assertEquals(listOf("p"), names(m, RowSection.CROSSING))
        assertEquals("partly inspected", m.getValue(RowSection.CROSSING).single().reason)
        val s = PrivacyRanking.summary(scan, results, evidence, default, true)
        assertEquals(1, s.crossing)
        assertEquals(1, s.notInspected)
    }

    @Test
    fun `a tracker with categories Crash reporting and Analytics counts under the default threshold`() {
        val m = sections(listOf(app("a")), listOf(ev("a", 1, "Crash reporting", "Analytics")))
        assertEquals(1, m.getValue(RowSection.CROSSING).single().refusedInCode)
    }

    @Test
    fun `a failed system app is in NEEDS_ATTENTION and counted even when system apps are hidden`() {
        val results = listOf(app("f", InspectOutcome.COULD_NOT_INSPECT, system = true))
        val m = sections(results, emptyList(), show = false)
        assertEquals(listOf("f"), names(m, RowSection.NEEDS_ATTENTION))
        assertEquals(1, PrivacyRanking.summary(scan, results, emptyList(), default, false).notInspected)
    }

    @Test
    fun `notInspected counts every PARTIAL and COULD_NOT_INSPECT app`() {
        val results = listOf(
            app("i"), app("p1", InspectOutcome.PARTIAL), app("p2", InspectOutcome.PARTIAL, system = true),
            app("f1", InspectOutcome.COULD_NOT_INSPECT), app("f2", InspectOutcome.COULD_NOT_INSPECT, system = true)
        )
        for (show in listOf(true, false)) {
            assertEquals(4, PrivacyRanking.summary(scan, results, emptyList(), default, show).notInspected)
        }
    }

    @Test
    fun `crossing apps order by refused-in-code count then label`() {
        val results = listOf(app("a", label = "Zed"), app("b", label = "Alpha"), app("c", label = "Beta"))
        val evidence = listOf(
            ev("a", 1, "Advertisement"), ev("a", 2, "Profiling"),
            ev("b", 1, "Advertisement"), ev("c", 1, "Advertisement")
        )
        assertEquals(listOf("a", "b", "c"), names(sections(results, evidence), RowSection.CROSSING))
    }

    @Test
    fun `trackers inside an app list refused first then by name`() {
        val evidence = listOf(
            ev("a", 1, "Crash reporting", name = "Aaa"), ev("a", 2, "Advertisement", name = "Zzz"),
            ev("a", 3, "Location", name = "Bbb")
        )
        val row = sections(listOf(app("a")), evidence).getValue(RowSection.CROSSING).single()
        assertEquals(listOf("Bbb", "Zzz", "Aaa"), row.trackers.map { it.name })
    }

    @Test
    fun `system apps are excluded from CROSSING and OTHER unless showSystemApps`() {
        val results = listOf(app("x", system = true), app("y", system = true), app("u"))
        val evidence = listOf(ev("x", 1, "Advertisement"))
        val hidden = sections(results, evidence, show = false)
        assertEquals(listOf("u"), names(hidden, RowSection.OTHER))
        assertEquals(emptyList<String>(), names(hidden, RowSection.CROSSING))
        val shown = sections(results, evidence, show = true)
        assertEquals(listOf("x"), names(shown, RowSection.CROSSING))
        assertEquals(setOf("y", "u"), names(shown, RowSection.OTHER).toSet())
    }

    @Test
    fun `summary equals the counts of rows for the same inputs`() {
        val results = listOf(app("a"), app("b", InspectOutcome.PARTIAL), app("c", InspectOutcome.COULD_NOT_INSPECT))
        val evidence = listOf(ev("a", 1, "Advertisement", isNew = true), ev("b", 1, "Location"))
        val m = sections(results, evidence)
        val s = PrivacyRanking.summary(scan, results, evidence, default, true)
        assertEquals(m.getValue(RowSection.CROSSING).size, s.crossing)
        assertEquals(m.getValue(RowSection.CROSSING).count { it.newCrossing }, s.newCrossing)
        assertEquals(1, s.newCrossing)
        assertEquals(2, s.notInspected)
        assertEquals(20L, s.scannedAt)
    }

    @Test
    fun `every app counted in notInspected is visible in some section, with system apps shown and hidden`() {
        val results = listOf(
            app("p", InspectOutcome.PARTIAL, system = true), app("q", InspectOutcome.PARTIAL, system = true),
            app("f", InspectOutcome.COULD_NOT_INSPECT, system = true), app("u", InspectOutcome.PARTIAL)
        )
        val evidence = listOf(ev("p", 1, "Advertisement"))
        for (show in listOf(true, false)) {
            val rows = PrivacyRanking.rows(results, evidence, default, show)
            val visible = rows.flatMap { it.second }.map { it.packageName }
            assertEquals(visible.size, visible.toSet().size)
            assertEquals(4, visible.size)
            assertEquals(4, PrivacyRanking.summary(scan, results, evidence, default, show).notInspected)
        }
        val hiddenRows = sections(results, evidence, show = false)
        assertTrue("p" in names(hiddenRows, RowSection.NEEDS_ATTENTION))
        assertEquals(1, hiddenRows.getValue(RowSection.NEEDS_ATTENTION).first { it.packageName == "p" }.refusedInCode)
    }

    @Test
    fun `changing refused changes summary and rows identically`() {
        val results = listOf(app("a"))
        val evidence = listOf(ev("a", 1, "Crash reporting"))
        val none = PrivacyRanking.summary(scan, results, evidence, default, true)
        val crash = default + TrackerCategory.CRASH_REPORTING
        val with = PrivacyRanking.summary(scan, results, evidence, crash, true)
        assertEquals(0, none.crossing)
        assertEquals(1, with.crossing)
        assertEquals(listOf("a"), names(sections(results, evidence, crash), RowSection.CROSSING))
        assertEquals(listOf("a"), names(sections(results, evidence, default), RowSection.OTHER))
    }

    @Test
    fun `an Uncategorised tracker in code crosses under the default threshold`() {
        val m = sections(listOf(app("a")), listOf(ev("a", 1, "Uncategorised")))
        assertEquals(listOf("a"), names(m, RowSection.CROSSING))
    }

    @Test
    fun `evidence with an empty categories string and inCode crosses under the default threshold`() {
        val m = sections(listOf(app("a")), listOf(ev("a", 1)))
        assertEquals(listOf("a"), names(m, RowSection.CROSSING))
        val tracker = m.getValue(RowSection.CROSSING).single().trackers[0]
        assertEquals(setOf(TrackerCategory.UNCATEGORISED), tracker.categories)
    }

    @Test
    fun `a COULD_NOT_INSPECT app with refused in-code evidence is CROSSING and counted in notInspected`() {
        val results = listOf(app("f", InspectOutcome.COULD_NOT_INSPECT))
        val evidence = listOf(ev("f", 1, "Advertisement"))
        assertEquals(listOf("f"), names(sections(results, evidence), RowSection.CROSSING))
        val s = PrivacyRanking.summary(scan, results, evidence, default, true)
        assertEquals(1, s.crossing)
        assertEquals(1, s.notInspected)
    }

    @Test
    fun `a hidden system COULD_NOT_INSPECT app with refused in-code evidence stays visible in NEEDS_ATTENTION`() {
        val results = listOf(app("f", InspectOutcome.COULD_NOT_INSPECT, system = true))
        val evidence = listOf(ev("f", 1, "Advertisement"))
        assertEquals(listOf("f"), names(sections(results, evidence, show = false), RowSection.NEEDS_ATTENTION))
    }

    @Test
    fun `OTHER category is not refused by default`() {
        val m = sections(listOf(app("a")), listOf(ev("a", 1, "Some Unknown Label")))
        assertEquals(emptyList<String>(), names(m, RowSection.CROSSING))
    }

    @Test
    fun `an unparseable outcome is treated as COULD_NOT_INSPECT`() {
        val bad = PrivacyAppResult(1, "a", 1, "a", false, "GARBAGE", null)
        assertEquals(listOf("a"), names(sections(listOf(bad), emptyList()), RowSection.NEEDS_ATTENTION))
    }

    @Test
    fun `byTracker lists most apps first`() {
        val results = listOf(app("a"), app("b"), app("c"))
        val evidence = listOf(
            ev("a", 1, "Advertisement", name = "One"), ev("a", 2, "Advertisement", name = "Two"),
            ev("b", 2, "Advertisement", name = "Two"), ev("c", 3, "Advertisement", name = "Aaa")
        )
        val rows = PrivacyRanking.rows(results, evidence, default, true).flatMap { it.second }
        val groups = PrivacyRanking.byTracker(rows)
        assertEquals(listOf("Two", "Aaa", "One"), groups.map { it.name })
        assertEquals(2, groups.first().apps.size)
        assertEquals(2, groups.first().apps.first().second.trackerId)
    }

    @Test
    fun `evidence is CODE, NETWORK or BOTH`() {
        val evidence = listOf(
            ev("a", 1, "Analytics"), ev("a", 2, "Analytics", inCode = false, lookups = 3),
            ev("a", 3, "Analytics", lookups = 3)
        )
        val byId = sections(listOf(app("a")), evidence).getValue(RowSection.CROSSING).single()
            .trackers.associateBy { it.trackerId }
        assertEquals(Evidence.CODE, byId.getValue(1).evidence)
        assertEquals(Evidence.NETWORK, byId.getValue(2).evidence)
        assertEquals(Evidence.BOTH, byId.getValue(3).evidence)
    }
}

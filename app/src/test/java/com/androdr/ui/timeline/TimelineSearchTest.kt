package com.androdr.ui.timeline

import com.androdr.data.db.TimelineDirection
import com.androdr.data.db.TimelineFilter
import com.androdr.data.db.TimelineKey
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanState
import com.androdr.data.model.TimelineRowEntity
import com.androdr.data.store.StoreFixture
import com.androdr.data.store.StoreFixture.Companion.dns
import com.androdr.sigma.StoreRecord
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * C5 search (ruling R30): [TimelineFilter.query] narrows both arms in SQL, over columns only —
 * facts by `packageName` and `category`, rows by `packageName`, `category`, `ruleId` and the title
 * (`description`) — case-insensitively, with `%`, `_` and `\` matched literally. It composes with
 * every other filter, the count agrees with what pages, and a hidden scan's entries never match.
 */
@RunWith(RobolectricTestRunner::class)
class TimelineSearchTest {
    private val f = StoreFixture(recordSql = false)
    private val dao get() = f.db.timelineDao()

    @After fun tearDown() = f.close()

    @Suppress("LongParameterList")
    private fun row(
        t: Long, title: String, pkg: String = "", ruleId: String = "", level: String? = null,
        category: String = "app_risk", scan: Long = -1L,
    ) = ForensicTimelineEvent(startTimestamp = t, source = "app_scanner", category = category, description = title,
        packageName = pkg, ruleId = ruleId, level = level, scanResultId = scan)

    private suspend fun all(filter: TimelineFilter): List<TimelineRowEntity> {
        val out = ArrayList<TimelineRowEntity>()
        var key: TimelineKey? = null
        while (true) {
            val page = dao.page(filter, key, if (key == null) TimelineDirection.FROM else TimelineDirection.AFTER, 3)
            out += page
            if (page.size < 3) return out
            key = page.last().key
        }
    }

    /** Every entry [filter] pages, with its count checked against them. */
    private suspend fun search(filter: TimelineFilter): List<TimelineRowEntity> {
        val got = all(filter)
        assertEquals("the count is what pages for $filter", got.size.toLong(), dao.count(filter))
        return got
    }

    private suspend fun seed(): Map<String, Long> {
        val rows = f.db.forensicTimelineEventDao()
        f.scan(1L)
        f.persist(1L, "dns_monitor", listOf(dns("tracker.example", time = 5_000L), dns("cdn.example", time = 5_001L)))
        f.setState(1L, ScanState.COMPLETE)
        return mapOf(
            "overlay" to rows.insert(row(1_000L, "Banking overlay detected", pkg = "com.bank",
                ruleId = "androdr-050", level = "high", scan = 1L)),
            "other" to rows.insert(row(1_001L, "Sideloaded app", pkg = "com.other", ruleId = "androdr-010",
                level = "medium", scan = 1L)),
            "percent" to rows.insert(row(1_002L, "100% match")),
            "noPercent" to rows.insert(row(1_003L, "1000 matches")),
            "underscore" to rows.insert(row(1_004L, "a_b token")),
            "noUnderscore" to rows.insert(row(1_005L, "axb token")),
            "backslash" to rows.insert(row(1_006L, "path c:\\dir")),
            "noBackslash" to rows.insert(row(1_007L, "path c:dir")),
        )
    }

    private fun List<TimelineRowEntity>.rowIds() =
        filter { it.rowKind == TimelineRowEntity.ROW }.map { it.id }.toSet()

    private fun List<TimelineRowEntity>.facts() = filter { it.rowKind == TimelineRowEntity.FACT }

    @Test
    fun `search matches a package, a rule id, a rule title and an event type, ignoring case`() = runBlocking {
        val ids = seed()
        assertEquals(setOf(ids["overlay"]), search(TimelineFilter(query = "OVERLAY")).rowIds())
        assertEquals(setOf(ids["overlay"]), search(TimelineFilter(query = "com.ba")).rowIds())
        assertEquals(setOf(ids["other"]), search(TimelineFilter(query = "androdr-010")).rowIds())
        val byPackage = search(TimelineFilter(query = "com.EXAMPLE"))
        assertEquals("both DNS facts, by their package", 2, byPackage.facts().size)
        assertTrue(byPackage.rowIds().isEmpty())
        assertEquals("an event type (category) matches facts", 2, search(TimelineFilter(query = "dns_q")).facts().size)
        assertTrue("no decoded body is searched (the domain lives only in the body)",
            search(TimelineFilter(query = "tracker")).isEmpty())
        assertEquals("a blank query filters nothing", all(TimelineFilter()).size,
            search(TimelineFilter(query = "  ")).size)
    }

    @Test
    fun `percent, underscore and backslash in the query are literal`() = runBlocking {
        val ids = seed()
        assertEquals(setOf(ids["percent"]), search(TimelineFilter(query = "100%")).rowIds())
        assertEquals(setOf(ids["percent"]), search(TimelineFilter(query = "%")).rowIds())
        assertEquals(setOf(ids["underscore"]), search(TimelineFilter(query = "a_b")).rowIds())
        assertEquals(setOf(ids["backslash"]), search(TimelineFilter(query = "c:\\d")).rowIds())
    }

    @Test
    fun `search composes with the severity, scan, package and findings filters`() = runBlocking {
        val ids = seed()
        val rows = f.db.forensicTimelineEventDao()
        f.scan(2L)
        f.setState(2L, ScanState.COMPLETE)
        val overlay2 = rows.insert(row(2_000L, "Banking overlay detected", pkg = "com.bank", ruleId = "androdr-050",
            level = "high", scan = 2L))
        val lowOverlay = rows.insert(row(2_001L, "Overlay hint", pkg = "com.bank", ruleId = "androdr-051",
            level = "low", scan = 1L))

        assertEquals(setOf(ids["overlay"], overlay2),
            search(TimelineFilter(query = "overlay", levels = setOf("HIGH"))).rowIds())
        assertEquals(setOf(ids["overlay"], lowOverlay), search(TimelineFilter(query = "overlay", scanId = 1L)).rowIds())
        assertEquals(setOf(ids["overlay"]),
            search(TimelineFilter(query = "overlay", scanId = 1L, levels = setOf("high"))).rowIds())
        assertEquals(setOf(ids["overlay"], overlay2, lowOverlay),
            search(TimelineFilter(query = "androdr-05", packageName = "com.bank", findingsAndEvidenceOnly = true))
                .rowIds())
        assertEquals("the scan filter and search read the scan's facts too", 2,
            search(TimelineFilter(query = "dns_query", scanId = 1L)).facts().size)
        assertTrue(search(TimelineFilter(query = "dns_query", scanId = 2L)).isEmpty())
    }

    @Test
    fun `nothing of an IN_PROGRESS scan is found`() = runBlocking {
        seed()
        val rows = f.db.forensicTimelineEventDao()
        f.scan(3L)
        val hidden = dns("hidden.example", time = 9_000L)
        f.persist(3L, "dns_monitor", listOf(StoreRecord(hidden.fields + ("source_package" to "com.hidden"))))
        rows.insert(row(9_001L, "Hidden finding", pkg = "com.hidden", ruleId = "androdr-099", level = "high",
            scan = 3L))

        assertTrue(search(TimelineFilter(query = "hidden")).isEmpty())
        assertTrue(search(TimelineFilter(query = "com.hidden", scanId = 3L)).isEmpty())
        assertTrue(search(TimelineFilter(query = "androdr-099", levels = setOf("high"))).isEmpty())
    }
}

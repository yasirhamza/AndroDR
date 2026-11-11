package com.androdr.ui.timeline

import com.androdr.data.db.TimelineDirection
import com.androdr.data.db.TimelineFilter
import com.androdr.data.db.TimelineKey
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TimelineRowEntity
import com.androdr.data.store.StoreFixture
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** The privacy scan's entries on the Timeline screen (spec 2026-11-10 §5.1, §5.3). */
@RunWith(RobolectricTestRunner::class)
class TimelinePrivacyTest {
    private val f = StoreFixture(recordSql = false)
    private val dao get() = f.db.timelineDao()
    private val rows get() = f.db.forensicTimelineEventDao()

    @After fun tearDown() = f.close()

    private fun privacy(t: Long = 50L, pkg: String = "com.game", app: String = "Some Game") = ForensicTimelineEvent(
        startTimestamp = t, source = "privacy_scan", category = "privacy_app",
        description = "$app: 3 trackers found in code", packageName = pkg, appName = app, createdAt = t,
        telemetrySource = TelemetrySource.PRIVACY_SCAN,
    )

    private fun finding(t: Long = 40L, pkg: String = "com.game") = ForensicTimelineEvent(
        startTimestamp = t, source = "app_scanner", category = "app_risk", description = "risky app",
        packageName = pkg, ruleId = "androdr-001", level = "high", createdAt = t,
    )

    private suspend fun all(filter: TimelineFilter): List<TimelineRowEntity> {
        val out = ArrayList<TimelineRowEntity>()
        var key: TimelineKey? = null
        while (true) {
            val page = dao.page(filter, key, if (key == null) TimelineDirection.FROM else TimelineDirection.AFTER, 3)
            out += page
            if (page.size < 3) break
            key = page.last().key
        }
        assertEquals("the count is what pages for $filter", out.size.toLong(), dao.count(filter))
        return out
    }

    private suspend fun seed() {
        rows.insert(privacy())
        rows.insert(finding())
        rows.insert(finding(t = 30L, pkg = "com.other"))
    }

    @Test fun `the Source filter shows only privacy entries`() = runBlocking {
        seed()
        val got = all(TimelineFilter(source = TelemetrySource.PRIVACY_SCAN))
        assertEquals(1, got.size)
    }

    @Test fun `Findings only and severity filters never show a privacy entry`() = runBlocking {
        seed()
        assertEquals(2, all(TimelineFilter(findingsAndEvidenceOnly = true)).size)
        assertEquals(2, all(TimelineFilter(levels = setOf("high", "medium", "low", "info", "critical"))).size)
    }

    @Test fun `search finds a privacy entry by app name and by package`() = runBlocking {
        seed()
        assertEquals(1, all(TimelineFilter(query = "some game")).size)
        assertEquals(2, all(TimelineFilter(query = "com.game")).size)
    }

    @Test fun `one app's timeline shows its privacy entry`() = runBlocking {
        seed()
        assertEquals(2, all(TimelineFilter(packageName = "com.game")).size)
    }

    @Test fun `exports leave privacy entries out`() = runBlocking {
        seed()
        assertEquals(3L, dao.count(TimelineFilter()))
        assertEquals(2, all(TimelineFilter(exportable = true)).size)
        assertEquals(0L, dao.count(TimelineFilter(source = TelemetrySource.PRIVACY_SCAN, exportable = true)))
    }

    @Test fun `the privacy scan's time is read for the By scan list`() = runBlocking {
        assertNull(rows.privacyScanAt().first())
        rows.insert(privacy(t = 77L))
        assertEquals(77L, rows.privacyScanAt().first())
    }

    @Test fun `the privacy header sits by its date among newest-first scans`() {
        fun g(t: Long) = ScanGroup(scanId = t, timestamp = t, importSource = null, maxSeverity = "INFO")
        assertTrue("first, when newest", privacyHeaderBetween(null, g(50), at = 60))
        assertFalse(privacyHeaderBetween(null, g(70), at = 60))
        assertTrue("between", privacyHeaderBetween(g(70), g(50), at = 60))
        assertFalse(privacyHeaderBetween(g(70), g(65), at = 60))
        assertTrue("last, when oldest", privacyHeaderBetween(g(70), null, at = 60))
        assertTrue("alone", privacyHeaderBetween(null, null, at = 60))
    }

    @Test fun `privacy entries are never linked evidence`() {
        val p = privacy().copy(id = 1)
        val a = finding().copy(id = 2)
        val b = finding(t = 41L).copy(id = 3)
        assertEquals(listOf(b), linkedEvidence(a, listOf(p, a, b)))
        assertEquals(emptyList<ForensicTimelineEvent>(), linkedEvidence(p, listOf(p, a, b)))
    }

    @Test fun `Open in privacy results is offered for a privacy entry only`() {
        var opened: String? = "unset"
        val open: (String?) -> Unit = { opened = it }
        assertNull(openPrivacyAction(finding(), open))
        openPrivacyAction(privacy(), open)!!.invoke()
        assertEquals("com.game", opened)
        openPrivacyAction(privacy().copy(category = "privacy_scan", packageName = ""), open)!!.invoke()
        assertNull("the scan entry opens the privacy screen itself", opened)
        assertNull(openPrivacyAction(privacy(), null))
    }
}

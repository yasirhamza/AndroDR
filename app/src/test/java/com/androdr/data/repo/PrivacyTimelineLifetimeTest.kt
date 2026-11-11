package com.androdr.data.repo

import androidx.room.withTransaction
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetrySource
import com.androdr.data.store.StoreFixture
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Spec 2026-11-10 §5.3–5.4: a privacy scan's Timeline entries live exactly as long as its results.
 * Only [TimelineRowDeleter.privacyRows] removes them; the 30-day prune, deleting a security scan and
 * History's "Clear all" (also when resumed at start-up: same deleter call) leave them. They never reach
 * the STIX export or the correlation inputs.
 */
@RunWith(RobolectricTestRunner::class)
class PrivacyTimelineLifetimeTest {
    private val f = StoreFixture()
    private val dao = f.db.forensicTimelineEventDao()
    private val deleter = TimelineRowDeleter(dao, f.store, f.db.signalMemberDao())

    @After fun tearDown() = f.close()

    private fun privacy(description: String = "Some Game: 3 trackers found in code") = ForensicTimelineEvent(
        startTimestamp = 5L, source = "privacy_scan", category = "privacy_app", description = description,
        packageName = "com.game", appName = "Some Game", createdAt = 1L, telemetrySource = TelemetrySource.PRIVACY_SCAN,
    )

    private fun live(scan: Long = -1L, category: String = "c") = ForensicTimelineEvent(
        startTimestamp = 5L, source = "s", category = category, description = "live", packageName = "com.game",
        scanResultId = scan, createdAt = 1L,
    )

    private fun privacyCount() =
        f.count("SELECT COUNT(*) FROM forensic_timeline WHERE telemetrySource = 'PRIVACY_SCAN'")

    @Test fun `the 30-day prune leaves privacy entries`() = runBlocking {
        dao.insert(privacy())
        dao.insert(live())
        f.db.withTransaction { deleter.olderThan(Long.MAX_VALUE) }
        assertEquals(1L, privacyCount())
        assertEquals(1L, f.count("SELECT COUNT(*) FROM forensic_timeline"))
    }

    @Test fun `deleting a security scan leaves privacy entries`() = runBlocking {
        f.scan(7L, ScanState.COMPLETE)
        dao.insert(privacy())
        dao.insert(live(scan = 7L))
        f.db.withTransaction { deleter.byScanId(7L) }
        assertEquals(1L, privacyCount())
    }

    @Test fun `Clear all leaves privacy entries`() = runBlocking {
        dao.insert(privacy())
        dao.insert(live())
        f.db.withTransaction { deleter.scanLessThrough(Long.MAX_VALUE) }
        assertEquals(1L, privacyCount())
        assertEquals("the live scan-less row is cleared", 1L, f.count("SELECT COUNT(*) FROM forensic_timeline"))
    }

    @Test fun `privacyRows deletes privacy entries and nothing else`() = runBlocking {
        dao.insert(privacy())
        dao.insert(privacy("Other: 1 tracker found in code"))
        dao.insert(live())
        f.db.withTransaction { deleter.privacyRows() }
        assertEquals(0L, privacyCount())
        assertEquals(1L, f.count("SELECT COUNT(*) FROM forensic_timeline"))
    }

    @Test fun `STIX export never reads a privacy entry`() = runBlocking {
        dao.insert(privacy())
        val live = dao.insert(live())
        assertEquals(listOf(live), dao.visibleAfter(0L, 500).map { it.id })
    }

    @Test fun `a privacy entry is never a correlation input`() = runBlocking {
        dao.insert(privacy().copy(category = "package_install"))
        // rowsForScan is called only with a security scan's id; a privacy entry's scan reference is -1.
        assertTrue(f.db.atomDao().liveRowsBetween(0L, Long.MAX_VALUE, listOf("package_install")).isEmpty())
    }
}

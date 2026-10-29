package com.androdr.data.repo

import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetrySource
import com.androdr.data.store.StoreFixture
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Battery B2, ruling R44: History's "since previous scan" diff. A live scan diffs against the
 * previous COMPLETE live scan; an import (evidence from another time or device) has no diff. The
 * old baseline was the previous COMPLETE scan of ANY source, so an import listed the live device
 * flags as "Resolved", and a live scan after an import diffed against the import.
 */
@RunWith(RobolectricTestRunner::class)
class ScanDiffBaselineTest {
    private val f = StoreFixture()
    private val repo = ScanRepository(f.db.scanResultDao(), f.db.dnsEventDao(), f.db.forensicTimelineEventDao(),
        mockk(relaxed = true), mockk(relaxed = true), ScanLock(), f.db)

    @After fun tearDown() = f.close()

    private suspend fun scan(id: Long, source: TelemetrySource, state: ScanState = ScanState.COMPLETE): ScanResult {
        val s = ScanResult(id = id, timestamp = id, bugReportFindings = emptyList(), riskySideloadCount = 0,
            knownMalwareCount = 0, state = state, source = source)
        f.db.scanResultDao().insert(s)
        return s
    }

    @Test
    fun `a live scan after an import diffs with the earlier live scan`() = runBlocking {
        val live1 = scan(1L, TelemetrySource.LIVE_SCAN)
        scan(2L, TelemetrySource.BUGREPORT_IMPORT)
        scan(3L, TelemetrySource.INTRUSION_LOG_IMPORT)
        scan(4L, TelemetrySource.LIVE_SCAN, ScanState.IN_PROGRESS)
        val live5 = scan(5L, TelemetrySource.LIVE_SCAN)
        assertEquals(live1.id, repo.diffBaselineOf(live5)?.id)
    }

    @Test
    fun `an import has no diff`() = runBlocking {
        scan(1L, TelemetrySource.LIVE_SCAN)
        val bugReport = scan(2L, TelemetrySource.BUGREPORT_IMPORT)
        val intrusionLog = scan(3L, TelemetrySource.INTRUSION_LOG_IMPORT)
        assertNull(repo.diffBaselineOf(bugReport))
        assertNull(repo.diffBaselineOf(intrusionLog))
    }

    @Test
    fun `the first live scan has no diff`() = runBlocking {
        scan(1L, TelemetrySource.BUGREPORT_IMPORT)
        assertNull(repo.diffBaselineOf(scan(2L, TelemetrySource.LIVE_SCAN)))
    }
}

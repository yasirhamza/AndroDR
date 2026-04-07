package com.androdr.scanner

import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.model.AppTelemetry
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class InstallEventEmitterTest {

    private fun telem(pkg: String, first: Long) = mockk<AppTelemetry>(relaxed = true).also {
        every { it.packageName } returns pkg
        every { it.firstInstallTime } returns first
        every { it.appName } returns pkg
    }

    @Test
    fun `first scan emits one row per package`() = runTest {
        val dao = mockk<ForensicTimelineEventDao>(relaxed = true)
        coEvery { dao.getInstalledPackagesAlreadyEmitted() } returns emptyList()
        val emitter = InstallEventEmitter(dao)
        val rows = emitter.emitNew(scanId = 1L, telemetry = listOf(
            telem("com.a", 1000), telem("com.b", 2000)
        ))
        assertEquals(2, rows.size)
        assertEquals("com.a", rows[0].packageName)
        assertEquals(1000L, rows[0].startTimestamp)
        assertEquals("event", rows[0].kind)
        assertEquals("package_install", rows[0].category)
    }

    @Test
    fun `subsequent scan with no new installs emits zero rows`() = runTest {
        val dao = mockk<ForensicTimelineEventDao>(relaxed = true)
        coEvery { dao.getInstalledPackagesAlreadyEmitted() } returns listOf("com.a", "com.b")
        val emitter = InstallEventEmitter(dao)
        val rows = emitter.emitNew(scanId = 2L, telemetry = listOf(
            telem("com.a", 1000), telem("com.b", 2000)
        ))
        assertTrue(rows.isEmpty())
    }

    @Test
    fun `scan with one new install emits exactly one row`() = runTest {
        val dao = mockk<ForensicTimelineEventDao>(relaxed = true)
        coEvery { dao.getInstalledPackagesAlreadyEmitted() } returns listOf("com.a")
        val emitter = InstallEventEmitter(dao)
        val rows = emitter.emitNew(scanId = 3L, telemetry = listOf(
            telem("com.a", 1000), telem("com.b", 2000)
        ))
        assertEquals(1, rows.size)
        assertEquals("com.b", rows[0].packageName)
    }

    @Test
    fun `package with firstInstallTime = 0 is skipped`() = runTest {
        val dao = mockk<ForensicTimelineEventDao>(relaxed = true)
        coEvery { dao.getInstalledPackagesAlreadyEmitted() } returns emptyList()
        val emitter = InstallEventEmitter(dao)
        val rows = emitter.emitNew(scanId = 1L, telemetry = listOf(telem("com.a", 0)))
        assertTrue(rows.isEmpty())
    }
}

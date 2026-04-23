package com.androdr.scanner

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.model.TelemetrySource
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceAdminGrantEmitterTest {

    private val idLabel: (String) -> String = { it }

    private fun emitter(known: List<String>): Pair<DeviceAdminGrantEmitter, ForensicTimelineEventDao> {
        val dao = mockk<ForensicTimelineEventDao>(relaxed = true)
        coEvery { dao.getAdminGrantedPackagesAlreadyEmitted() } returns known
        val context = mockk<Context>(relaxed = true)
        return DeviceAdminGrantEmitter(context, dao) to dao
    }

    @Test
    fun `first scan with two active admins emits two rows`() = runTest {
        val (emitter, _) = emitter(known = emptyList())
        val rows = emitter.buildEvents(
            scanId = 1L,
            activeAdminPackages = listOf("com.a", "com.b"),
            now = 100_000L,
            labelFor = idLabel,
        )
        assertEquals(2, rows.size)
        assertEquals("com.a", rows[0].packageName)
        assertEquals("device_admin_grant", rows[0].category)
        assertEquals("approximate", rows[0].timestampPrecision)
        assertEquals(100_000L, rows[0].startTimestamp)
        assertEquals("event", rows[0].kind)
        assertEquals(TelemetrySource.LIVE_SCAN, rows[0].telemetrySource)
        assertEquals(1L, rows[0].scanResultId)
    }

    @Test
    fun `subsequent scan with no change emits zero rows`() = runTest {
        val (emitter, _) = emitter(known = listOf("com.a", "com.b"))
        val rows = emitter.buildEvents(2L, listOf("com.a", "com.b"), 100_000L, idLabel)
        assertTrue(rows.isEmpty())
    }

    @Test
    fun `one newly-added admin emits exactly one row`() = runTest {
        val (emitter, _) = emitter(known = listOf("com.a"))
        val rows = emitter.buildEvents(3L, listOf("com.a", "com.b"), 100_000L, idLabel)
        assertEquals(1, rows.size)
        assertEquals("com.b", rows[0].packageName)
    }

    @Test
    fun `duplicate ComponentNames under one package collapse to a single row`() = runTest {
        val (emitter, _) = emitter(known = emptyList())
        val rows = emitter.buildEvents(4L, listOf("com.a", "com.a"), 100_000L, idLabel)
        assertEquals(1, rows.size)
        assertEquals("com.a", rows[0].packageName)
    }

    @Test
    fun `previously-emitted package is not re-emitted after uninstall and reinstall`() = runTest {
        // DAO row persists for com.a even after uninstall.  User reinstalls the
        // same package and re-grants admin.  The table-as-dedup-store must
        // suppress re-emission — mirrors InstallEventEmitter semantics.
        val (emitter, _) = emitter(known = listOf("com.a"))
        val rows = emitter.buildEvents(5L, listOf("com.a"), 100_000L, idLabel)
        assertTrue(rows.isEmpty())
    }

    @Test
    fun `DevicePolicyManager unavailable returns empty list without DAO call`() = runTest {
        val dao = mockk<ForensicTimelineEventDao>(relaxed = true)
        val context = mockk<Context>(relaxed = true)
        every { context.getSystemService(DevicePolicyManager::class.java) } returns null
        val result = DeviceAdminGrantEmitter(context, dao).emitNew(scanId = 1L)
        assertTrue(result.isEmpty())
        coVerify(exactly = 0) { dao.getAdminGrantedPackagesAlreadyEmitted() }
    }

    @Test
    fun `null activeAdmins returns empty list without DAO call`() = runTest {
        val dao = mockk<ForensicTimelineEventDao>(relaxed = true)
        val context = mockk<Context>(relaxed = true)
        val dpm = mockk<DevicePolicyManager>()
        every { context.getSystemService(DevicePolicyManager::class.java) } returns dpm
        every { dpm.activeAdmins } returns null
        val result = DeviceAdminGrantEmitter(context, dao).emitNew(scanId = 1L)
        assertTrue(result.isEmpty())
        coVerify(exactly = 0) { dao.getAdminGrantedPackagesAlreadyEmitted() }
    }

    @Test
    fun `empty activeAdmins list returns empty list without DAO call`() = runTest {
        val dao = mockk<ForensicTimelineEventDao>(relaxed = true)
        val context = mockk<Context>(relaxed = true)
        val dpm = mockk<DevicePolicyManager>()
        every { context.getSystemService(DevicePolicyManager::class.java) } returns dpm
        every { dpm.activeAdmins } returns emptyList<ComponentName>()
        val result = DeviceAdminGrantEmitter(context, dao).emitNew(scanId = 1L)
        assertTrue(result.isEmpty())
        coVerify(exactly = 0) { dao.getAdminGrantedPackagesAlreadyEmitted() }
    }

    @Test
    fun `emitted row source and description are correct`() = runTest {
        val (emitter, _) = emitter(known = emptyList())
        val rows = emitter.buildEvents(
            1L, listOf("com.evil"), 100_000L, labelFor = { "Evil App" }
        )
        assertEquals(1, rows.size)
        assertEquals("device_admin_emitter", rows[0].source)
        assertEquals("Evil App", rows[0].appName)
        assertTrue(rows[0].description.contains("Evil App"))
        assertTrue(rows[0].description.contains("com.evil"))
    }

    @Test
    fun `dedup DAO query is invoked when there are admins to consider`() = runTest {
        // Refactor guard: if someone changes the category string in
        // DeviceAdminGrantEmitter or in the DAO query (or unwires them
        // from each other), this test would still pass on output but
        // the verify call below catches the mismatch.
        val (emitter, dao) = emitter(known = listOf("com.a"))
        emitter.buildEvents(1L, listOf("com.a", "com.b"), 100_000L, idLabel)
        coVerify(exactly = 1) { dao.getAdminGrantedPackagesAlreadyEmitted() }
    }

    @Test
    fun `emitter does not insert via DAO — persistence is the orchestrator's job`() = runTest {
        // Refactor guard: ensures the emitter never starts persisting
        // independently of saveScanWithCorrelation (which would double-write
        // every admin row and bypass the correlation transaction's ID
        // assignment).
        val (emitter, dao) = emitter(known = emptyList())
        emitter.buildEvents(1L, listOf("com.a", "com.b"), 100_000L, idLabel)
        coVerify(exactly = 0) { dao.insert(any()) }
        coVerify(exactly = 0) { dao.insertAll(any()) }
    }

    @Test
    fun `label resolution failure falls back to package name`() = runTest {
        // Not strictly a unit for the emitter itself; documents the contract
        // that labelFor can return the package name unchanged when the label
        // resolver throws NameNotFoundException in production.
        val (emitter, _) = emitter(known = emptyList())
        val rows = emitter.buildEvents(
            1L, listOf("com.missing"), 100_000L, labelFor = { pkg -> pkg }
        )
        assertEquals(1, rows.size)
        assertEquals("com.missing", rows[0].appName)
        assertFalse(rows[0].description.isBlank())
    }
}

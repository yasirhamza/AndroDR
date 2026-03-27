package com.androdr.scanner

import android.app.ActivityManager
import android.content.Context
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ProcessScannerTest {

    private lateinit var context: Context
    private lateinit var scanner: ProcessScanner

    @Before
    fun setUp() {
        context = mockk(relaxed = true)
        scanner = ProcessScanner(context)
    }

    // ── 1. Null ActivityManager returns empty list ───────────────────────────

    @Test
    fun `null ActivityManager returns empty list`() = runTest {
        every { context.getSystemService(Context.ACTIVITY_SERVICE) } returns null

        val result = scanner.collectTelemetry()

        assertTrue("Expected empty list when ActivityManager is null", result.isEmpty())
    }

    // ── 2. Null runningAppProcesses returns empty list ───────────────────────

    @Test
    fun `null runningAppProcesses returns empty list`() = runTest {
        val am = mockk<ActivityManager>(relaxed = true)
        every { context.getSystemService(Context.ACTIVITY_SERVICE) } returns am
        every { am.runningAppProcesses } returns null

        val result = scanner.collectTelemetry()

        assertTrue("Expected empty list when runningAppProcesses is null", result.isEmpty())
    }

    // ── 3. Foreground process marked isForeground true ───────────────────────

    @Test
    fun `foreground process marked isForeground true`() = runTest {
        val proc = ActivityManager.RunningAppProcessInfo().apply {
            processName = "com.example.foreground"
            uid = 1001
            pkgList = arrayOf("com.example.foreground")
            importance = ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND
        }
        val am = mockk<ActivityManager>(relaxed = true)
        every { context.getSystemService(Context.ACTIVITY_SERVICE) } returns am
        every { am.runningAppProcesses } returns mutableListOf(proc)

        val result = scanner.collectTelemetry()

        assertEquals(1, result.size)
        val telemetry = result[0]
        assertEquals("com.example.foreground", telemetry.processName)
        assertEquals(1001, telemetry.processUid)
        assertEquals("com.example.foreground", telemetry.packageName)
        assertTrue("Expected isForeground = true for IMPORTANCE_FOREGROUND", telemetry.isForeground)
    }

    // ── 4. Background process marked isForeground false ─────────────────────

    @Test
    fun `background process marked isForeground false`() = runTest {
        val proc = ActivityManager.RunningAppProcessInfo().apply {
            processName = "com.example.background"
            uid = 2002
            pkgList = arrayOf("com.example.background")
            importance = ActivityManager.RunningAppProcessInfo.IMPORTANCE_BACKGROUND
        }
        val am = mockk<ActivityManager>(relaxed = true)
        every { context.getSystemService(Context.ACTIVITY_SERVICE) } returns am
        every { am.runningAppProcesses } returns mutableListOf(proc)

        val result = scanner.collectTelemetry()

        assertEquals(1, result.size)
        val telemetry = result[0]
        assertEquals("com.example.background", telemetry.processName)
        assertFalse("Expected isForeground = false for IMPORTANCE_BACKGROUND", telemetry.isForeground)
    }
}

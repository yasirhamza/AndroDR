package com.androdr.cellular

import android.app.ActivityManager
import android.content.Context
import android.os.PowerManager
import android.telephony.TelephonyManager
import com.androdr.data.model.CaptureOrigin
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/**
 * The capture-context reads are best-effort: each one is null on failure
 * and none of them may stop the observation. Importance is the subtle one —
 * a foreground SERVICE reports 125, which is not "the user can see us".
 */
class PlatformDeviceContextTest {

    private val power = mockk<PowerManager>()
    private val telephony = mockk<TelephonyManager>()
    private val context = mockk<Context> {
        every { getSystemService(PowerManager::class.java) } returns power
        every { getSystemService(TelephonyManager::class.java) } returns telephony
    }
    private var importance = ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE

    @Before
    fun setUp() {
        mockkStatic(ActivityManager::class)
        every { ActivityManager.getMyMemoryState(any()) } answers {
            firstArg<ActivityManager.RunningAppProcessInfo>().importance = importance
        }
        every { power.isInteractive } returns true
        every { telephony.dataActivity } returns TelephonyManager.DATA_ACTIVITY_IN
    }

    @After
    fun tearDown() = unmockkStatic(ActivityManager::class)

    @Test
    fun `reads the screen, the data direction and the record count`() {
        val c = PlatformDeviceContext(context).capture(CaptureOrigin.PRIME, rawRecordCount = 14)
        assertEquals(CaptureOrigin.PRIME, c.origin)
        assertEquals(true, c.screenInteractive)
        assertEquals("IN", c.dataActivity)
        assertEquals(14, c.rawRecordCount)
    }

    @Test
    fun `a foreground service is not a visible activity`() {
        importance = ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE
        assertEquals(false, PlatformDeviceContext(context).capture(CaptureOrigin.CALLBACK, 1).appForeground)

        importance = ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND
        assertEquals(true, PlatformDeviceContext(context).capture(CaptureOrigin.CALLBACK, 1).appForeground)

        importance = ActivityManager.RunningAppProcessInfo.IMPORTANCE_VISIBLE
        assertEquals(true, PlatformDeviceContext(context).capture(CaptureOrigin.CALLBACK, 1).appForeground)
    }

    @Test
    fun `every data activity value has a name`() {
        val names = listOf(
            TelephonyManager.DATA_ACTIVITY_NONE to "NONE",
            TelephonyManager.DATA_ACTIVITY_OUT to "OUT",
            TelephonyManager.DATA_ACTIVITY_INOUT to "INOUT",
            TelephonyManager.DATA_ACTIVITY_DORMANT to "DORMANT",
            99 to "UNKNOWN",
        )
        for ((value, name) in names) {
            every { telephony.dataActivity } returns value
            assertEquals(name, PlatformDeviceContext(context).capture(CaptureOrigin.CALLBACK, 1).dataActivity)
        }
    }

    @Test
    fun `a failed read is null and does not stop the capture`() {
        every { power.isInteractive } throws SecurityException("no")
        every { context.getSystemService(TelephonyManager::class.java) } returns null
        every { ActivityManager.getMyMemoryState(any()) } throws IllegalStateException("no process")

        val c = PlatformDeviceContext(context).capture(CaptureOrigin.CALLBACK, rawRecordCount = 3)
        assertNull(c.screenInteractive)
        assertNull(c.dataActivity)
        assertNull(c.appForeground)
        assertEquals("the facts that need no platform read still arrive", 3, c.rawRecordCount)
    }
}

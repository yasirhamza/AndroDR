package com.androdr.scanner

import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.androdr.ioc.OemPrefixResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf

/**
 * C1 m4, carried into C3 (usage is store-only): one collection holds at most
 * [UsageStatsScanner.MAX_EVENTS_PER_SCAN] usage events, however long the watermark gap. The rest is
 * not dropped: the watermark stops at the last event read, so the next scan continues from there.
 */
@RunWith(RobolectricTestRunner::class)
class UsageStatsScannerBoundTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val usm = context.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
    private val oem = mockk<OemPrefixResolver> { every { isOemPrefix(any(), any()) } returns false }
    private val granted = mockk<UsageAccess> { every { granted() } returns true }

    private fun scanner(cap: Int) = UsageStatsScanner(context, oem, granted, cap)

    /** One foreground event per minute, each a distinct app, from [start]. */
    private fun addEvents(start: Long, count: Int) = repeat(count) { i ->
        shadowOf(usm).addEvent(
            org.robolectric.shadows.ShadowUsageStatsManager.EventBuilder.buildEvent().setPackage("com.app$i")
                .setTimeStamp(start + i * MINUTE).setEventType(UsageEvents.Event.ACTIVITY_RESUMED).build(),
        )
    }

    @Test
    fun `a collection stops at the bound, oldest first`() = runBlocking {
        addEvents(start = MINUTE, count = 25)

        val events = (scanner(cap = 10).collectEvents(0L, 100 * MINUTE) as UsageCollection.Ok).events

        assertEquals(10, events.size)
        assertEquals((0 until 10).map { "com.app$it" }, events.map { it.packageName })
    }

    @Test
    fun `the default bound is the documented one`() {
        assertEquals(20_000, UsageStatsScanner.MAX_EVENTS_PER_SCAN)
    }

    @Test
    fun `bounded scans continue from the watermark until every event is read`() = runBlocking {
        addEvents(start = MINUTE, count = 25)
        val scanStart = 100 * MINUTE
        val seen = LinkedHashSet<String>()
        var previous: Long? = null
        repeat(8) {
            val since = Watermarks.usageSince(previous, scanStart).coerceAtLeast(0L)
            val collection = scanner(cap = 10).collectEvents(since, scanStart)
            (collection as UsageCollection.Ok).events.forEach { seen += it.packageName }
            previous = Watermarks.nextTime(previous, collection, scanStart, scanStart, saveFallback = false)
        }
        assertEquals("nothing is lost past the bound", (0 until 25).map { "com.app$it" }.toSet(), seen)
    }

    @Test
    fun `duplicates within a minute do not count toward the bound`() = runBlocking {
        repeat(5) { i ->
            shadowOf(usm).addEvent(
                org.robolectric.shadows.ShadowUsageStatsManager.EventBuilder.buildEvent().setPackage("com.same")
                    .setTimeStamp(MINUTE + i).setEventType(UsageEvents.Event.ACTIVITY_RESUMED).build(),
            )
        }
        addEvents(start = 2 * MINUTE, count = 3)

        val events = (scanner(cap = 4).collectEvents(0L, 100 * MINUTE) as UsageCollection.Ok).events

        assertEquals(listOf("com.same", "com.app0", "com.app1", "com.app2"), events.map { it.packageName })
    }

    private companion object {
        const val MINUTE = 60_000L
    }
}

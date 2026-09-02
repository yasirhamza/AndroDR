package com.androdr.cellular

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The distance behind androdr-104's "while stationary". The subtle
 * property is the null: a rule gating on stationarity must not read "no
 * fix in the window" as "did not move".
 */
class LocationTrailTest {

    private val window = RadioStateStore.DEFAULT_WINDOW_MILLIS

    // Doha Corniche → ~1 km north along the same longitude.
    private val lat = 25.2854
    private val lon = 51.5310
    private val oneKmNorth = lat + 0.008993

    @Test
    fun `two fixes in the window give the distance between them`() {
        val t = LocationTrail()
        t.record(lat, lon, timeMillis = 0)
        t.record(oneKmNorth, lon, timeMillis = 60_000)
        val moved = t.movedMetersLast(window, now = 120_000)!!
        assertTrue("expected ~1000 m, got $moved", moved in 990..1010)
    }

    @Test
    fun `a single fix says nothing about movement`() {
        val t = LocationTrail()
        t.record(lat, lon, timeMillis = 0)
        assertNull("one fix cannot tell moved from stationary", t.movedMetersLast(window, now = 1_000))
        assertEquals(1, t.fixAgeSeconds(now = 1_000))
    }

    @Test
    fun `a stationary device reads zero, not null`() {
        val t = LocationTrail()
        t.record(lat, lon, timeMillis = 0)
        t.record(lat, lon, timeMillis = 90_000)
        assertEquals(0, t.movedMetersLast(window, now = 100_000))
    }

    @Test
    fun `fixes outside the window do not count`() {
        val t = LocationTrail()
        t.record(oneKmNorth, lon, timeMillis = 0)
        t.record(lat, lon, timeMillis = window + 10_000)
        // Only the second fix is inside [now - window, now].
        assertNull(t.movedMetersLast(window, now = window + 20_000))
    }

    @Test
    fun `movement is measured from the newest fix`() {
        // Out and back: the newest fix is where it started, so the greatest
        // distance from it is the far point, not zero.
        val t = LocationTrail()
        t.record(lat, lon, timeMillis = 0)
        t.record(oneKmNorth, lon, timeMillis = 60_000)
        t.record(lat, lon, timeMillis = 120_000)
        assertTrue(t.movedMetersLast(window, now = 130_000)!! > 900)
    }

    @Test
    fun `the same fix delivered twice is recorded once`() {
        val t = LocationTrail()
        t.record(lat, lon, timeMillis = 0)
        t.record(lat, lon, timeMillis = 0)
        assertNull("still only one fix", t.movedMetersLast(window, now = 1_000))
    }

    @Test
    fun `a fix older than the newest is ignored`() {
        // The passive provider can hand back an older fix after a fresher
        // one; appended blindly it would become "the newest" by position.
        val t = LocationTrail()
        t.record(lat, lon, timeMillis = 60_000)
        t.record(oneKmNorth, lon, timeMillis = 30_000)
        assertNull("still only one fix", t.movedMetersLast(window, now = 70_000))
        assertEquals("age is from the fix that is actually newest", 10, t.fixAgeSeconds(now = 70_000))
    }

    @Test
    fun `a fix stamped a few seconds ahead of the clock still counts`() {
        // Fix times come from the location subsystem, now from the monitor.
        val t = LocationTrail()
        t.record(lat, lon, timeMillis = 0)
        t.record(oneKmNorth, lon, timeMillis = 63_000)
        val moved = t.movedMetersLast(window, now = 60_000)
        assertTrue("expected ~1000 m, got $moved", moved != null && moved in 990..1010)
        assertEquals(0, t.fixAgeSeconds(now = 60_000))
    }

    @Test
    fun `no fix means no age`() {
        assertNull(LocationTrail().fixAgeSeconds(now = 5_000))
    }

    @Test
    fun `old fixes are dropped but the newest is always kept`() {
        val t = LocationTrail(retentionMillis = 1_000)
        t.record(lat, lon, timeMillis = 0)
        t.record(oneKmNorth, lon, timeMillis = 5_000)
        assertNull("the first fix aged out of retention", t.movedMetersLast(windowMillis = 10_000, now = 5_000))
        assertEquals(0, t.fixAgeSeconds(now = 5_000))
    }
}

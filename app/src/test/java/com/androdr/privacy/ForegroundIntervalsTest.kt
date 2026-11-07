package com.androdr.privacy

import com.androdr.privacy.ActivityTransition.Kind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ForegroundIntervalsTest {

    private fun ev(pkg: String, time: Long, fg: Boolean, cls: String? = "Main") =
        ActivityTransition(pkg, cls, time, if (fg) Kind.RESUMED else Kind.PAUSED)

    private fun stop(pkg: String, time: Long, cls: String? = "Main") = ActivityTransition(pkg, cls, time, Kind.STOPPED)

    private fun reset(time: Long) = ActivityTransition("android", null, time, Kind.DEVICE_RESET)

    @Test fun `pairs resume and pause per package`() {
        val out = ForegroundIntervals.build(
            listOf(
                ev("a", 10, true), ev("b", 12, true), ev("a", 20, false),
                ev("b", 30, false), ev("a", 40, true), ev("a", 50, false),
            ),
            until = 100,
        )
        assertEquals(listOf(10L..20L, 40L..50L), out["a"])
        assertEquals(listOf(12L..30L), out["b"])
    }

    @Test fun `events out of order are sorted by time per package`() {
        val out = ForegroundIntervals.build(listOf(ev("a", 20, false), ev("a", 10, true)), until = 100)
        assertEquals(listOf(10L..20L), out["a"])
    }

    @Test fun `an open interval ends at until`() {
        val out = ForegroundIntervals.build(listOf(ev("a", 10, true)), until = 100)
        assertEquals(listOf(10L..100L), out["a"])
    }

    @Test fun `repeated resumes and pauses of one activity do not split or reopen an interval`() {
        val out = ForegroundIntervals.build(
            listOf(ev("a", 10, true), ev("a", 15, true), ev("a", 20, false), ev("a", 25, false)),
            until = 100,
        )
        assertEquals(listOf(10L..20L), out["a"])
    }

    @Test fun `a stop after a pause changes nothing`() {
        val out = ForegroundIntervals.build(
            listOf(ev("a", 10, true), ev("a", 20, false), stop("a", 21), ev("a", 30, true)),
            until = 40,
        )
        assertEquals(listOf(10L..20L, 30L..40L), out["a"])
    }

    @Test fun `a stop of a resumed class closes the interval like a pause`() {
        val out = ForegroundIntervals.build(listOf(ev("a", 10, true), stop("a", 20)), until = 100)
        assertEquals(listOf(10L..20L), out["a"])
    }

    @Test fun `split screen - A resumed, B resumed, A paused keeps the package in the foreground until B pauses`() {
        val out = ForegroundIntervals.build(
            listOf(
                ev("a", 10, true, "A"), ev("a", 15, true, "B"), ev("a", 20, false, "A"), ev("a", 30, false, "B"),
            ),
            until = 100,
        )
        assertEquals(listOf(10L..30L), out["a"])
    }

    @Test fun `a pause that is the package's first event infers foreground from the start of history`() {
        val out = ForegroundIntervals.build(listOf(ev("a", 20, false), ev("a", 30, true)), until = 100)
        assertEquals(listOf(Long.MIN_VALUE..20L, 30L..100L), out["a"])
    }

    @Test fun `a pause of a never-resumed class after other package events creates no range`() {
        val out = ForegroundIntervals.build(
            listOf(ev("a", 10, true, "A"), ev("a", 20, false, "A"), ev("a", 30, false, "B")),
            until = 100,
        )
        assertEquals(listOf(10L..20L), out["a"])
    }

    @Test fun `a lone stop creates no range`() {
        assertEquals(emptyList<LongRange>(), ForegroundIntervals.build(listOf(stop("a", 20)), until = 100)["a"])
    }

    @Test fun `a first pause after a device reset infers nothing`() {
        val out = ForegroundIntervals.build(listOf(reset(5), ev("a", 20, false)), until = 100)
        assertEquals(emptyList<LongRange>(), out["a"])
    }

    @Test fun `a shutdown closes an interval whose pause was lost, so later lookups are not foreground`() {
        val out = ForegroundIntervals.build(listOf(ev("a", 10, true), reset(40)), until = 100)
        assertEquals(listOf(10L..40L), out["a"])
        val usage = UsageIntervals(0, out)
        val source = listOf(30L, 50L, 90L)
        assertEquals(listOf(30L), source.filter { t -> usage.byPackage.getValue("a").any { t in it } })
    }

    @Test fun `a startup with no pause closes the interval at startup and clears every resumed class`() {
        val out = ForegroundIntervals.build(
            listOf(ev("a", 10, true, "A"), ev("a", 12, true, "B"), reset(40), ev("a", 50, false, "B")),
            until = 100,
        )
        assertEquals(listOf(10L..40L), out["a"])
    }

    @Test fun `a reset applies to every package`() {
        val out = ForegroundIntervals.build(listOf(ev("a", 10, true), ev("b", 20, true), reset(30)), until = 100)
        assertEquals(listOf(10L..30L), out["a"])
        assertEquals(listOf(20L..30L), out["b"])
        assertNull("a reset alone creates no package", out["android"])
    }

    @Test fun `system packages are kept`() {
        val out = ForegroundIntervals.build(
            listOf(ev("com.android.chrome", 1, true), ev("com.android.chrome", 5, false), ev("android", 2, true)),
            until = 9,
        )
        assertEquals(listOf(1L..5L), out["com.android.chrome"])
        assertEquals(listOf(2L..9L), out["android"])
    }

    @Test fun `the reader maps raw usage event types, shutdown and startup included`() {
        assertEquals(Kind.RESUMED, UsageIntervalReader.kindOf(1))
        assertEquals(Kind.PAUSED, UsageIntervalReader.kindOf(2))
        assertEquals(Kind.STOPPED, UsageIntervalReader.kindOf(23))
        assertEquals(Kind.DEVICE_RESET, UsageIntervalReader.kindOf(26))
        assertEquals(Kind.DEVICE_RESET, UsageIntervalReader.kindOf(27))
        assertNull(UsageIntervalReader.kindOf(5))
    }

    @Test fun `merge sorts and joins overlapping ranges`() {
        assertEquals(listOf(0L..30L, 40L..50L), ForegroundIntervals.merge(listOf(40L..50L, 10L..30L, 0L..15L)))
    }
}

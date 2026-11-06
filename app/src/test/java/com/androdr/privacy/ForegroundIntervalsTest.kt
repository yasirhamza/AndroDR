package com.androdr.privacy

import org.junit.Assert.assertEquals
import org.junit.Test

class ForegroundIntervalsTest {

    private fun ev(pkg: String, time: Long, fg: Boolean, cls: String? = "Main") =
        ActivityTransition(pkg, cls, time, fg)

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
            listOf(ev("a", 10, true), ev("a", 20, false), ev("a", 21, false), ev("a", 30, true)),
            until = 40,
        )
        assertEquals(listOf(10L..20L, 30L..40L), out["a"])
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

    @Test fun `a leading pause means the app was already in the foreground when history begins`() {
        val out = ForegroundIntervals.build(listOf(ev("a", 20, false), ev("a", 30, true)), until = 100)
        assertEquals(listOf(Long.MIN_VALUE..20L, 30L..100L), out["a"])
    }

    @Test fun `a first pause of an activity never seen resumed covers history up to it, merged with the rest`() {
        val out = ForegroundIntervals.build(
            listOf(ev("a", 10, true, "A"), ev("a", 20, false, "A"), ev("a", 30, false, "B")),
            until = 100,
        )
        assertEquals(listOf(Long.MIN_VALUE..30L), out["a"])
    }

    @Test fun `system packages are kept`() {
        val out = ForegroundIntervals.build(
            listOf(ev("com.android.chrome", 1, true), ev("com.android.chrome", 5, false), ev("android", 2, true)),
            until = 9,
        )
        assertEquals(listOf(1L..5L), out["com.android.chrome"])
        assertEquals(listOf(2L..9L), out["android"])
    }

    @Test fun `merge sorts and joins overlapping ranges`() {
        assertEquals(listOf(0L..30L, 40L..50L), ForegroundIntervals.merge(listOf(40L..50L, 10L..30L, 0L..15L)))
    }
}

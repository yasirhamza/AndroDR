package com.androdr.privacy.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TrackerSetTest {

    private fun tracker(
        id: Int,
        prefixes: List<String> = emptyList(),
        segments: List<String> = emptyList(),
        suffixes: List<String> = emptyList(),
        labels: List<String> = emptyList(),
        patterns: List<String> = emptyList(),
    ) = Tracker(
        id = id, name = "T$id", website = "", categories = setOf(TrackerCategory.ANALYTICS),
        rawCategories = listOf("Analytics"), codePrefixes = prefixes, codeSegments = segments,
        domainSuffixes = suffixes, domainLabels = labels,
        domainPatterns = patterns.map { requireNotNull(DomainGrammar.compilePattern(it)) },
    )

    private fun reg(vararg t: Tracker) = TrackerSet(t.toList(), "sha")

    @Test
    fun `matchPackages respects dotted boundaries`() {
        val t = tracker(1, prefixes = listOf("com.a"))
        val s = reg(t)
        assertEquals(emptySet<Tracker>(), s.matchPackages(listOf("com.ab")))
        assertEquals(setOf(t), s.matchPackages(listOf("com.a")))
        assertEquals(setOf(t), s.matchPackages(listOf("com.a.b.c")))
    }

    @Test
    fun `matchPackages returns every tracker whose prefix matches`() {
        val t1 = tracker(1, prefixes = listOf("com.a"))
        val t2 = tracker(2, prefixes = listOf("com.a.b"))
        assertEquals(setOf(t1, t2), reg(t1, t2).matchPackages(listOf("com.a.b.c")))
    }

    @Test
    fun `a code segment matches a package containing it`() {
        val t = tracker(1, segments = listOf("sizmek"))
        val s = reg(t)
        assertEquals(setOf(t), s.matchPackages(listOf("net.sizmek.sdk")))
        assertEquals(emptySet<Tracker>(), s.matchPackages(listOf("net.sizmekx")))
    }

    @Test
    fun `matchDomain matches suffixes on label boundaries and returns all owners`() {
        val t1 = tracker(1, suffixes = listOf("doubleclick.net"))
        val t2 = tracker(2, suffixes = listOf("doubleclick.net"))
        val s = reg(t1, t2)
        assertEquals(s.trackers.toSet(), s.matchDomain("ad.doubleclick.net"))
        assertEquals(s.trackers.toSet(), s.matchDomain("doubleclick.net"))
        assertEquals(emptySet<Tracker>(), s.matchDomain("notdoubleclick.net"))
    }

    @Test
    fun `a domain label matches only a whole label`() {
        val t = tracker(1, labels = listOf("alimama"))
        val s = reg(t)
        assertEquals(s.trackers.toSet(), s.matchDomain("x.alimama.com"))
        assertEquals(emptySet<Tracker>(), s.matchDomain("xalimama.com"))
    }

    @Test
    fun `a pattern matches the host or a label-bounded suffix`() {
        val t = tracker(1, patterns = listOf("mst[0-9]*\\.is\\.autonavi\\.com"))
        val s = reg(t)
        assertEquals(s.trackers.toSet(), s.matchDomain("mst3.is.autonavi.com"))
        assertEquals(s.trackers.toSet(), s.matchDomain("a.mst3.is.autonavi.com"))
        assertEquals(emptySet<Tracker>(), s.matchDomain("xmst3.is.autonavi.com"))
    }

    @Test
    fun `a host longer than 253 chars matches nothing`() {
        val t = tracker(1, suffixes = listOf("doubleclick.net"))
        val s = reg(t)
        val host = "a".repeat(250) + ".doubleclick.net"
        assertTrue(host.length > TrackerSet.MAX_HOST_CHARS)
        assertEquals(emptySet<Tracker>(), s.matchDomain(host))
    }
}
